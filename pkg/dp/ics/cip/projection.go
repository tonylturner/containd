// SPDX-License-Identifier: Apache-2.0
package cip

import (
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
)

func messageErrorCode(err error) string {
	if errors.Is(err, ErrPathTruncated) {
		return "cip.epath_truncated"
	}
	return "cip.message_short"
}

func encapsulationEvents(state *flow.State, hdr *EIPHeader) []dpi.Event {
	attrs := map[string]any{
		"enip_command": CommandName(hdr.Command), "enip_command_code": hdr.Command,
		"enip_session_handle": hdr.SessionHandle, "enip_status": hdr.Status,
		"enip_sender_context": hex.EncodeToString(hdr.SenderContext[:]), "enip_options": hdr.Options,
	}
	_, knownCommand := commandNames[hdr.Command]
	if !knownCommand {
		addFinding(attrs, "cip.unknown_command")
	}
	if cipCommands[hdr.Command] && hdr.Status == 0 {
		explicit := ParseCIPMessage(hdr.Data)
		cpf := explicit.CPF
		if len(hdr.Data) >= 8 {
			attrs["cpf_item_count"] = cpf.Count
			types := make([]string, 0, len(cpf.Items))
			for _, item := range cpf.Items {
				types = append(types, fmt.Sprintf("0x%04x", item.TypeID))
			}
			attrs["cpf_item_types"] = strings.Join(types, ",")
		}
		for _, code := range cpf.Conformance {
			addFinding(attrs, code)
		}
		for _, code := range cpf.Undecoded {
			addUndecoded(attrs, code)
		}
		if cpf.Selected >= 0 {
			selectedType := cpf.Items[cpf.Selected].TypeID
			if hdr.Command == 0x6f && selectedType != 0xb2 || hdr.Command == 0x70 && selectedType != 0xb1 {
				addFinding(attrs, "cip.cpf_layout")
			}
			attrs["cpf_item_index"] = uint16(cpf.Selected)
			attrs["cpf_data_item_type"] = cpf.Items[cpf.Selected].TypeID
			if cpf.ConnectionID != nil {
				attrs["connection_id"] = *cpf.ConnectionID
			}
			if cpf.ConnectedSequence != nil {
				attrs["connected_sequence"] = *cpf.ConnectedSequence
			}
			msg, err := explicit.Message, explicit.MessageError
			if err != nil {
				addFinding(attrs, messageErrorCode(err))
			}
			if msg != nil {
				budget := maxMSPServices
				var msp *MSPResult
				if hasMSPBody(msg) && err == nil {
					result := parseMSP(msg.Data, &msg.IsResponse, &budget, 0)
					msp = &result
				}
				return projectMessage(state, attrs, msg, msp, nil)
			}
		}
	} else if !knownCommand && len(hdr.Data) != 0 {
		// An unknown command might carry another message envelope. Known
		// non-explicit commands and encapsulation error bodies carry data,
		// not an unwalked service/path or nested CIP operation.
		addUndecoded(attrs, "cip.encapsulation_payload_unsupported")
	}
	return []dpi.Event{newEvent(state, "session", attrs)}
}

func newEvent(state *flow.State, kind string, attrs map[string]any) dpi.Event {
	id := ""
	if state != nil {
		id = state.Key.Hash()
	}
	return dpi.Event{FlowID: id, Proto: eventfields.ProtoCIP, Kind: kind,
		Attributes: attrs, Timestamp: time.Now().UTC()}
}

func projectMessage(state *flow.State, envelope map[string]any, msg *CIPMessage, msp *MSPResult, path []uint16) []dpi.Event {
	attrs := maps.Clone(envelope)
	attrs["service_code"], attrs["function_code"], attrs["service_name"] = msg.ServiceCode, msg.ServiceCode, msg.ServiceName
	if IsReadService(msg.ServiceCode) || IsWriteService(msg.ServiceCode) || IsControlService(msg.ServiceCode) {
		attrs["is_write"], attrs["is_control"] = IsWriteService(msg.ServiceCode), IsControlService(msg.ServiceCode)
	}
	if len(path) != 0 {
		attrs["msp"], attrs["msp_index"], attrs["msp_index_path"] = true, path[len(path)-1], slices.Clone(path)
	}
	for _, code := range msg.Conformance {
		addFinding(attrs, code)
	}
	kind := "request"
	if msg.IsResponse {
		kind = "response"
	}
	if r := msg.Response; r != nil {
		if r.Reserved != nil {
			attrs["response_reserved"] = *r.Reserved
		}
		if r.GeneralStatus != nil {
			attrs["general_status"] = *r.GeneralStatus
		}
		if r.AdditionalCount != nil {
			attrs["additional_status_count"] = *r.AdditionalCount
			attrs["additional_status"] = slices.Clone(r.AdditionalStatus)
		}
	}
	addPathFields(msg.Path, attrs)
	events := []dpi.Event{newEvent(state, kind, attrs)}
	if msp == nil {

		return events
	}
	attrs["multi_service_count"] = msp.Declared
	attrs["multi_service_decoded_count"] = uint16(len(msp.Children))
	for _, code := range msp.Conformance {
		addFinding(attrs, code)
	}
	for _, code := range msp.Undecoded {
		addUndecoded(attrs, code)
	}
	inherited := maps.Clone(envelope)
	for _, key := range []string{eventfields.KeyConformance, eventfields.KeyUndecoded} {
		if codes, ok := eventfields.Strings(attrs, key); ok {
			inherited[key] = slices.Clone(codes)
		}
	}
	for _, child := range msp.Children {
		childPath := append(slices.Clone(path), child.Index)
		children := projectMessage(state, inherited, child.CIPMessage, child.Nested, childPath)
		// The wrapper also reports uninspected or malformed descendants.
		for _, ev := range children {
			for _, key := range []string{eventfields.KeyConformance, eventfields.KeyUndecoded} {
				codes, _ := eventfields.Strings(ev.Attributes, key)
				for _, code := range codes {
					addCode(attrs, key, code)
				}
			}
		}
		events = append(events, children...)
	}
	return events
}
