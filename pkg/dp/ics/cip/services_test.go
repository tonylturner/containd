// SPDX-License-Identifier: Apache-2.0
package cip

import (
	"encoding/hex"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields/decodertest"
)

func requestBytes(t *testing.T, wire string) []byte {
	t.Helper()
	b, err := hex.DecodeString(wire)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// These complete request bytes are independent of the production service
// table and target/body validators. The same service number is deliberately
// exercised on colliding targets.
func TestServiceCodeClassification(t *testing.T) {
	for _, tc := range []struct {
		name, wire, service string
		category            AccessCategory
	}{
		{"attributes all", "010220012401", "Get_Attributes_All", AccessRead},
		{"attribute list", "03022001240101000100", "Get_Attribute_List", AccessRead},
		{"apply", "0d0220012401", "Apply_Attributes", AccessWrite},
		{"get single", "0e03200124013001", "Get_Attribute_Single", AccessRead},
		{"get member", "1803200424012801", "Get_Member", AccessRead},
		{"set member", "1903200424012801", "Set_Member", AccessWrite},
		{"restore", "150220012401", "Restore", AccessWrite},
		{"save", "160220012401", "Save", AccessWrite},
		{"nop", "170220012401", "No_Operation", AccessStructural},
		{"find next unsupported", "110220012401", "Find_Next_Object_Instance", AccessUnknown},
		{"DeviceNet error", "140220012401", "Error_Response", AccessUnknown},
		{"reserved", "0b0220012401", "Unknown(0x0B)", AccessUnknown},
		{"symbolic tag", "4c02910254470100", "Read_Tag", AccessRead},
		{"symbol instance", "4c02206b24010100", "Read_Tag", AccessRead},
		{"template instance", "4c02206c2401000000001000", "Template_Read", AccessRead},
		{"file download", "4c0220372401", "Initiate_Download", AccessWrite},
		{"connection configuration", "4c0220f32401", "Open_Connection", AccessControl},
		{"TCP IP admin", "4c0220f52401", "Set_Port_Admin_State", AccessWrite},
		{"Ethernet clear", "4c0220f62401", "Get_And_Clear", AccessWrite},
		{"DLR clear", "4c0220472401", "Clear_Rapid_Faults", AccessWrite},
		{"unlisted class", "4c02209924010100", "Unknown(0x4C)", AccessUnknown},
		{"unlisted vendor class", "4c032100341224010100", "Unknown(0x4C)", AccessUnknown},
		{"symbolic RMW", "4e0291025447", "Read_Modify_Write_Tag", AccessWrite},
		{"Symbol RMW unsupported", "4e02206b2401", "Unknown(0x4E)", AccessUnknown},
		{"CM close", "4e0220062401", "Forward_Close", AccessControl},
		{"file partial write", "4e0220372401", "Initiate_Partial_Write", AccessWrite},
		{"connection stop", "4e0220f32401", "Stop_Connection", AccessControl},
		{"bridge read unsupported", "4e0220442401", "Read_Holding_Registers", AccessUnknown},
		{"fragmented symbolic read", "520291025447010004000000", "Read_Tag_Fragmented", AccessRead},
		{"fragmented instance read", "5202206b2401010004000000", "Read_Tag_Fragmented", AccessRead},
		{"unconnected send", "520220062401010004000000", "Unconnected_Send", AccessUnknown},
		{"fragmented symbolic write", "530291025447", "Write_Tag_Fragmented", AccessWrite},
		{"instance write", "4d02206b2401", "Write_Tag", AccessWrite},
		{"fragmented instance write", "5302206b2401", "Write_Tag_Fragmented", AccessWrite},
		{"large forward open", "5b0220062401", "Large_Forward_Open", AccessControl},
		{"forward open", "540220062401", "Forward_Open", AccessControl},
		{"concurrent open", "5c0220062401", "Concurrent_Forward_Open", AccessControl},
		{"concurrent close", "5e0220062401", "Concurrent_Forward_Close", AccessControl},
		{"CM query data", "560220062401", "Get_Connection_Data", AccessUnknown},
		{"CM query search", "570220062401", "Search_Connection_Data", AccessUnknown},
		{"CM query owner", "5a0220062401", "Get_Connection_Owner", AccessUnknown},
		{"CM wrong instance", "4e0220062402", "Unknown(0x4E)", AccessUnknown},
		{"CM missing instance", "5b012006", "Unknown(0x5B)", AccessUnknown},
		{"Symbol missing instance", "4c01206b0100", "Unknown(0x4C)", AccessUnknown},
		{"Template missing instance", "4c01206c000000001000", "Unknown(0x4C)", AccessUnknown},
		{"Symbol zero instance tag", "4c02206b24000100", "Unknown(0x4C)", AccessUnknown},
		{"symbol browse", "5502206b2400020001000200", "Get_Instance_Attribute_List", AccessRead},
		{"unknown browse target", "55022004240101000100", "Unknown(0x55)", AccessUnknown},
		{"symbolic browse unsupported", "55029102544701000100", "Unknown(0x55)", AccessUnknown},
		{"PCCC unsupported", "4b0220672401", "Execute_PCCC", AccessUnknown},
		{"bridge discrete read", "4b0220442401", "Read_Discrete_Inputs", AccessUnknown},
		{"bridge coils read", "4c0220442401", "Read_Coils", AccessUnknown},
		{"bridge registers read", "4d0220442401", "Read_Input_Registers", AccessUnknown},
		{"bridge passthrough", "510220442401", "Modbus_Passthrough", AccessUnknown},
		{"bridge coils write", "4f0220442401", "Write_Coils", AccessWrite},
		{"bridge registers write", "500220442401", "Write_Holding_Registers", AccessWrite},
		{"file upload setup", "4b0220372401", "Initiate_Upload", AccessStructural},
		{"file partial read setup", "4d0220372401", "Initiate_Partial_Read", AccessStructural},
		{"file upload transfer", "4f0220372401", "Upload_Transfer", AccessUnknown},
		{"file download transfer", "500220372401", "Download_Transfer", AccessWrite},
		{"file clear", "510220372401", "Clear_File", AccessWrite},
		{"configuration status", "500220f32401", "Get_Status", AccessUnknown},
		{"configuration kick", "4b0220f32401", "Kick_Timer", AccessControl},
		{"configuration close", "4d0220f32401", "Close_Connection", AccessControl},
		{"configuration change start", "4f0220f32401", "Change_Start", AccessControl},
		{"configuration complete", "510220f32401", "Change_Complete", AccessControl},
		{"configuration audit", "520220f32401", "Audit_Change", AccessControl},
		{"protocol admin", "4d0220f52401", "Set_Protocol_Admin_State", AccessWrite},
		{"DLR verify", "4b0220472401", "Verify_Fault_Location", AccessControl},
		{"DLR restart", "4d0220472401", "Restart_Sign_On", AccessControl},
		{"DLR gateway clear", "4e0220472401", "Clear_Gateway_Partial_Fault", AccessWrite},
		{"reset", "050220012401", "Reset", AccessControl},
		{"start", "060220012401", "Start", AccessControl},
		{"stop", "070220012401", "Stop", AccessControl},
		{"create", "08012001", "Create", AccessControl},
		{"delete", "090220012401", "Delete", AccessControl},
		{"group sync", "1c0220012401", "GroupSync", AccessControl},
		{"set all", "020220012401", "Set_Attributes_All", AccessWrite},
		{"set list", "040220012401", "Set_Attribute_List", AccessWrite},
		{"set single", "1003200124013001", "Set_Attribute_Single", AccessWrite},
		{"insert member", "1a03200424012801", "Insert_Member", AccessWrite},
		{"remove member", "1b03200424012801", "Remove_Member", AccessWrite},
		{"response tag", "cc0000000100", "Unknown(0x4C)", AccessUnknown},
		{"response common", "8e000000", "Get_Attribute_Single", AccessUnknown},
		{"class truncation", "0e012100", "Get_Attribute_Single", AccessUnknown},
		{"unsupported path", "0e0220012200", "Get_Attribute_Single", AccessUnknown},
		{"repeated class", "4c032037206b24010100", "Unknown(0x4C)", AccessUnknown},
		{"class symbolic mix", "4c04206b2401910254470100", "Unknown(0x4C)", AccessUnknown},
		{"no target", "4c000100", "Unknown(0x4C)", AccessUnknown},
		{"16 bit target", "4c0421006b00250001000100", "Read_Tag", AccessRead},
		{"symbol members", "4c069103544147002801290002000100", "Read_Tag", AccessRead},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire := requestBytes(t, tc.wire)
			msg, err := parseCIPFromItem(wire)
			if err != nil {
				t.Fatal(err)
			}
			if got := Classify(msg); got != tc.category {
				t.Fatalf("category=%v want=%v", got, tc.category)
			}
			evs := wireEvents(t, wire)
			if len(evs) != 1 {
				t.Fatalf("events=%+v", evs)
			}
			if got := evs[0].Attributes["service_name"]; got != tc.service {
				t.Errorf("service=%v want=%s", got, tc.service)
			}
			for form, attrs := range decodertest.Forms(t, evs[0].Attributes) {
				write, hasWrite := eventfields.Bool(attrs, "is_write")
				control, hasControl := eventfields.Bool(attrs, "is_control")
				classified := tc.category == AccessRead || tc.category == AccessWrite || tc.category == AccessControl
				if hasWrite != classified || hasControl != classified ||
					classified && (write != (tc.category != AccessRead) || control != (tc.category == AccessControl)) {
					t.Fatalf("%s access flags=%v", form, attrs)
				}
			}
		})
	}
}

func TestReadBodiesRequireExactLayout(t *testing.T) {
	for _, tc := range []struct {
		name, header, body string
	}{
		{"all", "010220012401", ""},
		{"single", "0e03200124013001", ""},
		{"member", "1803200424012801", ""},
		{"list", "030220012401", "020001000200"},
		{"tag", "4c0291025447", "0100"},
		{"instance tag", "4c02206b2401", "0100"},
		{"fragment", "520291025447", "010004000000"},
		{"instance fragment", "5202206b2401", "010004000000"},
		{"browse", "5502206b2400", "020001000200"},
		{"template", "4c02206c2401", "040000001000"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			header, body := requestBytes(t, tc.header), requestBytes(t, tc.body)
			// Every shorter body and every extra byte is unsupported.
			for n := 0; n <= len(body)+1; n++ {
				b := append([]byte(nil), body...)
				if n > len(body) {
					b = append(b, 0)
				} else {
					b = b[:n]
				}
				ev := wireEvents(t, append(append([]byte(nil), header...), b...))[0]
				_, hasWrite := ev.Attributes["is_write"]
				if hasWrite != (n == len(body)) {
					t.Fatalf("body length %d flags=%v", n, ev.Attributes)
				}
			}
		})
	}
	for _, wire := range []string{
		"4c02910254470000", "520291025447000000000000",
		"0302200124010000", "5502206b24000000",
		"030220012401ffff0100", "5502206b2400ffff0100",
	} {
		ev := wireEvents(t, requestBytes(t, wire))[0]
		if _, hasWrite := ev.Attributes["is_write"]; hasWrite {
			t.Fatalf("invalid count %s classified: %v", wire, ev.Attributes)
		}
	}
}

func TestInvalidTargetsNeverClassify(t *testing.T) {
	for _, path := range []string{
		"", "200124", "2101", "21016b002401", "9100",
		"910354414701", "91045447", "280191025447",
		"200124012402", "20013001", "2001240130013002",
		"206b2400220000000000", "206b240191025447",
	} {
		for _, service := range []byte{0x0e, 0x4c, 0x4e, 0x52, 0x5b} {
			p := requestBytes(t, path)
			wire := append([]byte{service, byte(len(p) / 2)}, p...)
			switch service {
			case 0x4c:
				wire = append(wire, 1, 0)
			case 0x52:
				wire = append(wire, 1, 0, 0, 0, 0, 0)
			}
			ev := wireEvents(t, wire)[0]
			if _, ok := ev.Attributes["is_write"]; ok {
				t.Fatalf("service=%02x path=%s classified: %v", service, path, ev.Attributes)
			}
		}
	}
}

func TestServiceAndClassNames(t *testing.T) {
	for class, want := range map[uint16]string{
		0x37: "File", 0x44: "Modbus", 0x48: "QoS", 0x67: "PCCC",
		0x6b: "Symbol", 0x6c: "Template", 0xf3: "Connection_Configuration",
		0xf5: "TCP_IP_Interface", 0xf6: "EtherNet_Link",
		0xac: "Logix_Controller_Metadata", 0x66: "Class(0x0066)", 0x68: "Class(0x0068)",
	} {
		if got := ObjectClassName(class); got != want {
			t.Errorf("class=%x name=%s want=%s", class, got, want)
		}
	}
	if got := ServiceName(0x4c, nil); got != "Unknown(0x4C)" {
		t.Fatal(got)
	}
}

func TestMSPAccessStaysOnChildren(t *testing.T) {
	body := mspWire(0x0a,
		requestBytes(t, "4c02910254470100"),
		requestBytes(t, "4c0220372401"),
		requestBytes(t, "4c02209924010100"))[2:]
	wire := append(requestBytes(t, "0a0220022401"), body...)
	msg, err := parseCIPFromItem(wire)
	if err != nil || Classify(msg) != AccessStructural {
		t.Fatalf("MSP category=%v err=%v", Classify(msg), err)
	}
	events := wireEvents(t, wire)
	if len(events) != 4 {
		t.Fatalf("events=%+v", events)
	}
	for i, want := range []any{nil, false, true, nil} {
		if got := events[i].Attributes["is_write"]; got != want {
			t.Fatalf("event %d write=%v want=%v", i, got, want)
		}
	}
	if _, inherited := events[1].Attributes["object_class"]; inherited {
		t.Fatal("symbolic child inherited Message Router class")
	}
}

func TestIncompleteMessageHasNoCategory(t *testing.T) {
	msg, err := parseCIPFromItem(requestBytes(t, "0e0320012401"))
	if err != ErrPathTruncated || Classify(msg) != AccessUnknown {
		t.Fatalf("category=%v err=%v", Classify(msg), err)
	}
}

func TestIncompleteEnvelopeDoesNotClassify(t *testing.T) {
	for _, wire := range [][]byte{
		buildEIPHeader(0x6f, 1, append(cpfMessage(0x0e, 2, 0x20, 1, 0x24, 1), 0)),
		append(buildEIPHeader(0x6f, 1, cpfMessage(0x0e, 2, 0x20, 1, 0x24, 1)), 0),
		buildEIPHeader(0x6f, 1, cpfMessage(0x0e, 3, 0x20, 1, 0x24, 1)),
	} {
		events, err := NewDecoder().OnPacket(cipState(), &dpi.ParsedPacket{Payload: wire})
		if err != nil || len(events) != 1 {
			t.Fatalf("events=%+v err=%v", events, err)
		}
		if _, classified := events[0].Attributes["is_write"]; classified {
			t.Fatal(events[0].Attributes)
		}
	}
}
