// SPDX-License-Identifier: Apache-2.0

package itdpi

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/limits"
	"golang.org/x/net/http/httpguts"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const maxH2Frame = 16384
const maxH2Block = 64 * 1024
const hpackTableSize = 4096

// hpackDecoderEnvelopeBytes audits x/net v0.62.0's opaque Decoder. The RFC
// table retains at most 4096/32 entries, plus one insertion before eviction.
// Allow twice those slots at 64 bytes each (HeaderField is <=40 on 64-bit),
// 4096 indexed string bytes, and two maxHTTPHeaders strings for the incoming
// literal. Each whole-block Write is <=maxH2Block: allow twice that capacity
// for saveBuf/input retention. Tripling all variable terms covers old+new
// slice/buffer replacement peaks; DecoderMetadataBytes covers fixed state.
// The dependency-version/capacity proof test must be re-audited on upgrades.
const hpackDecoderEnvelopeBytes = int(limits.DecoderMetadataBytes) +
	3*(2*(hpackTableSize/32+1)*64+hpackTableSize+2*maxHTTPHeaders+2*maxH2Block)

type h2Stream struct {
	memory   *flow.InspectionMemory
	decoder  *hpack.Decoder
	started  bool
	pending  uint32
	block    []byte
	input    []byte // last whole-block Write may still be referenced by Decoder
	suppress bool
}

func newH2Stream(memory *flow.InspectionMemory) (*h2Stream, error) {
	if !memory.Reserve(hpackDecoderEnvelopeBytes) {
		return nil, flow.ErrInspectionLimit
	}
	d := hpack.NewDecoder(hpackTableSize, nil)
	d.SetAllowedMaxDynamicTableSize(hpackTableSize)
	d.SetMaxStringLength(maxHTTPHeaders)
	return &h2Stream{memory: memory, decoder: d}, nil
}

func (s *h2Stream) release() {
	if s.decoder == nil {
		return
	}
	size := hpackDecoderEnvelopeBytes + cap(s.block) + cap(s.input)
	s.decoder, s.block, s.input = nil, nil, nil
	s.memory.Refund(size)
}

func (s *h2Stream) frame(st *flow.State, p []byte) (int, []dpi.Event, error) {
	if len(p) < 9 {
		return 0, nil, nil
	}
	n := int(p[0])<<16 | int(p[1])<<8 | int(p[2])
	if n > maxH2Frame {
		return 0, nil, fmt.Errorf("HTTP/2 frame size limit")
	}
	if len(p) < 9+n {
		return 0, nil, nil
	}
	// Frame ordering is tracked below across manager calls, including
	// PUSH_PROMISE continuations. The library validates each frame payload.
	reader := bytes.NewReader(p[:9+n])
	header, err := http2.ReadFrameHeader(reader)
	if err != nil {
		return 0, nil, err
	}
	f, err := http2.NewFramer(nil, reader).ReadFrameForHeader(header)
	if err != nil {
		return 0, nil, fmt.Errorf("invalid HTTP/2 frame: %w", err)
	}
	if !s.started {
		settings, ok := f.(*http2.SettingsFrame)
		if !ok || settings.IsAck() {
			return 0, nil, fmt.Errorf("HTTP/2 preface requires SETTINGS")
		}
		s.started = true
	}
	if s.pending != 0 && (f.Header().Type != http2.FrameContinuation || f.Header().StreamID != s.pending) {
		return 0, nil, fmt.Errorf("interrupted HTTP/2 header block")
	}
	var fragment []byte
	var id uint32
	var done bool
	switch f := f.(type) {
	case *http2.HeadersFrame:
		id, fragment, done = f.StreamID, f.HeaderBlockFragment(), f.HeadersEnded()
	case *http2.ContinuationFrame:
		if s.pending == 0 {
			return 0, nil, fmt.Errorf("unexpected HTTP/2 CONTINUATION")
		}
		id, fragment, done = f.StreamID, f.HeaderBlockFragment(), f.HeadersEnded()
	case *http2.PushPromiseFrame:
		// PUSH_PROMISE shares the direction's compression context. Decode it even
		// though pushed requests are not emitted as client-originated requests.
		id, fragment, done = f.StreamID, f.HeaderBlockFragment(), f.HeadersEnded()
		s.suppress = true
	case *http2.SettingsFrame:
		err := f.ForeachSetting(func(setting http2.Setting) error { return setting.Valid() })
		if err != nil {
			return 0, nil, fmt.Errorf("invalid HTTP/2 settings: %w", err)
		}
	}
	var events []dpi.Event
	if id != 0 {
		if len(s.block)+len(fragment) > maxH2Block {
			return 0, nil, fmt.Errorf("HTTP/2 compressed header limit")
		}
		if !replaceBytes(s.memory, &s.block, fragment) {
			return 0, nil, flow.ErrInspectionLimit
		}
		s.pending = id
		if done {
			attrs, kind, err := s.headers()
			if err != nil {
				return 0, nil, err
			}
			s.pending = 0
			if kind != "" && !s.suppress {
				for k, v := range httpTransport(st) {
					attrs[k] = v
				}
				attrs["stream_id"] = id
				events = append(events, dpi.Event{FlowID: st.ID(), Proto: "http2", Kind: kind, Attributes: attrs})
			}
			s.suppress = false
		}
	}
	return 9 + n, events, nil
}

func (s *h2Stream) headers() (map[string]any, string, error) {
	attrs := make(map[string]any)
	size := uint64(0)
	var invalid error
	regular := false
	pseudo := map[string]bool{}
	s.decoder.SetEmitFunc(func(f hpack.HeaderField) {
		size += uint64(len(f.Name) + len(f.Value) + 32)
		if size > maxHTTPHeaders {
			invalid = fmt.Errorf("HTTP/2 header list limit")
			s.decoder.SetEmitEnabled(false)
			return
		}
		if !httpguts.ValidHeaderFieldName(strings.TrimPrefix(f.Name, ":")) || strings.ToLower(f.Name) != f.Name || !httpguts.ValidHeaderFieldValue(f.Value) {
			invalid = fmt.Errorf("invalid HTTP/2 header")
			return
		}
		if strings.HasPrefix(f.Name, ":") {
			if regular || pseudo[f.Name] {
				invalid = fmt.Errorf("invalid HTTP/2 pseudo header order")
				return
			}
			pseudo[f.Name] = true
		} else {
			regular = true
		}
		switch f.Name {
		case ":method":
			attrs["method"] = f.Value
		case ":path":
			attrs["path"] = f.Value
		case ":authority":
			attrs["authority"] = f.Value
		case ":scheme":
			attrs["scheme"] = f.Value
		case ":status":
			attrs["status"] = f.Value
		case "connection", "proxy-connection", "keep-alive", "transfer-encoding", "upgrade":
			invalid = fmt.Errorf("connection-specific HTTP/2 header")
		case "te":
			if f.Value != "trailers" {
				invalid = fmt.Errorf("invalid HTTP/2 TE header")
			}
		case "content-type":
			attrs["content_type"] = f.Value
		default:
			if strings.HasPrefix(f.Name, ":") {
				invalid = fmt.Errorf("unknown HTTP/2 pseudo header")
			}
		}
	})
	// The decoder outlives this result; do not retain its attribute map/strings
	// through the callback between blocks.
	defer s.decoder.SetEmitFunc(discardHPACKField)
	s.decoder.SetEmitEnabled(true)
	oldInput := cap(s.input)
	s.input, s.block = s.block, nil
	_, writeErr := s.decoder.Write(s.input)
	s.memory.Refund(oldInput)
	if writeErr != nil {
		return nil, "", fmt.Errorf("invalid HPACK: %w", writeErr)
	}
	if err := s.decoder.Close(); err != nil {
		return nil, "", fmt.Errorf("incomplete HPACK: %w", err)
	}
	if invalid != nil {
		return nil, "", invalid
	}
	if status, ok := attrs["status"].(string); ok {
		if len(pseudo) != 1 || status == "101" || len(status) != 3 || status[0] < '1' || status[0] > '5' || status[1] < '0' || status[1] > '9' || status[2] < '0' || status[2] > '9' {
			return nil, "", fmt.Errorf("invalid HTTP/2 response headers")
		}
		return attrs, "response", nil
	}
	if method, ok := attrs["method"].(string); ok {
		path, _ := attrs["path"].(string)
		scheme, _ := attrs["scheme"].(string)
		if method == "" || (method != "CONNECT" && (path == "" || scheme == "")) || (method == "CONNECT" && (attrs["authority"] == nil || pseudo[":path"] || pseudo[":scheme"])) {
			return nil, "", fmt.Errorf("invalid HTTP/2 request headers")
		}
		return attrs, "request", nil
	}
	if len(pseudo) > 0 {
		return nil, "", fmt.Errorf("incomplete HTTP/2 request headers")
	}
	return attrs, "", nil // trailers update HPACK state, not a second request
}

func discardHPACKField(hpack.HeaderField) {}
