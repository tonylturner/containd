// SPDX-License-Identifier: Apache-2.0
package ids

import (
	"bytes"
	"strings"
	"unicode"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// The parser's document start includes directives, not just '---'. Its line
// positions distinguish actual boundaries from marker text inside scalars.
// Inter-document comments stay with the preceding document; concatenating all
// slices recovers the complete original UTF-8 stream, including line endings.
func sigmaDocumentSources(data []byte, documents []*yaml.Node) ([]string, error) {
	sources := make([]string, len(documents))
	if len(documents) == 0 {
		return sources, nil
	}
	if sigmaUTF16Source(data) {
		// A UTF-16 stream has one encoding BOM. Later byte slices have no BOM
		// and yaml.v3 cannot decode them independently. Also, non-UTF-8 bytes
		// cannot survive RawSource's JSON persistence, even for one document.
		for i, doc := range documents {
			source, err := yaml.Marshal(doc)
			if err != nil {
				return nil, err
			}
			sources[i] = string(source)
		}
		return sources, nil
	}
	if len(documents) == 1 {
		sources[0] = string(data)
		return sources, nil
	}
	lines := sigmaLineOffsets(data)
	start := 0
	for i := 1; i < len(documents); i++ {
		end := lines[documents[i].Line-1]
		sources[i-1] = string(data[start:end])
		start = end
	}
	sources[len(sources)-1] = string(data[start:])
	return sources, nil
}

// YAML recognizes CRLF, CR, LF, NEL, LS and PS as line breaks.
func sigmaLineOffsets(data []byte) []int {
	offsets := []int{0}
	for i := 0; i < len(data); {
		r, size := utf8.DecodeRune(data[i:])
		i += size
		if r == '\r' && i < len(data) && data[i] == '\n' {
			i++
		}
		switch r {
		case '\r', '\n', '\u0085', '\u2028', '\u2029':
			offsets = append(offsets, i)
		}
	}
	return offsets
}

func sigmaExplicitDocument(text string) bool {
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(text), &doc); err != nil {
		return false
	} // caller already validated the source
	lines := sigmaLineOffsets([]byte(text))
	if doc.Line < 1 || doc.Line > len(lines) {
		return false
	}
	start := strings.TrimPrefix(text[lines[doc.Line-1]:], "\ufeff")
	if strings.HasPrefix(start, "%") {
		return true
	}
	if !strings.HasPrefix(start, "---") {
		return false
	}
	if len(start) == 3 {
		return true
	}
	next, _ := utf8.DecodeRuneInString(start[3:])
	return unicode.IsSpace(next)
}

func sigmaUTF16Source(data []byte) bool {
	return bytes.HasPrefix(data, []byte{0xff, 0xfe}) || bytes.HasPrefix(data, []byte{0xfe, 0xff})
}
