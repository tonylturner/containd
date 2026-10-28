// SPDX-License-Identifier: Apache-2.0
package dnp3

import (
	"testing"

	"github.com/tonylturner/containd/pkg/dp/internal/corpus"
)

func captureSegments(f *testing.F) [][]byte {
	f.Helper()
	var result [][]byte
	for _, fixture := range referenceFixtures(f) {
		result = append(result, corpus.Seeds(fixture)...)
	}
	return result
}
func captureStreams(f *testing.F) [][]byte {
	f.Helper()
	var result [][]byte
	for _, fixture := range referenceFixtures(f) {
		seeds, err := corpus.StreamSeeds(fixture)
		if err != nil {
			f.Fatal(err)
		}
		result = append(result, seeds...)
	}
	return result
}
func seedCapturedObjects(f *testing.F) {
	f.Helper()

	for _, fixture := range referenceFixtures(f) {
		streams, err := corpus.StreamSeeds(fixture)
		if err != nil {
			f.Fatal(err)
		}
		for _, stream := range streams {
			for pos := 0; pos < len(stream); {
				n, err := frameLinkFrame(stream[pos:])
				if err != nil || n == 0 {
					if fixture.Expectations["frame_error"] != nil {
						break
					} // declared unframeable suffix has no object seeds
					f.Fatalf("committed capture cannot frame at %d: %v", pos, err)
				}
				frame := decodeLinkFrame(stream[pos : pos+n])
				pos += n
				if !frame.HasApplicationHeader() {
					continue
				}
				offset := 3
				if IsResponse(frame.FunctionCode) {
					offset = 5
				}
				f.Add(frame.Data[min(offset, len(frame.Data)):], frame.FunctionCode)
			}
		}
	}
}
