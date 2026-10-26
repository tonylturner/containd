// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package eventfields

import "strconv"

// APDU direction letters for APDUID.
const (
	DirClient byte = 'c' // client (TCP opener) to server
	DirServer byte = 's' // server to client
)

// SessionID returns "<runID>-<seq lowercase hex>".
func SessionID(runID string, seq uint64) string {
	return runID + "-" + strconv.FormatUint(seq, 16)
}

// APDUID returns "<session>/<c|s>/<start decimal>". dir is DirClient or
// DirServer.
func APDUID(session string, dir byte, start int64) string {
	return session + "/" + string(rune(dir)) + "/" + strconv.FormatInt(start, 10)
}
