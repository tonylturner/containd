// SPDX-License-Identifier: Apache-2.0

// Package markabi defines containd's conntrack and packet mark allocation.
// Writers own only their masks; socket, gate and foreign bits must survive.
package markabi

const (
	OwnedForwardCtBit uint32 = 0x00000001
	AdmittedBit       uint32 = 0x00000002
	ParityBit         uint32 = 0x00000004
	AdmissionCtMask   uint32 = 0x00000006

	QueueMarkMask       uint32 = 0x0f000000
	EnvelopeMark        uint32 = 0x01000000
	HandshakeMark       uint32 = 0x02000000
	ObservedMark        uint32 = 0x04000000
	EnforceScopeMark    uint32 = 0x08000000
	NonAdmitMark        uint32 = 0x10000000
	ContinuationSkbMask uint32 = 0x1f000000
)

// Replace changes only the bits in mask, even if value contains other bits.
func Replace(old, mask, value uint32) uint32 { return old&^mask | value&mask }

// ValidParity reports whether parity is encoded as zero or ParityBit.
func ValidParity(parity uint32) bool { return parity == 0 || parity == ParityBit }

// Admit stamps the current admission. Callers must validate parity first.
func Admit(old, parity uint32) uint32 {
	return Replace(old, AdmissionCtMask, AdmittedBit|parity&ParityBit)
}

// ClearAdmission invalidates admission without changing parity or ownership.
func ClearAdmission(old uint32) uint32 { return old &^ AdmittedBit }

// Queue enters inspection without retaining stale continuation flags.
func Queue(old, scope uint32) uint32 {
	return Replace(old, ContinuationSkbMask, scope&(EnvelopeMark|HandshakeMark|EnforceScopeMark))
}

// Continue builds the full NFQA_MARK replacement used with NF_REPEAT.
func Continue(old uint32, nonAdmit bool) uint32 {
	bits := ObservedMark
	if nonAdmit {
		bits |= NonAdmitMark
	}
	return Replace(old, ContinuationSkbMask, bits)
}

// Clean removes all continuation flags before a terminal verdict.
func Clean(old uint32) uint32 { return old &^ ContinuationSkbMask }
