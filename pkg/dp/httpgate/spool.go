// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package httpgate

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
)

// spoolError reports a temporary-file failure; the gate maps it to busy.
type spoolError struct{ err error }

func (e *spoolError) Error() string { return "httpgate: spool: " + e.err.Error() }
func (e *spoolError) Unwrap() error { return e.err }

// spool holds one body: in memory up to threshold bytes, then in an
// exclusive temporary file unlinked right after creation so a crash
// leaves nothing behind. It hashes what it holds.
type spool struct {
	dir       string
	threshold int64
	mem       []byte
	file      *os.File
	size      int64
	hash      hash.Hash
}

func newSpool(dir string, threshold int64) *spool {
	return &spool{dir: dir, threshold: threshold, hash: sha256.New()}
}

func (s *spool) Write(p []byte) (int, error) {
	if s.file == nil && s.size+int64(len(p)) <= s.threshold {
		s.mem = growTo(s.mem, int(s.size)+len(p), int(s.threshold))
		s.mem = append(s.mem, p...)
	} else {
		if s.file == nil {
			if err := s.openFile(); err != nil {
				return 0, &spoolError{err}
			}
		}
		if _, err := s.file.WriteAt(p, s.size); err != nil {
			return 0, &spoolError{err}
		}
	}
	s.hash.Write(p)
	s.size += int64(len(p))
	return len(p), nil
}

// openFile moves the held bytes to an unlinked exclusive temporary file.
func (s *spool) openFile() error {
	f, err := os.CreateTemp(s.dir, "httpgate-*.spool")
	if err != nil {
		return err
	}
	if err := os.Remove(f.Name()); err != nil {
		f.Close()
		return fmt.Errorf("unlink %s: %w", f.Name(), err)
	}
	if len(s.mem) > 0 {
		if _, err := f.WriteAt(s.mem, 0); err != nil {
			f.Close()
			return err
		}
	}
	s.file, s.mem = f, nil
	return nil
}

// ReadAt serves the held bytes.
func (s *spool) ReadAt(p []byte, off int64) (int, error) {
	if s.file != nil {
		return s.file.ReadAt(p, off)
	}
	if off < 0 || off >= s.size {
		return 0, io.EOF
	}
	n := copy(p, s.mem[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// sum is the lowercase hex SHA-256 of the held bytes.
func (s *spool) sum() string { return hex.EncodeToString(s.hash.Sum(nil)) }

// reader streams the held bytes from the start.
func (s *spool) reader() io.Reader { return io.NewSectionReader(s, 0, s.size) }

func (s *spool) close() {
	if s.file != nil {
		s.file.Close()
		s.file = nil
	}
	s.mem = nil
}

// growTo gives b capacity for need bytes without exceeding limit.
func growTo(b []byte, need, limit int) []byte {
	if cap(b) >= need {
		return b
	}
	c := min(max(2*cap(b), need), limit)
	nb := make([]byte, len(b), c)
	copy(nb, b)
	return nb
}

// fillOutcome classifies how spooling ended.
type fillOutcome int

const (
	fillComplete fillOutcome = iota
	// fillOversized: the body exceeds max; excess holds the first bytes
	// past the cap and the reader the rest.
	fillOversized
	// fillDisk: the spool file failed; excess holds the unspooled bytes.
	fillDisk
	// fillFraming: the body cannot complete (bad chunk, early EOF, reset).
	fillFraming
	// fillTimeout: idle or object deadline passed.
	fillTimeout
)

// fill spools src into s up to max bytes. It returns the bytes read but not
// spooled (so a pass-through can continue the stream) and the error.
func (s *spool) fill(src io.Reader, max int64) (fillOutcome, []byte, error) {
	buf := make([]byte, copyBufSize)
	for {
		want := min(int64(len(buf)), max-s.size+1)
		n, err := src.Read(buf[:want])
		if n > 0 {
			keep := int64(n)
			if s.size+keep > max {
				keep = max - s.size
			}
			if _, werr := s.Write(buf[:keep]); werr != nil {
				return fillDisk, append([]byte(nil), buf[:n]...), werr
			}
			if keep < int64(n) {
				return fillOversized, append([]byte(nil), buf[keep:n]...), nil
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return fillComplete, nil, nil
			}
			if isTimeout(err) {
				return fillTimeout, nil, err
			}
			return fillFraming, nil, err
		}
	}
}
