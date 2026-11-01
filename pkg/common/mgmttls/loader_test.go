// SPDX-License-Identifier: Apache-2.0

package mgmttls

import (
	"bytes"
	"crypto/tls"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type loaderCounts struct {
	stats, reads, parses atomic.Int64
}

func countedLoader(cert, key string) (*Loader, *loaderCounts) {
	l := NewLoader(cert, key)
	counts := &loaderCounts{}
	l.ops.stat = func(path string) (os.FileInfo, error) {
		counts.stats.Add(1)
		return diskLoaderOps.stat(path)
	}
	l.ops.read = func(path string) ([]byte, os.FileInfo, error) {
		counts.reads.Add(1)
		return diskLoaderOps.read(path)
	}
	l.ops.parse = func(data []byte) (*tls.Certificate, error) {
		counts.parses.Add(1)
		return diskLoaderOps.parse(data)
	}
	return l, counts
}

func replaceIdentityFile(t *testing.T, path string, data []byte, timestamp time.Time) {
	t.Helper()
	next := path + ".next"
	if err := os.WriteFile(next, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(next, timestamp, timestamp); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(next, path); err != nil {
		t.Fatal(err)
	}
}

func TestLoaderCachesValidAndInvalidIdentities(t *testing.T) {
	for _, bundle := range []bool{true, false} {
		t.Run(map[bool]string{true: "bundle", false: "split"}[bundle], func(t *testing.T) {
			cert, key := testPair(t)
			nextCert, nextKey := testPair(t)
			nextPair, err := tls.X509KeyPair(nextCert, nextKey)
			if err != nil {
				t.Fatal(err)
			}
			c, k := filepath.Join(t.TempDir(), "cert"), ""
			k = c + ".key"
			if bundle {
				cert, err = bundleBytes(cert, key)
				if err != nil {
					t.Fatal(err)
				}
				nextCert, err = bundleBytes(nextCert, nextKey)
				if err != nil {
					t.Fatal(err)
				}
				k = c
			}
			// Preserve size and mtime across replacement: inode must detect it.
			size := max(len(cert), len(nextCert))
			cert = append(cert, bytes.Repeat([]byte(" "), size-len(cert))...)
			nextCert = append(nextCert, bytes.Repeat([]byte(" "), size-len(nextCert))...)
			timestamp := time.Unix(1700000000, 0)
			replaceIdentityFile(t, c, cert, timestamp)
			if !bundle {
				replaceIdentityFile(t, k, key, timestamp)
			}
			l, counts := countedLoader(c, k)
			first, err := l.GetCertificate(nil)
			if err != nil {
				t.Fatal(err)
			}
			files := int64(1)
			if !bundle {
				files = 2
			}
			for range 10 {
				got, err := l.GetCertificate(nil)
				if err != nil || got != first {
					t.Fatal("unchanged handshake lost cached pair")
				}
			}
			if counts.parses.Load() != 1 || counts.reads.Load() != files || counts.stats.Load() != 11*files {
				t.Fatalf("unchanged files: stats=%d reads=%d parses=%d", counts.stats.Load(), counts.reads.Load(), counts.parses.Load())
			}

			replaceIdentityFile(t, c, nextCert, timestamp)
			if !bundle {
				replaceIdentityFile(t, k, nextKey, timestamp)
			}
			next, err := l.GetCertificate(nil)
			if err != nil || !bytes.Equal(next.Certificate[0], nextPair.Certificate[0]) {
				t.Fatal("next handshake did not serve rename-replaced identity")
			}
			if counts.parses.Load() != 2 || counts.reads.Load() != 2*files {
				t.Fatal("replacement not loaded once")
			}
			invalid := bytes.Repeat([]byte("?"), size)
			replaceIdentityFile(t, c, invalid, timestamp)
			last, remembered := l.Reload()
			if remembered == nil || last != next {
				t.Fatal("invalid rotation did not retain last-good and its error")
			}
			for range 10 {
				got, err := l.GetCertificate(nil)
				if err != nil || got != next {
					t.Fatal("invalid rotation interrupted handshakes")
				}
				leaf, err := l.PublicLeaf()
				if leaf != next.Leaf || err != remembered {
					t.Fatal("status did not return the cached public leaf and error")
				}
			}
			if counts.parses.Load() != 3 || counts.reads.Load() != 3*files {
				t.Fatalf("invalid identity reread or reparsed: reads=%d parses=%d", counts.reads.Load(), counts.parses.Load())
			}
			replaceIdentityFile(t, c, invalid, timestamp)
			if _, err := l.Reload(); err == nil || err == remembered || counts.parses.Load() != 4 {
				t.Fatal("another invalid inode did not produce exactly one new parse/error")
			}
		})
	}
}

func TestLoaderMetadataChangesAndMissingFiles(t *testing.T) {
	for _, change := range []string{"size", "mtime", "key", "missing"} {
		t.Run(change, func(t *testing.T) {
			cert, key := testPair(t)
			c, k := filepath.Join(t.TempDir(), "cert"), ""
			k = c + ".key"
			timestamp := time.Unix(1700000000, 0)
			replaceIdentityFile(t, c, cert, timestamp)
			replaceIdentityFile(t, k, key, timestamp)
			l, counts := countedLoader(c, k)
			first, err := l.GetCertificate(nil)
			if err != nil {
				t.Fatal(err)
			}
			switch change {
			case "size":
				if err := os.WriteFile(c, append(cert, '\n'), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chtimes(c, timestamp, timestamp); err != nil {
					t.Fatal(err)
				}
			case "mtime":
				if err := os.Chtimes(c, timestamp.Add(time.Second), timestamp.Add(time.Second)); err != nil {
					t.Fatal(err)
				}
			case "key":
				replaceIdentityFile(t, k, key, timestamp)
			case "missing":
				if err := os.Rename(k, k+".removed"); err != nil {
					t.Fatal(err)
				}
			}
			_, remembered := l.Reload()
			for range 10 {
				got, err := l.GetCertificate(nil)
				if err != nil || got == nil {
					t.Fatal("cached handshake failed")
				}
				_, err = l.PublicLeaf()
				if err != remembered {
					t.Fatal("error was not remembered")
				}
			}
			wantParses := int64(2)
			if change == "missing" {
				wantParses = 1
				if remembered == nil || l.LastLeaf() != first.Leaf {
					t.Fatal("missing key did not preserve last-good")
				}
			}
			if counts.parses.Load() != wantParses {
				t.Fatalf("parses=%d want %d", counts.parses.Load(), wantParses)
			}
		})
	}
}

func TestLoaderCachesInvalidStartup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.pem")
	if err := os.WriteFile(path, []byte("invalid"), 0o600); err != nil {
		t.Fatal(err)
	}
	l, counts := countedLoader(path, path)
	_, remembered := l.GetCertificate(nil)
	if remembered == nil {
		t.Fatal("invalid startup accepted")
	}
	for range 10 {
		pair, err := l.GetCertificate(nil)
		if pair != nil || err != remembered {
			t.Fatal("invalid startup was not cached")
		}
	}
	if counts.parses.Load() != 1 || counts.reads.Load() != 1 {
		t.Fatal("invalid startup identity reread or reparsed")
	}
}

func TestLoaderCachesOpenedInode(t *testing.T) {
	cert, key := testPair(t)
	nextCert, nextKey := testPair(t)
	nextPair, err := tls.X509KeyPair(nextCert, nextKey)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "server.pem")
	if err := Publish(path, cert, key); err != nil {
		t.Fatal(err)
	}
	l, counts := countedLoader(path, path)
	read := l.ops.read
	l.ops.read = func(path string) ([]byte, os.FileInfo, error) {
		// Replace after the path stat but before open. The cached identity
		// must belong to the inode actually read, not to the stale probe.
		if err := Publish(path, nextCert, nextKey); err != nil {
			return nil, nil, err
		}
		return read(path)
	}
	first, err := l.GetCertificate(nil)
	if err != nil || !bytes.Equal(first.Certificate[0], nextPair.Certificate[0]) {
		t.Fatal("loaded the wrong inode")
	}
	for range 10 {
		got, err := l.GetCertificate(nil)
		if err != nil || got != first {
			t.Fatal("cache did not identify the opened inode")
		}
	}
	if counts.reads.Load() != 1 || counts.parses.Load() != 1 {
		t.Fatal("rename between stat and open caused repeated reads/parses")
	}
}

func TestLoaderHandshakesDoNotWaitForOtherIO(t *testing.T) {
	for _, phase := range []string{"stat", "read"} {
		t.Run(phase, func(t *testing.T) {
			cert, key := testPair(t)
			path := filepath.Join(t.TempDir(), "server.pem")
			if err := Publish(path, cert, key); err != nil {
				t.Fatal(err)
			}
			l, _ := countedLoader(path, path)
			first, err := l.GetCertificate(nil)
			if err != nil {
				t.Fatal(err)
			}
			entered, release := make(chan struct{}), make(chan struct{})
			var armed atomic.Bool
			armed.Store(true)
			block := func() {
				if armed.CompareAndSwap(true, false) {
					close(entered)
					<-release
				}
			}
			if phase == "stat" {
				stat := l.ops.stat
				l.ops.stat = func(path string) (os.FileInfo, error) { block(); return stat(path) }
			} else {
				read := l.ops.read
				l.ops.read = func(path string) ([]byte, os.FileInfo, error) { block(); return read(path) }
				cert, key = testPair(t)
				if err := Publish(path, cert, key); err != nil {
					t.Fatal(err)
				}
			}
			done := make(chan struct{})
			go func() {
				defer close(done)
				if _, err := l.GetCertificate(nil); err != nil {
					t.Error(err)
				}
			}()
			var once sync.Once
			t.Cleanup(func() {
				once.Do(func() { close(release) })
				<-done
			})
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("reload never entered blocked I/O")
			}
			returned := make(chan struct{})
			go func() {
				defer close(returned)
				pair, err := l.GetCertificate(nil)
				if err != nil || pair != first {
					t.Error("parallel handshake lost last-good snapshot")
				}
			}()
			select {
			case <-returned:
			case <-time.After(5 * time.Second):
				once.Do(func() { close(release) })
				<-returned
				t.Fatal("handshake serialized on another request's I/O")
			}
			once.Do(func() { close(release) })
			<-done
		})
	}
}
