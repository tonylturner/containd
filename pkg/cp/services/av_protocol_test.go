// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package services

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

func nulReply(s string) fakeClamdReply {
	return func(string, []byte) []byte { return []byte(s + "\x00") }
}

func TestClamdScanParsesNULReplies(t *testing.T) {
	cases := []struct {
		name    string
		reply   []byte
		verdict string
		sig     string
		errPart string
	}{
		{name: "clean", reply: []byte("stream: OK\x00"), verdict: "clean"},
		{name: "found", reply: []byte("stream: Win.Test.EICAR_HDB-1 FOUND\x00"), verdict: "malware", sig: "Win.Test.EICAR_HDB-1"},
		{name: "error", reply: []byte("INSTREAM size limit exceeded. ERROR\x00"), errPart: "size limit"},
		{name: "newline only", reply: []byte("stream: OK\n"), errPart: "truncated"},
		{name: "truncated", reply: []byte("stream: O"), errPart: "truncated"},
		{name: "empty close", reply: []byte{}, errPart: "truncated"},
		{name: "oversize", reply: bytes.Repeat([]byte("A"), clamdMaxReply+10), errPart: "size limit"},
		{name: "unknown", reply: []byte("stream: MAYBE\x00"), errPart: "unexpected reply"},
		{name: "found without name", reply: []byte("stream:  FOUND\x00"), errPart: "without signature"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sock := startFakeClamd(t, func(string, []byte) []byte { return tc.reply })
			res, err := (&ClamAVClient{Timeout: time.Second, Socket: sock}).Scan(context.Background(), strings.NewReader("payload"), 7)
			if tc.errPart != "" {
				if err == nil || !strings.Contains(err.Error(), tc.errPart) {
					t.Fatalf("Scan() = %+v, %v; want error containing %q", res, err, tc.errPart)
				}
				return
			}
			if err != nil || res.Verdict != tc.verdict || res.Signature != tc.sig {
				t.Fatalf("Scan() = %+v, %v; want %s/%s", res, err, tc.verdict, tc.sig)
			}
		})
	}
}

func TestClamdScanStreamsChunkedPayload(t *testing.T) {
	payload := bytes.Repeat([]byte("0123456789abcdef"), (3*clamdChunkSize)/16+7)
	got := make(chan []byte, 1)
	sock := startFakeClamd(t, func(cmd string, stream []byte) []byte {
		if cmd == "INSTREAM" {
			got <- stream
		}
		return []byte("stream: OK\x00")
	})
	if _, err := (&ClamAVClient{Timeout: time.Second, Socket: sock}).Scan(context.Background(), bytes.NewReader(payload), int64(len(payload))); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if stream := <-got; !bytes.Equal(stream, payload) {
		t.Fatalf("clamd received %d bytes, want %d identical bytes", len(stream), len(payload))
	}
}

func TestClamdScanTimesOutWithoutReply(t *testing.T) {
	sock := startFakeClamd(t, func(string, []byte) []byte {
		time.Sleep(2 * time.Second)
		return nil
	})
	start := time.Now()
	_, err := (&ClamAVClient{Timeout: 200 * time.Millisecond, Socket: sock}).Scan(context.Background(), strings.NewReader("x"), 1)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if elapsed := time.Since(start); elapsed > 1500*time.Millisecond {
		t.Fatalf("timeout not honoured: %s", elapsed)
	}
}

func TestClamdCommands(t *testing.T) {
	sock := startFakeClamd(t, func(cmd string, _ []byte) []byte {
		switch cmd {
		case "PING":
			return []byte("PONG\x00")
		case "VERSION":
			return []byte("ClamAV 1.5.2/27800/Mon Oct 26 08:00:00 2026\x00")
		case "RELOAD":
			return []byte("RELOADING\x00")
		}
		return []byte("UNKNOWN COMMAND\x00")
	})
	client := &ClamAVClient{Timeout: time.Second, Socket: sock}
	if err := client.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if v, err := client.Version(context.Background()); err != nil || !strings.HasPrefix(v, "ClamAV 1.5.2/27800/") {
		t.Fatalf("Version = %q, %v", v, err)
	}
	if err := client.Reload(context.Background()); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	bad := &ClamAVClient{Timeout: time.Second, Socket: startFakeClamd(t, nulReply("NOPE"))}
	if err := bad.Ping(context.Background()); err == nil {
		t.Fatal("Ping accepted a non-PONG reply")
	}
	if _, err := bad.Version(context.Background()); err == nil {
		t.Fatal("Version accepted a non-version reply")
	}
	if err := bad.Reload(context.Background()); err == nil {
		t.Fatal("Reload accepted a non-RELOADING reply")
	}
	if err := (&ClamAVClient{Timeout: time.Second}).Ping(context.Background()); err == nil {
		t.Fatal("Ping without socket succeeded")
	}
}
