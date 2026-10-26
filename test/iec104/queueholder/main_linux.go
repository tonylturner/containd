//go:build linux

// Command queueholder binds an NFQUEUE number before the containd engine
// does, so the harness can prove what the engine does when its queue bind
// fails at start. It is test tooling for
// scripts/smoke-iec104.sh and runs inside the firewall container.
//
// It accepts every packet it receives. That is the strict case: a foreign
// consumer owns the queue and would let IEC envelope traffic through, so the
// engine, which knows its own bind failed, must fail closed by itself rather
// than rely on the kernel dropping packets for an unbound queue.
//
// It prints "bound queue N" once the bind succeeds and runs until SIGTERM or
// SIGINT. A failed bind exits 1.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/florianl/go-nfqueue/v2"
	"golang.org/x/sys/unix"
)

func main() {
	queueNum := flag.Uint("queue", 101, "NFQUEUE number to hold")
	flag.Parse()
	if *queueNum == 0 || *queueNum > 65535 {
		fmt.Fprintln(os.Stderr, "queue must be 1..65535")
		os.Exit(2)
	}
	if err := run(uint16(*queueNum)); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(queueNum uint16) error {
	queue, err := nfqueue.Open(&nfqueue.Config{
		NfQueue:      queueNum,
		MaxQueueLen:  1024,
		MaxPacketLen: 65535,
		Copymode:     nfqueue.NfQnlCopyPacket,
		AfFamily:     unix.AF_INET,
	})
	if err != nil {
		return fmt.Errorf("open queue %d: %w", queueNum, err)
	}
	defer queue.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	accept := func(attr nfqueue.Attribute) int {
		if attr.PacketID != nil {
			if err := queue.SetVerdict(*attr.PacketID, nfqueue.NfAccept); err != nil {
				fmt.Fprintf(os.Stderr, "verdict %d: %v\n", *attr.PacketID, err)
			}
		}
		return 0
	}
	onErr := func(err error) int {
		if ctx.Err() != nil {
			return 1
		}
		if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
			return 0
		}
		fmt.Fprintf(os.Stderr, "queue %d receive: %v\n", queueNum, err)
		return 1
	}
	if err := queue.RegisterWithErrorFunc(ctx, accept, onErr); err != nil {
		return fmt.Errorf("bind queue %d: %w", queueNum, err)
	}
	fmt.Printf("bound queue %d\n", queueNum)
	<-ctx.Done()
	return nil
}
