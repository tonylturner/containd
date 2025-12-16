package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	engineapp "github.com/containd/containd/pkg/app/engine"
	mgmtapp "github.com/containd/containd/pkg/app/mgmt"
)

func main() {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("CONTAIND_MODE")))
	if len(os.Args) > 1 && strings.TrimSpace(os.Args[1]) != "" {
		mode = strings.ToLower(strings.TrimSpace(os.Args[1]))
	}
	if mode == "" {
		mode = "all"
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var err error
	switch mode {
	case "all":
		err = runAll(ctx)
	case "mgmt":
		err = mgmtapp.Run(ctx, mgmtapp.Options{})
	case "engine":
		err = engineapp.Run(ctx, engineapp.Options{})
	default:
		err = fmt.Errorf("unknown mode %q (expected all|mgmt|engine)", mode)
	}
	if err != nil {
		log.Fatalf("%v", err)
	}
}

func runAll(ctx context.Context) error {
	errCh := make(chan error, 2)
	go func() { errCh <- engineapp.Run(ctx, engineapp.Options{}) }()
	go func() { errCh <- mgmtapp.Run(ctx, mgmtapp.Options{}) }()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}
