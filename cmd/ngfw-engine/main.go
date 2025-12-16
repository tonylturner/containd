package main

import (
	"context"
	"log"

	engineapp "github.com/containd/containd/pkg/app/engine"
)

func main() {
	if err := engineapp.Run(context.Background(), engineapp.Options{}); err != nil {
		log.Fatalf("%v", err)
	}
}
