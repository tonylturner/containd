package main

import (
	"context"
	"log"

	mgmtapp "github.com/containd/containd/pkg/app/mgmt"
)

func main() {
	if err := mgmtapp.Run(context.Background(), mgmtapp.Options{}); err != nil {
		log.Fatalf("%v", err)
	}
}
