//go:build !linux

package conntrack

import "fmt"

func List(limit int) ([]Entry, error) {
	return nil, fmt.Errorf("conntrack is only available on Linux")
}

