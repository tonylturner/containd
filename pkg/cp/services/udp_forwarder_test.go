package services

import "testing"

func TestNewUDPForwarderInvalid(t *testing.T) {
	if _, err := newUDPForwarder("256.256.256.256", 514); err == nil {
		t.Fatalf("expected error for invalid address")
	}
}
