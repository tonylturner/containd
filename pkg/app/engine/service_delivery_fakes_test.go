// SPDX-License-Identifier: Apache-2.0
package engineapp

import (
	"context"
	"errors"
	"reflect"
	"sync"

	"github.com/tonylturner/containd/pkg/common/protection"
	"github.com/tonylturner/containd/pkg/cp/config"
)

// A fake runtime owner: successful apply stays live until its next mutation.
type testServiceOwner struct {
	mu    sync.Mutex
	out   protection.OwnerOutcome
	input any
	fn    func(context.Context) error
}

func (d *testServiceOwner) apply(ctx context.Context, meta protection.Metadata, name protection.SubsystemName, enabled bool, input any, fn func(context.Context) error) (protection.OwnerOutcome, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.out.Acknowledged != nil && reflect.DeepEqual(input, d.input) {
		ack := *d.out.Acknowledged
		ack.Metadata = meta
		d.out.Acknowledged, d.out.DesiredRevision = &ack, meta.RunningRevision
		return d.out, nil
	}
	d.input, d.fn = input, fn
	attempt := d.out.Attempt + 1
	d.out = fakeServiceOutcome(meta, name, enabled, attempt, errors.New("delivery outstanding"))
	d.out = fakeServiceOutcome(meta, name, enabled, attempt, fn(ctx))
	return d.out, nil
}
func fakeServiceOutcome(meta protection.Metadata, name protection.SubsystemName, enabled bool, attempt int, err error) protection.OwnerOutcome {
	out := wireGuardOutcome(meta, enabled, attempt, err)
	out.Name = name
	if name == protection.SubsystemAV {
		out.Owner = protection.OwnerManagement
	}
	if errors.Is(err, context.DeadlineExceeded) {
		out.State, out.Fault = protection.DeliveryPending, nil
	}
	return out
}
func (d *testServiceOwner) RetryDelivery(ctx context.Context, meta protection.Metadata) (protection.OwnerOutcome, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.out.Retryable {
		d.out = fakeServiceOutcome(meta, d.out.Name, d.out.Operation == protection.OperationApply, d.out.Attempt+1, d.fn(ctx))
	}
	return d.out, nil
}
func (d *testServiceOwner) DeliveryOutcome() protection.OwnerOutcome {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.out
}
func fakeWireGuard(apply func(context.Context, config.WireGuardConfig) error) *wireGuardDelivery {
	return newWireGuardDelivery(apply, func(context.Context, config.WireGuardConfig) (string, error) { return "live", nil })
}
