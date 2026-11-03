// SPDX-License-Identifier: Apache-2.0
package engineapp

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/tonylturner/containd/pkg/common/protection"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/netcfg"
)

type wireGuardDelivery struct {
	mu      sync.Mutex
	meta    protection.Metadata
	cfg     config.WireGuardConfig
	outcome protection.OwnerOutcome
	runtime string
	apply   func(context.Context, config.WireGuardConfig) error
	observe func(context.Context, config.WireGuardConfig) (string, error)
}

func newWireGuardDelivery(apply func(context.Context, config.WireGuardConfig) error, observe func(context.Context, config.WireGuardConfig) (string, error)) *wireGuardDelivery {
	return &wireGuardDelivery{apply: apply, observe: observe}
}

func (d *wireGuardDelivery) deliver(ctx context.Context, meta protection.Metadata, cfg config.WireGuardConfig, invalidate func()) (protection.OwnerOutcome, error) {
	data, _ := json.Marshal(cfg)
	cfg = config.WireGuardConfig{}
	_ = json.Unmarshal(data, &cfg)
	d.mu.Lock()
	defer d.mu.Unlock()
	if !meta.Valid() {
		return protection.OwnerOutcome{}, errors.New("invalid WireGuard delivery identity")
	}
	if d.meta.Valid() && reflect.DeepEqual(d.cfg, cfg) && d.outcome.Acknowledged != nil {
		runtime, err := d.observe(ctx, cfg)
		if err == nil && runtime == d.runtime {
			if d.meta != meta {
				d.outcome = wireGuardOutcome(meta, cfg.Enabled, d.outcome.Attempt, nil)
			}
			d.meta = meta
			return d.outcome, nil
		}
	}
	attempt := d.outcome.Attempt + 1
	d.meta = meta
	d.cfg = cfg
	d.outcome = wireGuardOutcome(meta, cfg.Enabled, attempt, errors.New("WireGuard delivery outstanding"))
	invalidate()
	err := d.apply(ctx, d.cfg)
	d.outcome = wireGuardOutcome(meta, cfg.Enabled, attempt, err)
	if err == nil {
		// Failure to observe does not undo synchronous delivery, but it makes
		// subsequent adoption undecidable and therefore requires redelivery.
		d.runtime, _ = d.observe(ctx, cfg)
	}
	return d.outcome, nil
}

func (d *wireGuardDelivery) retry(ctx context.Context, meta protection.Metadata) (protection.OwnerOutcome, error) {
	d.mu.Lock()
	if d.meta != meta {
		d.mu.Unlock()
		return protection.OwnerOutcome{}, errors.New("WireGuard delivery superseded")
	}
	cfg := d.cfg
	d.mu.Unlock()
	return d.deliver(ctx, meta, cfg, func() {})
}

func (d *wireGuardDelivery) observation() protection.OwnerOutcome {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.outcome.Acknowledged != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		runtime, err := d.observe(ctx, d.cfg)
		cancel()
		if err != nil || runtime != d.runtime {
			d.outcome = wireGuardOutcome(d.meta, d.cfg.Enabled, d.outcome.Attempt, errors.New("WireGuard runtime no longer matches"))
		}
	}
	out := d.outcome
	if out.Fault != nil {
		fault := *out.Fault
		out.Fault = &fault
	}
	if out.Acknowledged != nil {
		ack := *out.Acknowledged
		out.Acknowledged = &ack
	}
	return out
}

func wireGuardOutcome(meta protection.Metadata, enabled bool, attempt int, err error) protection.OwnerOutcome {
	op, state := protection.OperationApply, protection.DeliveryReady
	if !enabled {
		op, state = protection.OperationStop, protection.DeliveryOff
	}
	out := protection.OwnerOutcome{Name: protection.SubsystemWireGuard, Owner: protection.OwnerEngine,
		DesiredRevision: meta.RunningRevision, Operation: op, State: state, Attempt: attempt, ObservedAt: time.Now().UTC()}
	if err != nil {
		out.State, out.Retryable = protection.DeliveryFailed, true
		out.Fault = &protection.Fault{Kind: protection.FaultDelivery, Reason: "WireGuard delivery failed"}
	} else {
		out.Acknowledged = &protection.Acknowledgement{Metadata: meta, Operation: op}
	}
	return out
}

// Compare the same interface identity and configuration-bearing kernel facts,
// excluding handshake/counter/roaming endpoint telemetry.
func observeWireGuard(ctx context.Context, cfg config.WireGuardConfig) (string, error) {
	status, err := netcfg.GetWireGuardStatus(ctx, cfg.Interface)
	if err != nil {
		return "", err
	}
	if status.Present != cfg.Enabled {
		return "", errors.New("WireGuard presence changed")
	}
	if !cfg.Enabled {
		return "absent", nil
	}
	nic, err := net.InterfaceByName(status.Interface)
	if err != nil || nic.Flags&net.FlagUp == 0 {
		return "", errors.New("WireGuard interface unavailable")
	}
	addrs, err := nic.Addrs()
	if err != nil {
		return "", err
	}
	addresses := make([]string, len(addrs))
	for i, addr := range addrs {
		addresses[i] = addr.String()
	}
	slices.Sort(addresses)
	for i := range status.Peers {
		peer := &status.Peers[i]
		peer.Endpoint, peer.LastHandshake, peer.RxBytes, peer.TxBytes = "", "", 0, 0
		slices.Sort(peer.AllowedIPs)
	}
	slices.SortFunc(status.Peers, func(a, b netcfg.WireGuardPeerStatus) int { return strings.Compare(a.PublicKey, b.PublicKey) })
	data, err := json.Marshal(struct {
		Index     int
		Addresses []string
		Status    netcfg.WireGuardStatus
	}{nic.Index, addresses, status})
	return string(data), err
}
