// SPDX-License-Identifier: Apache-2.0

package engineapp

import (
	"context"
	"net/http"

	"github.com/tonylturner/containd/pkg/common/protection"
	"github.com/tonylturner/containd/pkg/cp/config"
)

// ownershipDelivery is protected by the owner's applyMu, including background
// reconciliation. Callbacks retain their attempt identity and never acquire the
// coordinator's effect lock (which may be waiting for this owner).
type ownershipDelivery struct {
	coordinator       *protectionCoordinator
	delivery          map[protection.SubsystemName]func(bool, bool)
	active            map[protection.SubsystemName]func() bool
	interfacesApplied func(context.Context, []config.Interface)
}

func (d *ownershipDelivery) bindDelivery(r *http.Request, name protection.SubsystemName) {
	completion, ok := r.Context().Value(completionKey{}).(phaseCompletion)
	if !ok {
		return
	}
	if d.delivery == nil {
		d.delivery = map[protection.SubsystemName]func(bool, bool){}
		d.active = map[protection.SubsystemName]func() bool{}
	}
	d.delivery[name] = func(done, failed bool) {
		completion.c.outcome(completion.m, name, true, done, failed, "")
	}
	d.active[name] = func() bool {
		return completion.c.dp.Protection().Observation().Metadata == completion.m
	}
}

func (d *ownershipDelivery) currentDelivery(name protection.SubsystemName) bool {
	current := d.active[name]
	return current == nil || current()
}

func (d *ownershipDelivery) publishDelivery(name protection.SubsystemName, done, failed bool) {
	if publish := d.delivery[name]; publish != nil {
		publish(done, failed)
	}
}
