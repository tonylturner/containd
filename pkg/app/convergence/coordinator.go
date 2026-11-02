// SPDX-License-Identifier: Apache-2.0

package convergence

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/tonylturner/containd/pkg/common/protection"
	"github.com/tonylturner/containd/pkg/cp/config"
)

type worker struct {
	cancel context.CancelFunc
	done   chan struct{}
	err    error // read only after done
}

type view struct {
	input    protection.Input
	deadline time.Time
	epoch    uint64
}

type coordinator struct {
	options      Options
	fence        chan struct{}
	wake         chan struct{}
	notify       chan struct{}
	mu           sync.Mutex
	current      view
	active       *worker
	running      bool
	work         *attempt // only the joined worker or transition-fence holder accesses it
	hooks        sync.Mutex
	demoKey      protection.Metadata
	pcapBoot     protection.BootID
	pcapSnapshot *config.RunningSnapshot
}

func New(options Options) (Coordinator, error) {
	if options.Store == nil || options.Engine == nil || options.Services == nil || options.Environment == nil {
		return nil, errors.New("store, engine, services and environment are required")
	}
	return &coordinator{options: options, fence: make(chan struct{}, 1),
		wake: make(chan struct{}, 1), notify: make(chan struct{}, 1)}, nil
}

func (c *coordinator) enter(ctx context.Context) error {
	select {
	case c.fence <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *coordinator) leave() { <-c.fence }

// drain never holds the status lock or a store/owner lock. A worker that ignores
// cancellation stays registered; a later transition must join it too.
func (c *coordinator) drain(ctx context.Context) error {
	c.mu.Lock()
	w := c.active
	c.mu.Unlock()
	if w == nil {
		return nil
	}
	w.cancel()
	timer := time.NewTimer(RetryBudget)
	defer timer.Stop()
	select {
	case <-w.done:
		c.mu.Lock()
		if c.active == w {
			c.active = nil
		}
		c.mu.Unlock()
		return nil
	case <-ctx.Done():
		c.drainFault()
		return errors.Join(ErrDrain, ctx.Err())
	case <-timer.C:
		c.drainFault()
		return ErrDrain
	}
}

func (c *coordinator) drainFault() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.invalidateLocked()
	c.current.input.Outcomes = replace(c.current.input.Outcomes, protection.OwnerOutcome{
		Name: protection.SubsystemConfig, Owner: protection.OwnerEngine,
		DesiredRevision: c.current.input.DesiredRevision, Operation: protection.OperationApply,
		State: protection.DeliveryUnknown, ObservedAt: time.Now().UTC(),
		Reason: "rollback delayed; runtime worker did not drain",
		Fault:  &protection.Fault{Kind: protection.FaultUnknown, Reason: "runtime uncertain; overlapping effects refused"},
	})
}

func (c *coordinator) invalidate() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.invalidateLocked()
}

func (c *coordinator) invalidateLocked() {
	c.retireLocked()
	if c.active != nil {
		c.active.cancel()
	}
}

func (c *coordinator) retireLocked() {
	c.current.epoch++
	c.current.input.Coherent = false
	c.current.input.Uncertain = true
	c.current.deadline = time.Time{}
}

func (c *coordinator) epoch() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.current.epoch
}

func (c *coordinator) valid(epoch uint64) bool { return c.epoch() == epoch }

func (c *coordinator) publish(epoch uint64, a *attempt) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.current.epoch != epoch {
		return false
	}
	c.current.input = protection.Input{
		DesiredRevision: a.desired(), Current: a.admission.Metadata,
		DesiredTrustRevision: protection.TrustRevision(a.prepared.Trust.Revision),
		Selection:            a.prepared.Selection, EnforcementEnabled: a.enforcing,
		Uncertain: a.uncertain, Coherent: true,
		Outcomes: originalFaults(a),
	}
	c.current.deadline = time.Time{}
	if a.snapshot != nil && a.snapshot.PendingConfirm != nil {
		c.current.deadline = a.snapshot.PendingConfirm.Deadline
	}
	return true
}

func (c *coordinator) launch(ctx context.Context, wait bool) (*worker, error) {
	if wait {
		if err := c.enter(ctx); err != nil {
			return nil, err
		}
	} else {
		select {
		case c.fence <- struct{}{}:
		default:
			return nil, nil
		}
	}
	defer c.leave()
	c.mu.Lock()
	if c.active != nil {
		select {
		case <-c.active.done:
			c.active = nil
		default:
			w := c.active
			c.mu.Unlock()
			return w, nil
		}
	}
	workCtx, cancel := context.WithTimeout(ctx, RetryBudget)
	w := &worker{cancel: cancel, done: make(chan struct{})}
	c.active = w
	epoch := c.current.epoch
	c.mu.Unlock()
	go func() {
		defer close(w.done)
		defer cancel()
		w.err = c.cycle(workCtx, epoch, false, nil)
		if w.err != nil {
			select {
			case c.options.Errors <- w.err:
			default:
			}
		}
	}()
	return w, nil
}

func (c *coordinator) Tick(ctx context.Context) error {
	w, err := c.launch(ctx, true)
	if err != nil {
		return err
	}
	select {
	case <-w.done:
		return w.err
	case <-ctx.Done():
		w.cancel()
		return ctx.Err()
	}
}

func (c *coordinator) Run(ctx context.Context) error {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return errors.New("convergence already running")
	}
	c.running = true
	c.mu.Unlock()
	c.options.Store.SetStoreNotify(c.notify)
	defer c.options.Store.SetStoreNotify(nil)
	defer func() {
		c.mu.Lock()
		c.running = false
		c.mu.Unlock()
	}()
	poll := time.NewTicker(time.Second)
	deadlines := time.NewTicker(100 * time.Millisecond)
	defer poll.Stop()
	defer deadlines.Stop()
	c.signal()
	for {
		select {
		case <-ctx.Done():
			// Entering the fence is context-bounded even if a synchronous
			// callback is still in its documented forward/compensation budget.
			joinCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*ApplyBudget+RetryBudget)
			err := c.enter(joinCtx)
			if err == nil {
				err = c.drain(joinCtx)
				c.invalidate()
				if err == nil {
					c.resetDemo(joinCtx)
				}
				c.leave()
			}
			cancel()
			return err
		case <-deadlines.C:
			c.expire()
		case <-poll.C:
			c.signal()
		case <-c.notify:
			c.signal()
		case <-c.wake:
			// Do not wait here: the deadline observer remains responsive to
			// effects or readers blocked inside the single bounded worker.
			_, err := c.launch(ctx, false)
			if err != nil && ctx.Err() == nil {
				return err
			}
		}
	}
}

func (c *coordinator) signal() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

// Expiry invalidates before waiting for any owner or store read. cycle rechecks
// the persisted pending generation/CAS before attempting rollback. A confirm
// may conservatively make status unknown until that read, never falsely ready.
func (c *coordinator) expire() {
	c.mu.Lock()
	deadline := c.current.deadline
	if deadline.IsZero() || time.Now().Before(deadline) {
		c.mu.Unlock()
		return
	}
	c.invalidateLocked()
	c.mu.Unlock()
	c.signal()
}

func (c *coordinator) Retry(target protection.Metadata) error {
	c.mu.Lock()
	matches := target == c.current.input.Current && !c.current.input.Uncertain
	c.mu.Unlock()
	if !matches {
		return ErrSuperseded
	}
	c.signal()
	return nil
}

func mintApplyID() (protection.ApplyID, error) {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return protection.ApplyID(hex.EncodeToString(b[:])), nil
}
