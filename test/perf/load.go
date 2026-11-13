// SPDX-License-Identifier: Apache-2.0
package main

import (
	"errors"
	"fmt"
	"math"
	"net"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// Logarithmic upper bounds at 1% precision, from 1 us to 60 s. Samples beyond
// the range are counted explicitly. Histograms merge by adding bucket counts.
type histogram struct {
	Buckets  [1802]uint64 `json:"buckets"`
	Count    uint64       `json:"count"`
	Overflow uint64       `json:"overflow"`
}

func (h *histogram) add(d time.Duration) {
	i := 0
	if us := float64(d) / float64(time.Microsecond); us > 1 {
		i = int(math.Ceil(math.Log(us) / math.Log(1.01)))
	}
	if i >= len(h.Buckets) {
		i = len(h.Buckets) - 1
		h.Overflow++
	}
	h.Buckets[i]++
	h.Count++
}
func (h *histogram) merge(other histogram) {
	for i, n := range other.Buckets {
		h.Buckets[i] += n
	}
	h.Count += other.Count
	h.Overflow += other.Overflow
}

type counts struct {
	Success      uint64    `json:"success"`
	Errors       uint64    `json:"errors"`
	Timeouts     uint64    `json:"timeouts"`
	Resets       uint64    `json:"resets"`
	Missed       uint64    `json:"missed_slots"`
	RequestBytes uint64    `json:"request_bytes"`
	ReplyBytes   uint64    `json:"reply_bytes"`
	RTT          histogram `json:"rtt"`
}

func (c *counts) failure(err error) {
	c.Errors++
	var n net.Error
	if errors.As(err, &n) && n.Timeout() {
		c.Timeouts++
	}
	if errors.Is(err, syscall.ECONNRESET) {
		c.Resets++
	}
}
func (c *counts) merge(b counts) {
	c.Success += b.Success
	c.Errors += b.Errors
	c.Timeouts += b.Timeouts
	c.Resets += b.Resets
	c.Missed += b.Missed
	c.RequestBytes += b.RequestBytes
	c.ReplyBytes += b.ReplyBytes
	c.RTT.merge(b.RTT)
}

type loadConfig struct {
	Protocol, Addr, Dir      string
	Sessions                 int
	Rate                     float64
	Warmup, Measure, Timeout time.Duration
}
type loadResult struct {
	Schema            int     `json:"schema"`
	Protocol          string  `json:"protocol"`
	Sessions          int     `json:"sessions"`
	Ready             int     `json:"ready"`
	CompletedSessions int     `json:"completed_sessions"`
	Offered           float64 `json:"offered_tps"`
	Seconds           float64 `json:"seconds"`
	TimeoutMS         float64 `json:"timeout_ms"`
	Main              counts  `json:"main"`
	Probe             counts  `json:"probe"`
	WarmupErrors      uint64  `json:"warmup_errors"`
}

func connectSession(cfg loadConfig) (*session, error) {
	c, err := net.DialTimeout("tcp", cfg.Addr, cfg.Timeout)
	if err != nil {
		return nil, err
	}
	if err = c.(*net.TCPConn).SetNoDelay(true); err != nil {
		c.Close()
		return nil, err
	}
	s := &session{conn: c, protocol: cfg.Protocol}
	if err = c.SetDeadline(time.Now().Add(cfg.Timeout)); err == nil {
		err = s.init(false)
	}
	if err == nil {
		_, _, err = s.exchange(false)
	}
	if err != nil {
		c.Close()
		return nil, err
	}
	return s, nil
}
func transact(s *session, cfg loadConfig, c *counts) bool {
	start := time.Now()
	if err := s.conn.SetDeadline(start.Add(cfg.Timeout)); err != nil {
		c.failure(err)
		return false
	}
	req, rep, err := s.exchange(false)
	if err != nil {
		c.failure(err)
		return false
	}
	c.Success++
	c.RequestBytes += uint64(req)
	c.ReplyBytes += uint64(rep)
	c.RTT.add(time.Since(start))
	return true
}
func steady(s *session, cfg loadConfig, start time.Time, duration time.Duration, rate float64, offset time.Duration) (counts, bool) {
	var c counts
	period := time.Duration(float64(time.Second) / rate)
	if period < time.Microsecond {
		period = time.Microsecond
	}
	end := start.Add(duration)
	next := start.Add(offset)
	for next.Before(end) {
		if delay := time.Until(next); delay > 0 {
			time.Sleep(delay)
		}
		if !time.Now().Before(end) {
			break
		}
		if !transact(s, cfg, &c) {
			return c, false
		}
		next = next.Add(period)
		if lag := time.Since(next); lag >= period {
			skip := uint64(lag / period)
			c.Missed += skip
			next = next.Add(time.Duration(skip) * period)
		}
	}
	if left := time.Until(end); left > 0 {
		time.Sleep(left)
	}
	return c, true
}
func load(cfg loadConfig) error {
	result := loadResult{Schema: 1, Protocol: cfg.Protocol, Sessions: cfg.Sessions, Offered: cfg.Rate, TimeoutMS: float64(cfg.Timeout) / float64(time.Millisecond)}
	sessions := make([]*session, 0, cfg.Sessions+1)
	defer func() {
		for _, s := range sessions {
			s.conn.Close()
		}
	}()
	for range cfg.Sessions + 1 {
		s, err := connectSession(cfg)
		if err != nil {
			result.Main.failure(err)
			if err := save(filepath.Join(cfg.Dir, "result.json"), result); err != nil {
				return err
			}
			return fmt.Errorf("application readiness: %w", err)
		}
		sessions = append(sessions, s)
	}
	result.Ready = cfg.Sessions
	warmStart := time.Now().Add(50 * time.Millisecond)
	var wg sync.WaitGroup
	var mu sync.Mutex
	for i, s := range sessions {
		wg.Go(func() {
			r := cfg.Rate / float64(cfg.Sessions)
			if i == cfg.Sessions {
				r = 10
			}
			c, _ := steady(s, cfg, warmStart, cfg.Warmup, r, 0)
			mu.Lock()
			result.WarmupErrors += c.Errors
			mu.Unlock()
		})
	}
	wg.Wait()
	if result.WarmupErrors != 0 {
		if err := save(filepath.Join(cfg.Dir, "result.json"), result); err != nil {
			return err
		}
		return fmt.Errorf("warmup errors")
	}
	if err := save(filepath.Join(cfg.Dir, "ready.json"), map[string]int{"ready": result.Ready}); err != nil {
		return err
	}
	if err := marker(filepath.Join(cfg.Dir, "go"), time.Now().Add(90*time.Second)); err != nil {
		return err
	}
	start := time.Now().Add(50 * time.Millisecond)
	for i, s := range sessions {
		wg.Go(func() {
			r := cfg.Rate / float64(cfg.Sessions)
			offset := time.Duration(float64(time.Second) * float64(i) / cfg.Rate)
			if i == cfg.Sessions {
				r = 10
				offset = 0
			}
			c, complete := steady(s, cfg, start, cfg.Measure, r, offset)
			mu.Lock()
			if i == cfg.Sessions {
				result.Probe = c
			} else {
				result.Main.merge(c)
				if complete && c.Success > 0 {
					result.CompletedSessions++
				}
			}
			mu.Unlock()
		})
	}
	wg.Wait()
	result.Seconds = time.Since(start).Seconds()
	if err := save(filepath.Join(cfg.Dir, "result.json"), result); err != nil {
		return err
	}
	if err := marker(filepath.Join(cfg.Dir, "release"), time.Now().Add(90*time.Second)); err != nil {
		return err
	}
	if result.Main.Errors+result.Probe.Errors > 0 || result.CompletedSessions != cfg.Sessions {
		return fmt.Errorf("steady load errors")
	}
	return nil
}
