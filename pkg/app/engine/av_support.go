// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engineapp

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/cp/services"
	"github.com/tonylturner/containd/pkg/dp/engine"
	dpevents "github.com/tonylturner/containd/pkg/dp/events"
)

type avSinkAdapter struct {
	av *services.AVManager
	dp *engine.Engine
}

func (a *avSinkAdapter) EnqueueAVScan(ctx context.Context, task engine.AVScanTask) {
	if a == nil || a.av == nil {
		return
	}
	a.av.EnqueueScan(services.ScanTask{
		Hash:    task.Hash,
		Proto:   task.Proto,
		Source:  task.Source,
		Dest:    task.Dest,
		Preview: task.Preview,
		ICS:     task.ICS,
		Metadata: map[string]any{
			"direction": task.Direction,
			"flow_id":   task.FlowID,
		},
	})
}

func (a *avSinkAdapter) ApplyAVConfig(ctx context.Context, cfg config.AVConfig) error {
	if a == nil || a.av == nil {
		return fmt.Errorf("av sink unavailable")
	}
	return a.av.Apply(ctx, cfg)
}

func wireAVEvents(avMgr *services.AVManager, dpEngine *engine.Engine) {
	if avMgr == nil {
		return
	}
	if dpEngine != nil && dpEngine.Events() != nil {
		avMgr.OnEvent = func(kind string, attrs map[string]any) {
			dpEngine.Events().Append(dpevents.Event{
				Proto:      "service",
				Kind:       kind,
				Attributes: attrs,
				Timestamp:  time.Now().UTC(),
			})
		}
	}
	if dpEngine != nil {
		avMgr.OnVerdict = func(task services.ScanTask, res services.ScanResult) {
			handleAVVerdict(dpEngine, task, res)
		}
	}
}

func handleAVVerdict(dpEngine *engine.Engine, task services.ScanTask, res services.ScanResult) {
	if dpEngine == nil || res.Verdict == "" {
		return
	}
	events := dpEngine.Events()
	flowID := ""
	if task.Metadata != nil {
		if v, ok := task.Metadata["flow_id"].(string); ok {
			flowID = v
		}
	}
	emit := func(kind string, attrs map[string]any) {
		if events == nil {
			return
		}
		events.Append(dpevents.Event{
			Proto:      "service",
			Kind:       kind,
			Attributes: attrs,
			FlowID:     flowID,
			Timestamp:  time.Now().UTC(),
		})
	}
	cfg := config.AVConfig{}
	if a, ok := dpEngine.AVSink().(*avSinkAdapter); ok && a != nil && a.av != nil {
		cfg = a.av.Current()
	}
	if task.ICS && cfg.FailOpenICS {
		emit("service.av.bypass_ics", map[string]any{
			"hash":   task.Hash,
			"proto":  task.Proto,
			"source": task.Source,
			"dest":   task.Dest,
		})
		return
	}
	if res.Verdict != "malware" {
		return
	}
	emit("service.av.detected", map[string]any{
		"hash":    task.Hash,
		"proto":   task.Proto,
		"source":  task.Source,
		"dest":    task.Dest,
		"flow_id": flowID,
	})
	upd := dpEngine.Updater()
	if upd == nil {
		return
	}
	srcIP, dstIP, dport, proto := parseHostPort(task.Source, task.Dest)
	if srcIP == nil || dstIP == nil || proto == "" || dport == "" {
		return
	}
	ttl := time.Duration(cfg.BlockTTL) * time.Second
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = upd.BlockFlowTemp(ctx, srcIP, dstIP, proto, dport, ttl)
	emit("service.av.block_flow", map[string]any{
		"hash":   task.Hash,
		"src":    task.Source,
		"dst":    task.Dest,
		"proto":  proto,
		"dport":  dport,
		"ttl":    int(ttl.Seconds()),
		"reason": "av_malware",
	})
}

func parseHostPort(src, dst string) (net.IP, net.IP, string, string) {
	srcHost, _, _ := strings.Cut(src, ":")
	dstHost, dstPort, _ := strings.Cut(dst, ":")
	return net.ParseIP(strings.TrimSpace(srcHost)), net.ParseIP(strings.TrimSpace(dstHost)), strings.TrimSpace(dstPort), "tcp"
}
