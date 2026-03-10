// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type systemStatsResponse struct {
	CPU        cpuStats       `json:"cpu"`
	Memory     memoryStats    `json:"memory"`
	Disk       diskStats      `json:"disk"`
	RuleEval   ruleEvalStats  `json:"ruleEval"`
	Container  containerStats `json:"container"`
	Runtime    runtimeStats   `json:"runtime"`
	CollectedAt string        `json:"collectedAt"`
}

type cpuStats struct {
	UsagePercent float64 `json:"usagePercent"`
	NumCPU       int     `json:"numCPU"`
}

type memoryStats struct {
	TotalBytes     uint64  `json:"totalBytes"`
	UsedBytes      uint64  `json:"usedBytes"`
	AvailableBytes uint64  `json:"availableBytes"`
	UsagePercent   float64 `json:"usagePercent"`
}

type diskStats struct {
	TotalBytes     uint64  `json:"totalBytes"`
	UsedBytes      uint64  `json:"usedBytes"`
	AvailableBytes uint64  `json:"availableBytes"`
	UsagePercent   float64 `json:"usagePercent"`
}

type ruleEvalStats struct {
	RulesLoaded int     `json:"rulesLoaded"`
	AvgLatencyMs float64 `json:"avgLatencyMs"`
}

type containerStats struct {
	Running bool   `json:"running"`
	ID      string `json:"id,omitempty"`
	Image   string `json:"image,omitempty"`
	Uptime  string `json:"uptime,omitempty"`
	MemUsedBytes  uint64  `json:"memUsedBytes"`
	MemLimitBytes uint64  `json:"memLimitBytes"`
	MemPercent    float64 `json:"memPercent"`
}

type runtimeStats struct {
	Goroutines   int    `json:"goroutines"`
	HeapAllocMB  float64 `json:"heapAllocMB"`
	HeapSysMB    float64 `json:"heapSysMB"`
	GCPauseMsAvg float64 `json:"gcPauseMsAvg"`
	Uptime       string `json:"uptime"`
}

var processStartTime = time.Now()

func systemStatsHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		resp := systemStatsResponse{
			CollectedAt: time.Now().UTC().Format(time.RFC3339),
		}

		// CPU
		resp.CPU = collectCPU()

		// Memory
		resp.Memory = collectMemory()

		// Disk
		resp.Disk = collectDisk()

		// Go runtime
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		resp.Runtime = runtimeStats{
			Goroutines:  runtime.NumGoroutine(),
			HeapAllocMB: float64(ms.HeapAlloc) / 1048576,
			HeapSysMB:   float64(ms.HeapSys) / 1048576,
			Uptime:      time.Since(processStartTime).Truncate(time.Second).String(),
		}
		if ms.NumGC > 0 {
			var totalPause uint64
			n := ms.NumGC
			if n > 256 {
				n = 256
			}
			for i := uint32(0); i < n; i++ {
				totalPause += ms.PauseNs[i]
			}
			resp.Runtime.GCPauseMsAvg = float64(totalPause) / float64(n) / 1e6
		}

		// Container (cgroup-based detection for Docker/Podman)
		resp.Container = collectContainer()

		c.JSON(http.StatusOK, resp)
	}
}

// collectCPU reads /proc/stat to compute CPU usage.
// Falls back to 0 on non-Linux.
func collectCPU() cpuStats {
	st := cpuStats{NumCPU: runtime.NumCPU()}
	f, err := os.Open("/proc/stat")
	if err != nil {
		return st
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			break
		}
		user, _ := strconv.ParseUint(fields[1], 10, 64)
		nice, _ := strconv.ParseUint(fields[2], 10, 64)
		system, _ := strconv.ParseUint(fields[3], 10, 64)
		idle, _ := strconv.ParseUint(fields[4], 10, 64)
		total := user + nice + system + idle
		if total > 0 {
			active := user + nice + system
			st.UsagePercent = float64(active) / float64(total) * 100
		}
		break
	}
	return st
}

// collectMemory reads /proc/meminfo.
func collectMemory() memoryStats {
	var m memoryStats
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		// Fallback: Go runtime stats
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		m.UsedBytes = ms.Sys
		return m
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	vals := map[string]uint64{}
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		valStr := strings.TrimSpace(parts[1])
		valStr = strings.TrimSuffix(valStr, " kB")
		v, _ := strconv.ParseUint(strings.TrimSpace(valStr), 10, 64)
		vals[key] = v * 1024 // kB to bytes
	}
	m.TotalBytes = vals["MemTotal"]
	m.AvailableBytes = vals["MemAvailable"]
	if m.TotalBytes > m.AvailableBytes {
		m.UsedBytes = m.TotalBytes - m.AvailableBytes
	}
	if m.TotalBytes > 0 {
		m.UsagePercent = float64(m.UsedBytes) / float64(m.TotalBytes) * 100
	}
	return m
}

// collectDisk reads disk usage for /.
func collectDisk() diskStats {
	var d diskStats
	// Use syscall.Statfs on Linux; this file won't compile on non-Linux but
	// the build tags in the sibling file handle that.  For portability we
	// simply read /proc/mounts + df-like info, but the simplest cross-compile
	// approach is to read from the cgroup or just return zeros.
	d = diskStatfs("/")
	return d
}

// collectContainer reads cgroup v1/v2 to detect Docker container metrics.
func collectContainer() containerStats {
	var cs containerStats

	// Detect if running in a container
	if _, err := os.Stat("/.dockerenv"); err == nil {
		cs.Running = true
	} else if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		s := string(data)
		if strings.Contains(s, "docker") || strings.Contains(s, "containerd") || strings.Contains(s, "kubepods") {
			cs.Running = true
		}
	}

	if !cs.Running {
		return cs
	}

	// Container ID from hostname (Docker default)
	if h, err := os.Hostname(); err == nil && len(h) >= 12 {
		cs.ID = h[:12]
	}

	// Uptime from process start
	cs.Uptime = time.Since(processStartTime).Truncate(time.Second).String()

	// cgroup v2 memory
	if data, err := os.ReadFile("/sys/fs/cgroup/memory.current"); err == nil {
		cs.MemUsedBytes, _ = strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	} else if data, err := os.ReadFile("/sys/fs/cgroup/memory/memory.usage_in_bytes"); err == nil {
		// cgroup v1
		cs.MemUsedBytes, _ = strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	}
	if data, err := os.ReadFile("/sys/fs/cgroup/memory.max"); err == nil {
		s := strings.TrimSpace(string(data))
		if s != "max" {
			cs.MemLimitBytes, _ = strconv.ParseUint(s, 10, 64)
		}
	} else if data, err := os.ReadFile("/sys/fs/cgroup/memory/memory.limit_in_bytes"); err == nil {
		cs.MemLimitBytes, _ = strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	}
	if cs.MemLimitBytes > 0 && cs.MemUsedBytes > 0 {
		cs.MemPercent = float64(cs.MemUsedBytes) / float64(cs.MemLimitBytes) * 100
	}

	return cs
}

// dockerSockAvailable checks if the Docker socket is reachable.
func dockerSockAvailable() bool {
	conn, err := net.DialTimeout("unix", "/var/run/docker.sock", 500*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// dockerContainerCount queries the Docker API for running container count.
// Returns -1 if unavailable.
func dockerContainerCount(ctx context.Context) int {
	if !dockerSockAvailable() {
		return -1
	}
	client := http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.DialTimeout("unix", "/var/run/docker.sock", time.Second)
			},
		},
		Timeout: 2 * time.Second,
	}
	req, err := http.NewRequestWithContext(ctx, "GET", "http://localhost/containers/json", nil)
	if err != nil {
		return -1
	}
	resp, err := client.Do(req)
	if err != nil {
		return -1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return -1
	}
	// Count the JSON array elements without fully parsing
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return -1
	}
	s := strings.TrimSpace(string(body))
	if s == "[]" || s == "null" {
		return 0
	}
	// Quick count by counting top-level objects
	count := 0
	depth := 0
	for _, ch := range s {
		switch ch {
		case '{':
			if depth == 1 {
				count++
			}
			depth++
		case '}':
			depth--
		case '[':
			depth++
		case ']':
			depth--
		}
	}
	return count
}
