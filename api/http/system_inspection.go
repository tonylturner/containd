// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
)

// inspectionResponse is the full response for the system inspection endpoint
// used by the Physical topology view.
type inspectionResponse struct {
	Host      hostInfo      `json:"host"`
	Runtime   runtimeInfo   `json:"runtime"`
	Container containerInfo `json:"container"`
	Process   processInfo   `json:"process"`
	Security  securityInfo  `json:"security"`
}

type hostInfo struct {
	Kernel     string `json:"kernel"`
	OS         string `json:"os"`
	Arch       string `json:"arch"`
	HostUptime string `json:"hostUptime"`
	NumCPU     int    `json:"numCPU"`
}

type runtimeInfo struct {
	DockerVersion    string `json:"dockerVersion,omitempty"`
	ContainerdVersion string `json:"containerdVersion,omitempty"`
	CgroupDriver     string `json:"cgroupDriver"`
	StorageDriver    string `json:"storageDriver,omitempty"`
}

type containerInfo struct {
	ID              string    `json:"id,omitempty"`
	Image           string    `json:"image,omitempty"`
	RestartPolicy   string    `json:"restartPolicy,omitempty"`
	RestartCount    int       `json:"restartCount"`
	NetworkMode     string    `json:"networkMode,omitempty"`
	Privileged      bool      `json:"privileged"`
	SeccompProfile  string    `json:"seccompProfile,omitempty"`
	ApparmorProfile string    `json:"apparmorProfile,omitempty"`
	ReadonlyRootfs  bool      `json:"readonlyRootfs"`
	NoNewPrivileges bool      `json:"noNewPrivileges"`
	Capabilities    []string  `json:"capabilities,omitempty"`
	Mounts          []mountInfo `json:"mounts,omitempty"`
	EnvVars         []envVar  `json:"envVars,omitempty"`
}

type mountInfo struct {
	HostPath      string `json:"hostPath"`
	ContainerPath string `json:"containerPath"`
	Mode          string `json:"mode"`
}

type envVar struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type processInfo struct {
	PID         int    `json:"pid"`
	GoVersion   string `json:"goVersion"`
	FDCount     int    `json:"fdCount"`
	FDSoftLimit uint64 `json:"fdSoftLimit"`
	FDHardLimit uint64 `json:"fdHardLimit"`
}

type securityInfo struct {
	DockerSocketMounted bool   `json:"dockerSocketMounted"`
	CgroupCPUQuota      string `json:"cgroupCPUQuota,omitempty"`
	CgroupPIDsLimit     string `json:"cgroupPIDsLimit,omitempty"`
}

// capNames maps Linux capability bit positions to names.
var capNames = map[int]string{
	0:  "CAP_CHOWN",
	1:  "CAP_DAC_OVERRIDE",
	2:  "CAP_DAC_READ_SEARCH",
	3:  "CAP_FOWNER",
	4:  "CAP_FSETID",
	5:  "CAP_KILL",
	6:  "CAP_SETGID",
	7:  "CAP_SETUID",
	8:  "CAP_SETPCAP",
	9:  "CAP_LINUX_IMMUTABLE",
	10: "CAP_NET_BIND_SERVICE",
	11: "CAP_NET_BROADCAST",
	12: "CAP_NET_ADMIN",
	13: "CAP_NET_RAW",
	14: "CAP_IPC_LOCK",
	15: "CAP_IPC_OWNER",
	16: "CAP_SYS_MODULE",
	17: "CAP_SYS_RAWIO",
	18: "CAP_SYS_CHROOT",
	19: "CAP_SYS_PTRACE",
	20: "CAP_SYS_PACCT",
	21: "CAP_SYS_ADMIN",
	22: "CAP_SYS_BOOT",
	23: "CAP_SYS_NICE",
	24: "CAP_SYS_RESOURCE",
	25: "CAP_SYS_TIME",
	26: "CAP_SYS_TTY_CONFIG",
	27: "CAP_MKNOD",
	28: "CAP_LEASE",
	29: "CAP_AUDIT_WRITE",
	30: "CAP_AUDIT_CONTROL",
	31: "CAP_SETFCAP",
	32: "CAP_MAC_OVERRIDE",
	33: "CAP_MAC_ADMIN",
	34: "CAP_SYSLOG",
	35: "CAP_WAKE_ALARM",
	36: "CAP_BLOCK_SUSPEND",
	37: "CAP_AUDIT_READ",
	38: "CAP_PERFMON",
	39: "CAP_BPF",
	40: "CAP_CHECKPOINT_RESTORE",
}

// safeEnvPrefixes lists prefixes for environment variables safe to expose.
var safeEnvPrefixes = []string{"CONTAIND_"}

// safeEnvKeys lists exact environment variable keys safe to expose.
var safeEnvKeys = map[string]bool{
	"LOG_LEVEL": true,
	"TZ":        true,
	"HOME":      true,
	"PATH":      true,
}

func systemInspectionHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		resp := inspectionResponse{}

		// Host info
		resp.Host = collectHostInfo()

		// Process info
		resp.Process = collectProcessInfo()

		// Security checks
		resp.Security = collectSecurityInfo()

		// Container + Runtime info (try Docker API first, fall back to proc)
		hostname, _ := os.Hostname()
		if dockerSockAvailable() {
			ri, ci, dockerHost := collectFromDocker(c.Request.Context(), hostname)
			resp.Runtime = ri
			resp.Container = ci
			// Prefer Docker-reported host info over /proc (which shows container's view)
			if dockerHost.OS != "" {
				resp.Host.OS = dockerHost.OS
			}
			if dockerHost.Kernel != "" {
				resp.Host.Kernel = dockerHost.Kernel
			}
			if dockerHost.Arch != "" {
				resp.Host.Arch = dockerHost.Arch
			}
		}

		// Fill in anything Docker didn't provide from /proc
		enrichFromProc(&resp.Container)

		// Always populate capabilities from /proc/self/status
		if len(resp.Container.Capabilities) == 0 {
			resp.Container.Capabilities = collectCapabilities()
		}

		// Always populate mounts from /proc/self/mountinfo
		if len(resp.Container.Mounts) == 0 {
			resp.Container.Mounts = collectMounts()
		}

		// Environment variables (filtered)
		if len(resp.Container.EnvVars) == 0 {
			resp.Container.EnvVars = collectFilteredEnv()
		}

		// Cgroup driver detection
		if resp.Runtime.CgroupDriver == "" {
			resp.Runtime.CgroupDriver = detectCgroupDriver()
		}

		c.JSON(http.StatusOK, resp)
	}
}

// collectHostInfo reads kernel, OS, arch and uptime from /proc and /etc/os-release.
func collectHostInfo() hostInfo {
	h := hostInfo{
		Arch:   runtime.GOARCH,
		NumCPU: runtime.NumCPU(),
	}

	// Kernel version from /proc/version
	if data, err := os.ReadFile("/proc/version"); err == nil {
		line := strings.TrimSpace(string(data))
		// First three fields: "Linux version X.Y.Z-..."
		if fields := strings.Fields(line); len(fields) >= 3 {
			h.Kernel = fields[2]
		}
	}

	// OS name from /etc/os-release
	if f, err := os.Open("/etc/os-release"); err == nil {
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				val := strings.TrimPrefix(line, "PRETTY_NAME=")
				val = strings.Trim(val, "\"")
				h.OS = val
				break
			}
		}
	}

	// Host uptime from /proc/uptime
	if data, err := os.ReadFile("/proc/uptime"); err == nil {
		fields := strings.Fields(strings.TrimSpace(string(data)))
		if len(fields) >= 1 {
			if secs, err := strconv.ParseFloat(fields[0], 64); err == nil {
				d := time.Duration(secs * float64(time.Second))
				h.HostUptime = d.Truncate(time.Second).String()
			}
		}
	}

	return h
}

// collectProcessInfo gathers process-level information.
func collectProcessInfo() processInfo {
	p := processInfo{
		PID:       os.Getpid(),
		GoVersion: runtime.Version(),
	}

	// Count open file descriptors
	if entries, err := os.ReadDir("/proc/self/fd"); err == nil {
		p.FDCount = len(entries)
	}

	// File descriptor limits
	var rlim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rlim); err == nil {
		p.FDSoftLimit = rlim.Cur
		p.FDHardLimit = rlim.Max
	}

	return p
}

// collectSecurityInfo checks Docker socket presence and cgroup resource limits.
func collectSecurityInfo() securityInfo {
	s := securityInfo{}

	// Docker socket mounted?
	if _, err := os.Stat("/var/run/docker.sock"); err == nil {
		s.DockerSocketMounted = true
	}

	// CPU quota: cgroup v2 cpu.max or cgroup v1 cpu.cfs_quota_us
	if data, err := os.ReadFile("/sys/fs/cgroup/cpu.max"); err == nil {
		s.CgroupCPUQuota = strings.TrimSpace(string(data))
	} else if data, err := os.ReadFile("/sys/fs/cgroup/cpu/cpu.cfs_quota_us"); err == nil {
		s.CgroupCPUQuota = strings.TrimSpace(string(data))
	}

	// PIDs limit: cgroup v2 pids.max or cgroup v1
	if data, err := os.ReadFile("/sys/fs/cgroup/pids.max"); err == nil {
		s.CgroupPIDsLimit = strings.TrimSpace(string(data))
	} else if data, err := os.ReadFile("/sys/fs/cgroup/pids/pids.max"); err == nil {
		s.CgroupPIDsLimit = strings.TrimSpace(string(data))
	}

	return s
}

// dockerHTTPClient returns an HTTP client that communicates over the Docker Unix socket.
func dockerHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.DialTimeout("unix", "/var/run/docker.sock", 2*time.Second)
			},
		},
		Timeout: 3 * time.Second,
	}
}

// collectFromDocker queries the Docker API for runtime, container, and host details.
// The returned hostInfo contains the Docker daemon's view of the host OS, which
// reflects the actual host (e.g., macOS) rather than the container's Linux distro.
func collectFromDocker(ctx context.Context, hostname string) (runtimeInfo, containerInfo, hostInfo) {
	ri := runtimeInfo{}
	ci := containerInfo{}
	hostOut := hostInfo{}
	client := dockerHTTPClient()

	// Docker version info
	if req, err := http.NewRequestWithContext(ctx, "GET", "http://localhost/version", nil); err == nil {
		if resp, err := client.Do(req); err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
				var ver map[string]interface{}
				if json.Unmarshal(body, &ver) == nil {
					if v, ok := ver["Version"].(string); ok {
						ri.DockerVersion = v
					}
					// Containerd version from Docker components
					if components, ok := ver["Components"].([]interface{}); ok {
						for _, comp := range components {
							if m, ok := comp.(map[string]interface{}); ok {
								if name, _ := m["Name"].(string); strings.EqualFold(name, "containerd") {
									if v, ok := m["Version"].(string); ok {
										ri.ContainerdVersion = v
									}
								}
							}
						}
					}
				}
			}
		}
	}

	// Docker info for storage/cgroup driver
	if req, err := http.NewRequestWithContext(ctx, "GET", "http://localhost/info", nil); err == nil {
		if resp, err := client.Do(req); err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
				var info map[string]interface{}
				if json.Unmarshal(body, &info) == nil {
					if v, ok := info["Driver"].(string); ok {
						ri.StorageDriver = v
					}
					if v, ok := info["CgroupDriver"].(string); ok {
						ri.CgroupDriver = v
					}
					// Host OS info from Docker daemon (reflects actual host, not container)
					if v, ok := info["OperatingSystem"].(string); ok {
						hostOut.OS = v
					}
					if v, ok := info["KernelVersion"].(string); ok {
						hostOut.Kernel = v
					}
					if v, ok := info["Architecture"].(string); ok {
						hostOut.Arch = v
					}
				}
			}
		}
	}

	// Container inspect for our own container
	containerID := hostname
	inspectURL := fmt.Sprintf("http://localhost/containers/%s/json", containerID)
	if req, err := http.NewRequestWithContext(ctx, "GET", inspectURL, nil); err == nil {
		if resp, err := client.Do(req); err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
				var cj map[string]interface{}
				if json.Unmarshal(body, &cj) == nil {
					ci = parseDockerInspect(cj)
				}
			}
		}
	}

	return ri, ci, hostOut
}

// parseDockerInspect extracts container details from a Docker inspect JSON response.
func parseDockerInspect(cj map[string]interface{}) containerInfo {
	ci := containerInfo{}

	if id, ok := cj["Id"].(string); ok {
		if len(id) > 12 {
			ci.ID = id[:12]
		} else {
			ci.ID = id
		}
	}

	if config, ok := cj["Config"].(map[string]interface{}); ok {
		if img, ok := config["Image"].(string); ok {
			ci.Image = img
		}
		// Environment variables (filtered)
		if envList, ok := config["Env"].([]interface{}); ok {
			ci.EnvVars = filterEnvList(envList)
		}
	}

	if hostConfig, ok := cj["HostConfig"].(map[string]interface{}); ok {
		if nm, ok := hostConfig["NetworkMode"].(string); ok {
			ci.NetworkMode = nm
		}
		if priv, ok := hostConfig["Privileged"].(bool); ok {
			ci.Privileged = priv
		}
		if ro, ok := hostConfig["ReadonlyRootfs"].(bool); ok {
			ci.ReadonlyRootfs = ro
		}

		// Restart policy
		if rp, ok := hostConfig["RestartPolicy"].(map[string]interface{}); ok {
			if name, ok := rp["Name"].(string); ok {
				ci.RestartPolicy = name
			}
		}

		// Security options
		if secOpts, ok := hostConfig["SecurityOpt"].([]interface{}); ok {
			for _, opt := range secOpts {
				s, _ := opt.(string)
				if strings.HasPrefix(s, "no-new-privileges") {
					ci.NoNewPrivileges = true
				}
				if strings.HasPrefix(s, "seccomp=") {
					ci.SeccompProfile = strings.TrimPrefix(s, "seccomp=")
				}
				if strings.HasPrefix(s, "apparmor=") {
					ci.ApparmorProfile = strings.TrimPrefix(s, "apparmor=")
				}
			}
		}

		// Capabilities
		if capAdd, ok := hostConfig["CapAdd"].([]interface{}); ok {
			for _, cap := range capAdd {
				if s, ok := cap.(string); ok {
					ci.Capabilities = append(ci.Capabilities, s)
				}
			}
		}

		// Mounts/Binds
		if binds, ok := hostConfig["Binds"].([]interface{}); ok {
			for _, b := range binds {
				s, _ := b.(string)
				parts := strings.SplitN(s, ":", 3)
				if len(parts) >= 2 {
					m := mountInfo{
						HostPath:      parts[0],
						ContainerPath: parts[1],
						Mode:          "rw",
					}
					if len(parts) == 3 {
						m.Mode = parts[2]
					}
					ci.Mounts = append(ci.Mounts, m)
				}
			}
		}
	}

	// Restart count
	if rc, ok := cj["RestartCount"].(float64); ok {
		ci.RestartCount = int(rc)
	}

	// AppArmor from top-level
	if ap, ok := cj["AppArmorProfile"].(string); ok && ap != "" && ci.ApparmorProfile == "" {
		ci.ApparmorProfile = ap
	}

	return ci
}

// filterEnvList filters a Docker env list ([]interface{} of "KEY=VALUE") to safe keys.
func filterEnvList(envList []interface{}) []envVar {
	var result []envVar
	for _, e := range envList {
		s, ok := e.(string)
		if !ok {
			continue
		}
		parts := strings.SplitN(s, "=", 2)
		if len(parts) != 2 {
			continue
		}
		if isEnvSafe(parts[0]) {
			result = append(result, envVar{Key: parts[0], Value: parts[1]})
		}
	}
	return result
}

// isEnvSafe returns true if the environment variable key is in the allow list.
func isEnvSafe(key string) bool {
	if safeEnvKeys[key] {
		return true
	}
	for _, prefix := range safeEnvPrefixes {
		if strings.HasPrefix(key, prefix) {
			return true
		}
	}
	return false
}

// enrichFromProc fills container info fields from /proc when Docker API is not available.
func enrichFromProc(ci *containerInfo) {
	// Container ID from hostname if not set
	if ci.ID == "" {
		if h, err := os.Hostname(); err == nil && len(h) >= 12 {
			ci.ID = h[:12]
		}
	}

	// Image from /proc/1/environ if not set
	if ci.Image == "" {
		if data, err := os.ReadFile("/proc/1/environ"); err == nil {
			// environ is null-delimited
			for _, entry := range strings.Split(string(data), "\x00") {
				if strings.HasPrefix(entry, "CONTAIND_IMAGE=") {
					ci.Image = strings.TrimPrefix(entry, "CONTAIND_IMAGE=")
					break
				}
			}
		}
	}

	// NoNewPrivileges from /proc/self/status
	if data, err := os.ReadFile("/proc/self/status"); err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "NoNewPrivs:") {
				val := strings.TrimSpace(strings.TrimPrefix(line, "NoNewPrivs:"))
				if val == "1" {
					ci.NoNewPrivileges = true
				}
			}
		}
	}
}

// collectCapabilities reads CapEff from /proc/self/status and decodes the hex bitmask.
func collectCapabilities() []string {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return nil
	}

	var capHex string
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "CapEff:") {
			capHex = strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
			break
		}
	}
	if capHex == "" {
		return nil
	}

	// Parse hex bitmask using math/big for full 64-bit support
	capInt := new(big.Int)
	capInt.SetString(capHex, 16)

	var caps []string
	for bit := 0; bit <= 40; bit++ {
		if capInt.Bit(bit) == 1 {
			if name, ok := capNames[bit]; ok {
				caps = append(caps, name)
			} else {
				caps = append(caps, fmt.Sprintf("CAP_%d", bit))
			}
		}
	}
	return caps
}

// collectMounts parses /proc/self/mountinfo for mount details.
func collectMounts() []mountInfo {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return nil
	}
	defer f.Close()

	var mounts []mountInfo
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		// mountinfo format: id parent major:minor root mount-point options ... - fstype source super-options
		parts := strings.Fields(line)
		if len(parts) < 5 {
			continue
		}
		mountPoint := parts[4]
		mode := parts[5] // mount options like "rw,relatime"

		// Find the separator "-"
		sepIdx := -1
		for i, p := range parts {
			if p == "-" {
				sepIdx = i
				break
			}
		}
		if sepIdx < 0 || sepIdx+2 >= len(parts) {
			continue
		}
		source := parts[sepIdx+2]

		// Skip virtual/system filesystems for readability
		fsType := parts[sepIdx+1]
		if isVirtualFS(fsType) {
			continue
		}

		// Extract rw/ro from mount options
		modeShort := "rw"
		if strings.HasPrefix(mode, "ro") {
			modeShort = "ro"
		}

		mounts = append(mounts, mountInfo{
			HostPath:      source,
			ContainerPath: mountPoint,
			Mode:          modeShort,
		})
	}
	return mounts
}

// isVirtualFS returns true for pseudo/virtual filesystem types we skip in mount listing.
func isVirtualFS(fsType string) bool {
	switch fsType {
	case "proc", "sysfs", "tmpfs", "devpts", "cgroup", "cgroup2",
		"mqueue", "debugfs", "tracefs", "securityfs", "pstore",
		"bpf", "autofs", "hugetlbfs", "fusectl", "configfs",
		"devtmpfs", "ramfs", "binfmt_misc":
		return true
	}
	return false
}

// collectFilteredEnv reads the current process environment and filters to safe keys.
func collectFilteredEnv() []envVar {
	var result []envVar
	for _, e := range os.Environ() {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) != 2 {
			continue
		}
		if isEnvSafe(parts[0]) {
			result = append(result, envVar{Key: parts[0], Value: parts[1]})
		}
	}
	return result
}

// detectCgroupDriver returns "cgroupv2" or "cgroupv1" based on filesystem presence.
func detectCgroupDriver() string {
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err == nil {
		return "cgroupv2"
	}
	if _, err := os.Stat("/sys/fs/cgroup/memory/memory.usage_in_bytes"); err == nil {
		return "cgroupv1"
	}
	return "unknown"
}
