// SPDX-License-Identifier: Apache-2.0
package services

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"

	"github.com/tonylturner/containd/pkg/cp/config"
)

const maxOpenVPNProfile = 1 << 20

// OpenVPNProfile is a bounded client profile. Its private representation can
// only be constructed by ParseOpenVPNProfile; callers cannot add directives.
type OpenVPNProfile struct {
	lines    []string
	material map[string]string
}

// ParseOpenVPNProfile is the sole import/runtime grammar. File-bearing options
// are not accepted: certificates and TLS keys must be inline. Interactive
// authentication, scripts, includes, plugins and management are unsupported.
// Supported options and arities are enumerated below, not delegated to OpenVPN.
func ParseOpenVPNProfile(data []byte) (*OpenVPNProfile, error) {
	if len(data) > maxOpenVPNProfile || bytes.ContainsAny(data, "\x00\r\\") {
		return nil, fmt.Errorf("invalid OpenVPN profile encoding or size")
	}
	p := &OpenVPNProfile{material: make(map[string]string)}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), maxOpenVPNProfile)
	block := ""
	var payload strings.Builder
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if block != "" {
			if line == "</"+block+">" {
				if payload.Len() == 0 {
					return nil, fmt.Errorf("empty inline material")
				}
				p.material[block] = payload.String()
				block = ""
				payload.Reset()
				continue
			}
			if strings.ContainsAny(line, "<>") {
				return nil, fmt.Errorf("inline material breakout")
			}
			payload.WriteString(line + "\n")
			continue
		}
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "<") {
			name := strings.TrimSuffix(strings.TrimPrefix(line, "<"), ">")
			switch name {
			case "ca", "cert", "key", "tls-auth", "tls-crypt":
			default:
				return nil, fmt.Errorf("unsupported inline block")
			}
			if line != "<"+name+">" || p.material[name] != "" {
				return nil, fmt.Errorf("invalid or duplicate inline block")
			}
			block = name
			continue
		}
		fields := strings.Fields(line)
		if err := validateOpenVPNProfileOption(fields); err != nil {
			return nil, err
		}
		p.lines = append(p.lines, strings.Join(fields, " "))
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if block != "" {
		return nil, fmt.Errorf("unterminated inline block")
	}
	if p.material["tls-auth"] != "" && p.material["tls-crypt"] != "" {
		return nil, fmt.Errorf("conflicting TLS keys")
	}
	return p, nil
}

func validateOpenVPNProfileOption(f []string) error {
	n := len(f) - 1
	arity := map[string][2]int{
		"client": {0, 0}, "nobind": {0, 0}, "persist-key": {0, 0}, "persist-tun": {0, 0}, "auth-nocache": {0, 0},
		"remote": {1, 3}, "proto": {1, 1}, "dev": {1, 1}, "resolv-retry": {1, 1}, "remote-cert-tls": {1, 1},
		"cipher": {1, 1}, "data-ciphers": {1, 1}, "data-ciphers-fallback": {1, 1}, "auth": {1, 1},
		"verb": {1, 1}, "mute": {1, 1}, "connect-retry": {1, 2}, "connect-timeout": {1, 1},
		"ping": {1, 1}, "ping-restart": {1, 1}, "key-direction": {1, 1}, "tls-version-min": {1, 1},
		"route-nopull": {0, 0}, "remote-random": {0, 0}, "explicit-exit-notify": {0, 1},
	}
	bounds, ok := arity[f[0]]
	if !ok || n < bounds[0] || n > bounds[1] {
		return fmt.Errorf("unsupported OpenVPN option or arity")
	}
	for _, v := range f[1:] {
		if strings.HasPrefix(v, "-") {
			return fmt.Errorf("invalid OpenVPN argument")
		}
		for _, r := range v {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._:-", r)) || unicode.IsControl(r) {
				return fmt.Errorf("invalid OpenVPN argument")
			}
		}
	}
	switch f[0] {
	case "remote":
		if err := config.ValidateOpenVPNRemote(f[1]); err != nil {
			return err
		}
		if n >= 2 {
			port, err := strconv.Atoi(f[2])
			if err != nil || port < 1 || port > 65535 {
				return fmt.Errorf("invalid remote port")
			}
		}
		if n == 3 && f[3] != "udp" && f[3] != "tcp" && f[3] != "tcp-client" {
			return fmt.Errorf("invalid remote protocol")
		}
	case "dev":
		if f[1] != "tun" {
			return fmt.Errorf("only tun devices are supported")
		}
	case "proto":
		if f[1] != "udp" && f[1] != "udp4" && f[1] != "udp6" && f[1] != "tcp-client" && f[1] != "tcp" {
			return fmt.Errorf("unsupported protocol")
		}
	case "remote-cert-tls":
		if f[1] != "server" {
			return fmt.Errorf("only server verification supported")
		}
	case "key-direction":
		if f[1] != "0" && f[1] != "1" {
			return fmt.Errorf("invalid key direction")
		}
	}
	return nil
}

func readOpenVPNProfile(path string) (*OpenVPNProfile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("profile must be a regular file")
	}
	b, err := io.ReadAll(io.LimitReader(f, maxOpenVPNProfile+1))
	if err != nil {
		return nil, err
	}
	return ParseOpenVPNProfile(b)
}

func (p *OpenVPNProfile) render(dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	var b strings.Builder
	for _, line := range p.lines {
		b.WriteString(line + "\n")
	}
	for _, name := range []string{"ca", "cert", "key", "tls-auth", "tls-crypt"} {
		if value := p.material[name]; value != "" {
			if err := atomicWriteFile(filepath.Join(dir, name+".pem"), []byte(value), 0o600); err != nil {
				return "", err
			}
			b.WriteString(name + " " + name + ".pem\n")
		}
	}
	path := filepath.Join(dir, "openvpn.conf")
	return path, atomicWriteFile(path, []byte(b.String()), 0o600)
}

func (m *VPNManager) renderOpenVPNProfile(p *OpenVPNProfile) (string, error) {
	if m.BaseDir == "" {
		return "", fmt.Errorf("VPN services directory is unset")
	}
	dir, err := filepath.Abs(filepath.Join(m.BaseDir, "openvpn-import"))
	if err != nil {
		return "", err
	}
	return p.render(dir)
}
