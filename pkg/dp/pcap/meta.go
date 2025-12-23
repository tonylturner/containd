package pcap

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

type Meta struct {
	Name      string    `json:"name"`
	Interface string    `json:"interface"`
	CreatedAt time.Time `json:"createdAt"`
	Tags      []string  `json:"tags,omitempty"`
	Status    string    `json:"status,omitempty"`
}

func metaPath(pcapPath string) string {
	return pcapPath + ".json"
}

func readMeta(path string) (Meta, error) {
	var meta Meta
	b, err := os.ReadFile(path)
	if err != nil {
		return meta, err
	}
	if err := json.Unmarshal(b, &meta); err != nil {
		return meta, err
	}
	return meta, nil
}

func writeMeta(path string, meta Meta) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	raw, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o644)
}
