package conntrack

// Entry is a minimal, portable conntrack record representation.
// This is intentionally lossy; it's meant for operator visibility (show sessions/conntrack),
// not for full fidelity export.
type Entry struct {
	Proto       string `json:"proto"`
	State       string `json:"state,omitempty"`
	Src         string `json:"src,omitempty"`
	Dst         string `json:"dst,omitempty"`
	Sport       string `json:"sport,omitempty"`
	Dport       string `json:"dport,omitempty"`
	ReplySrc    string `json:"replySrc,omitempty"`
	ReplyDst    string `json:"replyDst,omitempty"`
	ReplySport  string `json:"replySport,omitempty"`
	ReplyDport  string `json:"replyDport,omitempty"`
	Mark        string `json:"mark,omitempty"`
	Assured     bool   `json:"assured,omitempty"`
	TimeoutSecs int    `json:"timeoutSecs,omitempty"`
	Raw         string `json:"raw,omitempty"`
}

// DeleteRequest identifies a flow to delete from conntrack (best-effort).
// This is intentionally minimal for operator-driven session termination.
type DeleteRequest struct {
	Proto string `json:"proto"`
	Src   string `json:"src"`
	Dst   string `json:"dst"`
	Sport int    `json:"sport,omitempty"`
	Dport int    `json:"dport,omitempty"`
}
