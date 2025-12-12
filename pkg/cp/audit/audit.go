package audit

import "time"

// Record captures an audit event for config mutations and sensitive actions.
type Record struct {
	ID        int64     `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Actor     string    `json:"actor"`  // user or system identifier
	Source    string    `json:"source"` // ui/api/ssh/cli
	Action    string    `json:"action"` // e.g., commit, import, set zone
	Target    string    `json:"target"` // resource identifier
	Result    string    `json:"result"` // success/failure
	Detail    string    `json:"detail"` // optional diff/description
}
