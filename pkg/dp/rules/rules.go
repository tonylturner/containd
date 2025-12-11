package rules

// Snapshot is an immutable rule set used by the data-plane fast path.
// It is intended to be hot-swapped atomically by the engine.
type Snapshot struct {
	Version   string  // compiled rule version
	Firewall  []Entry // firewall rules
	Default   Action
}

type Entry struct {
	ID           string
	SourceZones  []string
	DestZones    []string
	Sources      []string
	Destinations []string
	Protocols    []Protocol
	Action       Action
	// Future predicates
	Identities []string // user/group roles
	ICS        ICSPredicate
}

type Action string

const (
	ActionAllow Action = "ALLOW"
	ActionDeny  Action = "DENY"
)

type Protocol struct {
	Name string
	Port string // single or range
}

// ICSPredicate captures ICS-specific fields (placeholder).
type ICSPredicate struct {
	Protocol     string   // modbus, dnp3, etc.
	FunctionCode []uint8  // e.g., modbus function codes
	Addresses    []string // address/register ranges as strings
}
