// SPDX-License-Identifier: Apache-2.0

package evidence

// Span is a closed address interval. Role preserves FC23 read/write distinction
// even though today's predicates cannot express it. No gap filling is allowed.
type Span struct {
	First uint32 `json:"first"`
	Last  uint32 `json:"last"`
	Role  string `json:"role"` // read|write|target
}

// Modbus preserves a whole PDU's operation, subtype and span relation. Values
// and masks remain evidence even when their required constraints are withheld.
type Modbus struct {
	UnitID       *uint8   `json:"unitId,omitempty"`
	FunctionCode *uint8   `json:"functionCode,omitempty"`
	Subfunction  *uint16  `json:"subfunction,omitempty"`
	MEIType      *uint8   `json:"meiType,omitempty"`
	Spans        []Span   `json:"spans"`
	Values       []uint16 `json:"values"`
	AndMask      *uint16  `json:"andMask,omitempty"`
	OrMask       *uint16  `json:"orMask,omitempty"`
}

// DNP3 keeps station roles and ordered object headers together, never a product
// of independent group/variation/index lists or points borrowed from a reply.
type DNP3 struct {
	Master       *uint16      `json:"master,omitempty"`
	Outstation   *uint16      `json:"outstation,omitempty"`
	FunctionCode *uint8       `json:"functionCode,omitempty"`
	Objects      []DNP3Object `json:"objects"`
}

// DNP3Object is an ordered parent header with its own qualifier and targets.
// DataDigest retains unsupported command/value evidence without raw payloads.
type DNP3Object struct {
	Index      uint32  `json:"index"`
	Group      *uint8  `json:"group,omitempty"`
	Variation  *uint8  `json:"variation,omitempty"`
	Qualifier  *uint8  `json:"qualifier,omitempty"`
	AllObjects bool    `json:"allObjects"`
	Count      *uint32 `json:"count,omitempty"`
	Spans      []Span  `json:"spans"`
	DataDigest string  `json:"dataDigest,omitempty"`
}

// IEC104 retains one complete APDU/ASDU; APCI/system/monitoring observations
// remain evidence but do not generate command permission or startup templates.
type IEC104 struct {
	APCIType   string         `json:"apciType"`
	TypeID     *uint8         `json:"typeId,omitempty"`
	CA         *uint16        `json:"ca,omitempty"`
	COT        *uint8         `json:"cot,omitempty"`
	Originator *uint8         `json:"originator,omitempty"`
	Negative   *bool          `json:"negative,omitempty"`
	Test       *bool          `json:"test,omitempty"`
	Objects    []IEC104Object `json:"objects"`
}

// IEC104Object preserves wire presence of select/execute, qualifiers and values.
// ValueDigest binds canonical decoded value bytes, not a lossy float rendering.
type IEC104Object struct {
	Index       uint32  `json:"index"`
	IOA         *uint32 `json:"ioa,omitempty"`
	Select      *bool   `json:"select,omitempty"`
	Qualifier   *uint8  `json:"qualifier,omitempty"`
	ValueDigest string  `json:"valueDigest,omitempty"`
}

// CIP is observation-only. Absence of a class is never fabricated as class zero.
type CIP struct {
	Service      *uint8  `json:"service,omitempty"`
	Class        *uint16 `json:"class,omitempty"`
	Instance     *uint16 `json:"instance,omitempty"`
	Attribute    *uint16 `json:"attribute,omitempty"`
	Symbol       string  `json:"symbol,omitempty"`
	TargetDigest string  `json:"targetDigest,omitempty"`
}
