// Stable reason codes from pkg/evidence/store.go and pkg/dp/learn/binding.go.
export const withheldReasons: Record<string, string> = {
  incomplete_parent: "Incomplete transaction. Capture the full request and response, then import again.",
  malformed: "Malformed protocol data. Check the device traffic and capture integrity before collecting again.",
  undecoded: "Traffic could not be decoded. Check protocol support and collect a complete capture.",
  missing_authority: "Client/server roles are uncertain. Capture connection setup and both directions.",
  missing_selector: "Required rule selectors are missing. Collect complete supported operations or author a narrowly scoped rule manually.",
  nonstandard_port: "Nonstandard service port; observation only. Verify the service and author a scoped rule manually.",
  cip_observation_only: "CIP is observation only. Review the observations and author policy manually.",
  modbus_fc23_roles: "Modbus read/write roles cannot be expressed exactly. Review both address ranges and author policy manually.",
  modbus_write_values_or_masks: "Modbus write values or masks cannot be constrained exactly. Review the operation and author policy manually.",
  modbus_unbound_subtype: "Modbus subtype is not bound to a supported selector. Review the subtype and author policy manually.",
  dnp3_all_objects: "DNP3 all-objects request is too broad to represent exactly. Review object scope and author policy manually.",
  dnp3_count_only: "DNP3 count-only objects lack exact address scope. Review object addresses and author policy manually.",
  dnp3_variation_wildcard: "DNP3 wildcard variation cannot be expressed exactly. Review the required variation and author policy manually.",
  dnp3_indexless_control: "DNP3 control has no exact point index. Verify point scope and author policy manually.",
  dnp3_values: "DNP3 values cannot be constrained exactly. Review command values and author policy manually.",
  unrepresentable_correlation: "Related selectors cannot be expressed without broadening scope. Review the relation and author policy manually.",
  iec104_qualifier: "IEC 104 qualifier cannot be expressed exactly. Review the qualifier and author policy manually.",
  iec104_value: "IEC 104 command value cannot be expressed exactly. Review the command value and author policy manually.",
  iec104_sbo_sequence: "IEC 104 select-before-operate sequence cannot be certified. Review the sequence and author policy manually.",
  iec104_non_command: "IEC 104 traffic is not a supported command. Collect supported commands or review monitoring policy manually.",
  iec104_broadcast_ca: "IEC 104 broadcast station address cannot be scoped safely. Verify intended stations and author policy manually.",
  unsupported_operation: "Operation is not supported for rule generation. Review the operation and author policy manually.",
  unsupported_coordinates: "Captured addresses cannot be mapped safely to policy. Verify deployment and NAT addressing before authoring policy manually.",
  budget_exceeded: "Evidence capacity was exceeded. Collect a smaller, focused dataset.",
  evidence_expired: "Evidence expired. Collect fresh evidence and generate again.",
  replay_failed: "Saved-evidence checks failed. Inspect failures and collect corrected evidence; do not stage this suggestion.",
  collection_loss: "Collection loss may hide operations. Resolve capture drops and collect complete evidence again.",
  observation_binding: "Observations disagree about this connection. Check capture scope, roles and NAT mapping, then collect again.",
};

export function withheldReason(code: string): string {
  return Object.hasOwn(withheldReasons, code)
    ? withheldReasons[code]
    : `Unrecognized reason (${code})`;
}
