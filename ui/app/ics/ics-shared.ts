import type { ICSPredicate, ICSPredicatePatch } from "../../lib/api";

export type ICSMode = "enforce" | "learn";
export type ICSModeSelection = ICSMode | "";

export const UNSUPPORTED_ADDRESSES =
  "Address filters are not supported for CIP. Remove this filter before saving; use object classes, instances, attributes or tags.";

export function addressFilterError(protocol: string, addresses: string): string | null {
  return protocol === "cip" && addresses.trim()
    ? UNSUPPORTED_ADDRESSES
    : null;
}

export function icsAddressDraftFrom(ics: ICSPredicate | undefined): string {
  const values = ics?.addresses ?? [];
  const text = values.join(", ");
  // Even [""] is a nonempty, invalid stored predicate. Do not hide it.
  return values.length && !text.trim() && (ics?.protocol === "dnp3" || ics?.protocol === "cip")
    ? JSON.stringify(values)
    : text;
}

function normalizeMode(mode: string | undefined): ICSMode | "" | "other" {
  const m = (mode ?? "").trim().toLowerCase();
  if (m === "" || m === "enforce" || m === "learn") return m;
  return "other";
}

/**
 * Resolves the effective mode as the engine does: the rule mode, then the
 * global DPI mode, then learn; anything but "enforce" never enforces.
 */
export function formatICSMode(
  ruleMode: string | undefined,
  globalMode: string | undefined,
): { label: string; effectiveMode: ICSMode; inherited: boolean } {
  const rule = normalizeMode(ruleMode);
  const inherited = rule === "";
  const resolved = inherited ? normalizeMode(globalMode) : rule;
  const effectiveMode: ICSMode = resolved === "enforce" ? "enforce" : "learn";
  const effectiveLabel = effectiveMode === "learn" ? "learning" : "enforce";
  return {
    label: inherited ? `inherit (${effectiveLabel})` : effectiveLabel,
    effectiveMode,
    inherited,
  };
}

export type ProtocolMeta = {
  label: string;
  port: string;
  fcLabel: string;
  fcPlaceholder: string;
  fcHelp: string;
  addrLabel?: string;
  addrPlaceholder?: string;
  addrHelp?: string;
};

export const PROTOCOLS: Record<string, ProtocolMeta> = {
  modbus: {
    label: "Modbus/TCP",
    port: "502",
    fcLabel: "Function codes",
    fcPlaceholder: "3, 16",
    fcHelp:
      "Modbus function codes (e.g., 1=Read Coils, 3=Read Holding, 5=Write Coil, 6=Write Register, 15=Write Coils, 16=Write Registers).",
    addrLabel: "Register / coil addresses",
    addrPlaceholder: "0x0000-0x00FF, 40001",
    addrHelp:
      "Comma-separated register or coil ranges. Supports decimal (100-200) and hex (0x0064-0x00C8).",
  },
  dnp3: {
    label: "DNP3",
    port: "20000",
    fcLabel: "Function codes",
    fcPlaceholder: "1, 2, 3",
    addrLabel: "Point indexes",
    addrPlaceholder: "0-10, 100",
    addrHelp: "Closed point-index ranges, 0-4294967295. Requires object groups. Unknown indexes fail ALLOW and match DENY.",
    fcHelp:
      "DNP3 application function codes (1=Read, 2=Write, 3=Select, 4=Operate, 5=Direct Operate, 13=Cold Restart, 14=Warm Restart).",
  },
  iec104: {
    label: "IEC 60870-5-104",
    port: "2404",
    fcLabel: "Type IDs / classes",
    fcPlaceholder: "",
    fcHelp:
      "ASDU Type IDs (1=single point, 3=double point, 13=float measurement, 30=single point with time, 31=double point with time, 45-51/58-64=commands and setpoints, 100=general interrogation, 102=read) and classes (monitor, control, system, unknown).",
    addrLabel: "CA / IOA",
    addrPlaceholder: "",
    addrHelp:
      "Common address (station, 0-65534) and information object address ranges (0-16777215).",
  },
  cip: {
    label: "CIP / EtherNet/IP",
    port: "44818",
    fcLabel: "Service codes",
    fcPlaceholder: "76, 77",
    fcHelp:
      "Common CIP codes: 0x0A=Multiple_Service_Packet, 0x0D=Apply_Attributes, 0x0E=Get_Attribute_Single, 0x10=Set_Attribute_Single, 0x18=Get_Member, 0x19=Set_Member. Object-specific codes depend on class: 0x4C/76 is Read_Tag for Logix tags; 0x52 is Logix Read_Tag_Fragmented or class 0x06 Unconnected_Send.",
  },
};

export const PROTOCOL_KEYS = Object.keys(PROTOCOLS);

export function protoMeta(name: string): ProtocolMeta {
  return Object.prototype.hasOwnProperty.call(PROTOCOLS, name)
    ? PROTOCOLS[name]
    : {
        label: name,
        port: "",
        fcLabel: "Function codes",
        fcPlaceholder: "",
        fcHelp: "Protocol-specific function or service codes.",
      };
}

export function isSupportedICSProtocol(name: string): boolean {
  return Object.prototype.hasOwnProperty.call(PROTOCOLS, name);
}

/** Empty CSV tokens are separators, never numeric zero. Hex is explicit. */
export function parseSelectorCSV(text: string, label: string, max: number): number[] {
  return text.split(",").map((v) => v.trim()).filter(Boolean).map((token) => {
    const value = Number(token);
    if (!/^(?:[0-9]+|0x[0-9a-f]+)$/i.test(token) || !Number.isInteger(value) || value > max) {
      throw new Error(`${label}: "${token}" must be an integer from 0 to ${max}.`);
    }
    return value;
  });
}

function parseUnitID(text: string): number | undefined {
  if (!text.trim()) return undefined;
  if (text.includes(",")) throw new Error("Unit ID: enter one integer from 0 to 255.");
  return parseSelectorCSV(text, "Unit ID", 255)[0];
}

export function selectorFieldError(protocol: string, codes: string, unit: string, classes: string): string | null {
  if (protocol === "iec104") return null;
  try {
    parseSelectorCSV(codes, "Function / service codes", 255);
    if (protocol === "modbus") parseUnitID(unit);
    if (protocol === "cip") parseSelectorCSV(classes, "Object classes", 65535);
    return null;
  } catch (error) {
    return (error as Error).message;
  }
}

export const GENERIC_SELECTOR_FIELDS = ["masters", "outstations", "groups", "variations", "instances", "attributes", "tags"] as const;
export type GenericSelectorDraft = Record<typeof GENERIC_SELECTOR_FIELDS[number], string> & {
  direction: "" | "request" | "response";
};

export function genericSelectorDraftFrom(ics?: ICSPredicate): GenericSelectorDraft {
  return {
    masters: (ics?.masters ?? []).join(", "), outstations: (ics?.outstations ?? []).join(", "),
    groups: (ics?.groups ?? []).join(", "), variations: (ics?.variations ?? []).join(", "),
    instances: (ics?.instances ?? []).join(", "), attributes: (ics?.attributes ?? []).join(", "),
    tags: (ics?.tags ?? []).join(", "), direction: ics?.direction ?? "",
  };
}

export const UNSUPPORTED_UNIT_ID = "unitId is not supported for DNP3 or CIP: these decoders emit no unit ID. Remove this filter before saving.";

/** PATCH is the validated effective predicate plus explicit removals. */
export function predicatePatch(effective: ICSPredicate, existing?: ICSPredicate): ICSPredicatePatch {
  const patch: ICSPredicatePatch = { ...effective };
  if (existing && existing.protocol === effective.protocol) {
    for (const key of Object.keys(existing) as (keyof ICSPredicate)[]) {
      if (existing[key] !== undefined && effective[key] === undefined) Object.assign(patch, { [key]: null });
    }
  }
  return patch;
}

/** Never send merge-patch nulls to create/replace/preview endpoints. */
export function effectivePredicate(patch?: ICSPredicatePatch | null): ICSPredicate | undefined {
  return patch == null ? undefined : Object.fromEntries(Object.entries(patch).filter(([, v]) => v != null)) as ICSPredicate;
}

function parseAddresses(protocol: string, text: string): string[] {
  const entries = text.split(",").map((v) => v.trim()).filter(Boolean);
  const error = addressFilterError(protocol, text);
  if (error) throw new Error(error);
  const max = protocol === "dnp3" ? 4294967295 : 65535;
  for (const entry of entries) {
    const parts = entry.split("-").map((v) => v.trim());
    if (parts.length > 2 || parts.some((v) => !v)) throw new Error(`Invalid address range: ${entry}`);
    const values = parts.map((v) => parseSelectorCSV(v, "Address", max)[0]);
    if (values[0] > values[values.length - 1]) throw new Error(`Address range starts after it ends: ${entry}`);
  }
  return entries;
}

export function buildICSRuleUpdate(
  protocol: string,
  functionCodes: string,
  addresses: string,
  unitId: string,
  objectClasses: string,
  readOnly: boolean,
  writeOnly: boolean,
  mode: ICSModeSelection,
  existing?: ICSPredicate,
  selectors = genericSelectorDraftFrom(existing),
): ICSPredicatePatch {
  if (!isSupportedICSProtocol(protocol)) throw new Error(`Unsupported ICS protocol: ${protocol}`);
  if (protocol !== "modbus" && unitId.trim()) throw new Error(UNSUPPORTED_UNIT_ID);
  if (readOnly && writeOnly) throw new Error("Read-only and write-only are mutually exclusive.");
  const ics: ICSPredicate = { protocol, readOnly, writeOnly };
  const codes = parseSelectorCSV(functionCodes, "Function / service codes", 255);
  if (codes.length) ics.functionCode = codes;
  const addressList = parseAddresses(protocol, addresses);
  if (addressList.length) ics.addresses = addressList;
  if (selectors.direction) ics.direction = selectors.direction;
  if (mode) ics.mode = mode;
  if (protocol === "modbus") {
    const uid = parseUnitID(unitId);
    if (uid != null) ics.unitId = uid;
  }
  if (protocol === "dnp3") {
    for (const key of ["masters", "outstations", "groups", "variations"] as const) {
      const values = parseSelectorCSV(selectors[key], key, key === "masters" || key === "outstations" ? 65519 : 255);
      if (values.length) ics[key] = values;
    }
    if (addressList.length && !ics.groups?.length) throw new Error("DNP3 point indexes require non-empty groups.");
  }
  if (protocol === "cip") {
    for (const [key, text] of [["objectClasses", objectClasses], ["instances", selectors.instances], ["attributes", selectors.attributes]] as const) {
      const values = parseSelectorCSV(text, key, 65535);
      if (values.length) ics[key] = values;
    }
    const tags = selectors.tags.split(",").map((v) => v.trim()).filter(Boolean);
    if (tags.length) {
      if (ics.objectClasses || ics.instances || ics.attributes) throw new Error("Tags cannot combine with objectClasses, instances or attributes.");
      for (const tag of tags) {
        if (!tag.split(".").every((segment, i) => {
          const name = i === 0 && segment.startsWith("Program:") ? segment.slice(8) : segment;
          return /^[A-Za-z_][A-Za-z0-9_]*$/.test(name) && name.length <= 40;
        })) throw new Error(`Invalid tag: ${tag}. Use dot-separated names (up to 40 characters each), optional first Program:Name, no brackets.`);
      }
      ics.tags = tags;
    }
  }
  return predicatePatch(ics, existing);
}

/** Compact restrictions for review tables; never hide a constrained target. */
export function summarizeGenericICS(ics: ICSPredicate, includeCodes = true): string {
  const parts = includeCodes ? [`fc=${ics.functionCode?.join(", ") || "*"}`] : [];
  if (ics.unitId != null) parts.push(`unitId=${ics.unitId}`);
  for (const key of ["addresses", "objectClasses", ...GENERIC_SELECTOR_FIELDS] as const) {
    if (ics[key]?.length) parts.push(`${key}=${ics[key]?.join(", ")}`);
  }
  if (ics.direction) parts.push(ics.direction);
  if (ics.readOnly) parts.push("read-only");
  if (ics.writeOnly) parts.push("write-only");
  return parts.join(" · ");
}
