import type { ICSPredicate } from "../../lib/api";

export type ICSMode = "enforce" | "learn";
export type ICSModeSelection = ICSMode | "";

export const UNSUPPORTED_ADDRESSES =
  "Address filters are not supported for DNP3 or CIP. Remove this filter before saving; protocol-specific station, point and CIP path selectors are not available yet.";

export function addressFilterError(protocol: string, addresses: string): string | null {
  return (protocol === "dnp3" || protocol === "cip") && addresses.trim()
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
      "CIP service codes (0x0E=Get_Attribute, 0x10=Set_Attribute, 0x4C/76=Read_Tag, 0x4D/77=Write_Tag, 0x52=Unconnected_Send).",
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
): ICSPredicate {
  const codes = parseSelectorCSV(functionCodes, "Function / service codes", 255);
  const classes = protocol === "cip" ? parseSelectorCSV(objectClasses, "Object classes", 65535) : [];
  const sameProtocol = existing?.protocol === protocol ? existing : undefined;
  const addressList = addresses.split(",").map((s) => s.trim()).filter(Boolean);
  const ics: ICSPredicate = {
    protocol,
    readOnly,
    writeOnly,
    ...(sameProtocol?.direction ? { direction: sameProtocol.direction } : {}),
    ...(mode ? { mode } : {}),
  };
  // Omission retains a stored restriction on PATCH. Null clears it, and is
  // also accepted by create/preview, keeping those payloads identical.
  if (codes.length) ics.functionCode = codes;
  else if (sameProtocol?.functionCode?.length) ics.functionCode = null;
  if (addressList.length) ics.addresses = addressList;
  else if (sameProtocol?.addresses?.length) ics.addresses = null;
  if (protocol === "modbus") {
    const uid = parseUnitID(unitId);
    if (uid != null) ics.unitId = uid;
    else if (sameProtocol?.unitId != null) ics.unitId = null;
  } else if (sameProtocol?.unitId != null) {
    // The server accepts legacy unit selectors on other generic protocols;
    // a form without a unit input must not silently widen those predicates.
    ics.unitId = sameProtocol.unitId;
  }
  if (classes.length) ics.objectClasses = classes;
  else if (sameProtocol?.objectClasses?.length) ics.objectClasses = null;
  return ics;
}
