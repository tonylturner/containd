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
  const ics: ICSPredicate = {
    protocol,
    functionCode: functionCodes
      .split(",")
      .map((v) => Number(v.trim()))
      .filter((n) => Number.isFinite(n) && n >= 0)
      .map((n) => Math.min(255, n)),
    addresses: addresses
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean),
    readOnly,
    writeOnly,
    ...(mode ? { mode } : {}),
  };

  if (protocol === "modbus" && unitId.trim()) {
    const uid = Number(unitId.trim());
    if (Number.isFinite(uid) && uid >= 0 && uid <= 255) ics.unitId = uid;
  }

  if (protocol === "cip" && objectClasses.trim()) {
    ics.objectClasses = objectClasses
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean)
      .map((s) => parseInt(s, s.startsWith("0x") ? 16 : 10))
      .filter((n) => Number.isFinite(n) && n >= 0);
  }

  if (ics.functionCode?.length === 0) delete ics.functionCode;
  // PATCH merges omitted fields. Explicitly empty a removed stored filter.
  if (ics.addresses?.length === 0 && !existing?.addresses?.length) delete ics.addresses;
  if ((ics.objectClasses?.length ?? 0) === 0) delete ics.objectClasses;

  return ics;
}
