import type { ICSPredicate } from "../../lib/api";

export type ProtocolMeta = {
  label: string;
  port: string;
  fcLabel: string;
  fcPlaceholder: string;
  fcHelp: string;
  addrLabel: string;
  addrPlaceholder: string;
  addrHelp: string;
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
    addrLabel: "Station addresses",
    addrPlaceholder: "1-10",
    addrHelp:
      "DNP3 outstation destination addresses (decimal). Use ranges for address groups.",
  },
  cip: {
    label: "CIP / EtherNet/IP",
    port: "44818",
    fcLabel: "Service codes",
    fcPlaceholder: "76, 77",
    fcHelp:
      "CIP service codes (0x0E=Get_Attribute, 0x10=Set_Attribute, 0x4C/76=Read_Tag, 0x4D/77=Write_Tag, 0x52=Unconnected_Send).",
    addrLabel: "CIP path",
    addrPlaceholder: "",
    addrHelp: "Optional CIP class/instance path filter (hex string).",
  },
  s7comm: {
    label: "S7comm (Siemens)",
    port: "102",
    fcLabel: "Function codes",
    fcPlaceholder: "4, 5",
    fcHelp:
      "S7comm parameter function codes (4=Read Var, 5=Write Var, 0x1A=Download, 0x28=PLC Control, 0x29=PLC Stop).",
    addrLabel: "DB / address",
    addrPlaceholder: "",
    addrHelp: "Optional S7 data block or address filter.",
  },
  mms: {
    label: "IEC 61850 MMS",
    port: "102",
    fcLabel: "Service codes",
    fcPlaceholder: "",
    fcHelp:
      "MMS confirmed-request service tags (Read=0xA4, Write=0xA5, GetVariableAccessAttributes=0xA6).",
    addrLabel: "Named variable",
    addrPlaceholder: "",
    addrHelp: "Optional MMS named-variable filter.",
  },
  bacnet: {
    label: "BACnet/IP",
    port: "47808",
    fcLabel: "Service codes",
    fcPlaceholder: "12, 15",
    fcHelp:
      "BACnet service choice (12=ReadProperty, 14=ReadPropertyMultiple, 15=WriteProperty, 16=WritePropertyMultiple, 8=WhoIs).",
    addrLabel: "Object instance",
    addrPlaceholder: "",
    addrHelp: "Optional BACnet object instance filter.",
  },
  opcua: {
    label: "OPC UA",
    port: "4840",
    fcLabel: "Service IDs",
    fcPlaceholder: "",
    fcHelp:
      "OPC UA service node IDs (631=ReadRequest, 673=WriteRequest, 527=BrowseRequest).",
    addrLabel: "Node ID",
    addrPlaceholder: "",
    addrHelp: "Optional OPC UA node ID filter.",
  },
};

export const PROTOCOL_KEYS = Object.keys(PROTOCOLS);

export function protoMeta(name: string): ProtocolMeta {
  return (
    PROTOCOLS[name] ?? {
      label: name,
      port: "",
      fcLabel: "Function codes",
      fcPlaceholder: "",
      fcHelp: "Protocol-specific function or service codes.",
      addrLabel: "Addresses",
      addrPlaceholder: "",
      addrHelp: "Protocol-specific address filter.",
    }
  );
}

export function buildICSRulePreview(
  rule: { id: string },
  enabled: boolean,
  protocol: string,
  functionCodes: string,
  addresses: string,
  readOnly: boolean,
  writeOnly: boolean,
  mode: "enforce" | "learn",
): Record<string, unknown> {
  return {
    id: rule.id,
    ics: enabled
      ? {
          protocol,
          functionCode: functionCodes
            .split(",")
            .map((v) => Number(v.trim()))
            .filter((n) => Number.isFinite(n) && n >= 0),
          addresses: addresses
            .split(",")
            .map((s) => s.trim())
            .filter(Boolean),
          readOnly,
          writeOnly,
          mode,
        }
      : undefined,
  };
}

export function buildICSRuleUpdate(
  protocol: string,
  functionCodes: string,
  addresses: string,
  unitId: string,
  objectClasses: string,
  readOnly: boolean,
  writeOnly: boolean,
  mode: "enforce" | "learn",
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
    mode,
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
  if (ics.addresses?.length === 0) delete ics.addresses;
  if ((ics.objectClasses?.length ?? 0) === 0) delete ics.objectClasses;

  return ics;
}
