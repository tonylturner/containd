export type ICSProtoMeta = {
  label: string;
  port: string;
  fcLabel: string;
  fcPlaceholder: string;
  fcHelp: string;
  addrLabel?: string;
  addrPlaceholder?: string;
  addrHelp?: string;
  showUnitId?: boolean;
  showObjectClasses?: boolean;
  notes?: string;
};

export const ICS_PROTOCOLS: Record<string, ICSProtoMeta> = {
  modbus: {
    label: "Modbus/TCP",
    port: "502",
    fcLabel: "Function codes",
    fcPlaceholder: "3, 16",
    fcHelp:
      "1=Read Coils, 2=Read Discrete Inputs, 3=Read Holding Registers, 4=Read Input Registers, 5=Write Single Coil, 6=Write Single Register, 8=Diagnostics, 15=Write Multiple Coils, 16=Write Multiple Registers, 43=Encapsulated Interface Transport (MEI)",
    addrLabel: "Register / coil addresses",
    addrPlaceholder: "0-100, 40001-40100",
    addrHelp:
      "Comma-separated ranges. Supports decimal (0-100) or hex (0x0000-0x00FF). Modbus registers are 16-bit (0-65535).",
    showUnitId: true,
    notes:
      "Unit ID identifies the slave device on a serial-to-TCP gateway (0-255, 0=broadcast).",
  },
  dnp3: {
    label: "DNP3",
    port: "20000",
    fcLabel: "Function codes",
    fcPlaceholder: "1, 2, 129",
    fcHelp:
      "1=Read, 2=Write, 3=Select, 4=Operate, 5=Direct Operate, 6=Direct Operate No Ack, 13=Cold Restart, 14=Warm Restart, 129=Response, 130=Unsolicited Response",
    notes:
      "DNP3 uses source/destination station addresses (0-65534) to identify master and outstation. IIN (Internal Indications) flags are inspected for anomaly detection.",
  },
  iec104: {
    label: "IEC 60870-5-104",
    port: "2404",
    fcLabel: "Type IDs and classes",
    fcPlaceholder: "46, 100",
    fcHelp:
      "Decoded Type IDs: 1, 3, 13, 30, 31 (monitor); 45-51 and 58-64 (commands and setpoints); 70, 100-103, 105, 107 (system: end of init, general interrogation, counter interrogation, read, clock sync, reset process, test). Classes group them as monitor, control, system or unknown.",
    addrLabel: "CA and IOA",
    addrPlaceholder: "",
    addrHelp:
      "Common address (CA) identifies the station, 0-65534; 65535 is broadcast and never matches an allow rule. Information object addresses (IOA) are closed ranges, 0-16777215.",
    notes:
      "Rules match the session tuple (client to port 2404) in both directions. Inside an enforce envelope, a denied, malformed or unsupported APDU drops the packet and resets the session; unmatched traffic is denied.",
  },
  cip: {
    label: "CIP / EtherNet/IP",
    port: "44818",
    fcLabel: "CIP service codes",
    fcPlaceholder: "0x4C, 0x4D, 0x52",
    fcHelp:
      "0x01=Get Attributes All, 0x02=Set Attributes All, 0x0E=Get Attribute Single, 0x10=Set Attribute Single, 0x4C=Read Tag, 0x4D=Write Tag, 0x4E=Read Modify Write, 0x52=Multiple Service Packet, 0x4F=Read Tag Fragmented, 0x53=Write Tag Fragmented",
    showObjectClasses: true,
    notes:
      "CIP uses an object model: Object Class identifies the type (0x01=Identity, 0x02=Message Router, 0x04=Assembly, 0x66=Connection Manager). Multiple Service Packet (0x52) requests are unpacked into individual services for inspection.",
  },
};

export const ICS_PROTOCOL_KEYS = Object.keys(ICS_PROTOCOLS);

export function icsProtoMeta(name: string): ICSProtoMeta {
  return Object.prototype.hasOwnProperty.call(ICS_PROTOCOLS, name)
    ? ICS_PROTOCOLS[name]
    : {
        label: name,
        port: "",
        fcLabel: "Function codes",
        fcPlaceholder: "",
        fcHelp: "",
      };
}

export const IT_PROTOCOLS: {
  key: string;
  label: string;
  port: string;
  desc: string;
}[] = [
  { key: "dns", label: "DNS", port: "53", desc: "Domain name queries and responses" },
  { key: "tls", label: "TLS / SSL", port: "443", desc: "TLS handshake metadata, SNI, JA3 fingerprinting" },
  { key: "http", label: "HTTP", port: "80", desc: "HTTP method, URI, host, status inspection" },
  { key: "ssh", label: "SSH", port: "22", desc: "SSH version exchange and cipher negotiation" },
  { key: "smb", label: "SMB", port: "445", desc: "Windows file sharing commands and shares" },
  { key: "ntp", label: "NTP", port: "123", desc: "Network time protocol mode and stratum" },
  { key: "snmp", label: "SNMP", port: "161", desc: "SNMP community auth, PDU type, OIDs" },
  { key: "rdp", label: "RDP", port: "3389", desc: "Remote desktop protocol negotiation and security" },
];

export const ICS_DPI_PROTOCOLS: {
  key: string;
  label: string;
  port: string;
  desc: string;
}[] = [
  { key: "modbus", label: "Modbus/TCP", port: "502", desc: "Function codes, register addresses, unit IDs" },
  { key: "dnp3", label: "DNP3", port: "20000", desc: "Function codes, station addresses, IIN flags" },
  { key: "iec104", label: "IEC 60870-5-104", port: "2404", desc: "APCI frames, Type IDs, common addresses, IOAs" },
  { key: "cip", label: "CIP / EtherNet/IP", port: "44818", desc: "Service codes, object classes, CIP paths" },
];

/**
 * Effective decoder state per ICS protocol. The engine enables a decoder
 * that is not configured; only an explicit `false` disables it
 * (pkg/dp/engine/decoders.go). Unknown keys are retained so the API can
 * report invalid saved configuration and the operator can explicitly remove it.
 */
export function effectiveICSDecoders(
  configured: Record<string, boolean> | undefined,
): Record<string, boolean> {
  const out: Record<string, boolean> = { ...(configured ?? {}) };
  for (const p of ICS_DPI_PROTOCOLS) out[p.key] = configured?.[p.key] !== false;
  return out;
}

export const ICS_PROTOCOL_OPTIONS: Record<
  string,
  {
    fcLabel: string;
    fcHelp: string;
    addrLabel?: string;
    addrHelp?: string;
    hasUnitId?: boolean;
    hasObjectClasses?: boolean;
  }
> = {
  modbus: {
    fcLabel: "Function codes",
    fcHelp:
      "1=Read Coils, 3=Read Holding, 5=Write Coil, 6=Write Register, 15=Write Coils, 16=Write Registers",
    addrLabel: "Register/coil addresses",
    addrHelp: "e.g. 0-100, 40001-40100",
    hasUnitId: true,
  },
  dnp3: {
    fcLabel: "Function codes",
    fcHelp:
      "1=Read, 2=Write, 3=Select, 4=Operate, 13=Cold Restart, 14=Warm Restart",
  },
  iec104: {
    fcLabel: "Type IDs and classes",
    fcHelp: "3/13/31 monitor, 45-51/58-64 control, 100 interrogation, 102 read",
    addrLabel: "CA and IOA",
    addrHelp: "Common address 0-65534, IOA ranges 0-16777215",
  },
  cip: {
    fcLabel: "Service codes",
    fcHelp: "0x4C=Read Tag, 0x4D=Write Tag, 0x52=Multiple Service",
    hasObjectClasses: true,
  },
};
