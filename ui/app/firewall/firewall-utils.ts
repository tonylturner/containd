import type { Interface, InterfaceState, Zone } from "../../lib/api";

export type ICSProtoMeta = {
  label: string;
  port: string;
  fcLabel: string;
  fcPlaceholder: string;
  fcHelp: string;
  addrLabel: string;
  addrPlaceholder: string;
  addrHelp: string;
  showUnitId?: boolean;
  showObjectClasses?: boolean;
  showStationAddrs?: boolean;
  showDbNumber?: boolean;
  showObjectType?: boolean;
  showPropertyId?: boolean;
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
    addrLabel: "Point indices",
    addrPlaceholder: "0-10",
    addrHelp:
      "DNP3 data point indices. Used to restrict which binary/analog points this rule matches.",
    showStationAddrs: true,
    notes:
      "DNP3 uses source/destination station addresses (0-65534) to identify master and outstation. IIN (Internal Indications) flags are inspected for anomaly detection.",
  },
  cip: {
    label: "CIP / EtherNet/IP",
    port: "44818",
    fcLabel: "CIP service codes",
    fcPlaceholder: "0x4C, 0x4D, 0x52",
    fcHelp:
      "0x01=Get Attributes All, 0x02=Set Attributes All, 0x0E=Get Attribute Single, 0x10=Set Attribute Single, 0x4C=Read Tag, 0x4D=Write Tag, 0x4E=Read Modify Write, 0x52=Multiple Service Packet, 0x4F=Read Tag Fragmented, 0x53=Write Tag Fragmented",
    addrLabel: "EPATH (class/instance)",
    addrPlaceholder: "0x02/1, 0x04/1",
    addrHelp:
      "CIP path segments as class/instance pairs. The EPATH defines the target object in the CIP object model.",
    showObjectClasses: true,
    notes:
      "CIP uses an object model: Object Class identifies the type (0x01=Identity, 0x02=Message Router, 0x04=Assembly, 0x66=Connection Manager). Multiple Service Packet (0x52) requests are unpacked into individual services for inspection.",
  },
  s7comm: {
    label: "S7comm (Siemens)",
    port: "102",
    fcLabel: "Function codes",
    fcPlaceholder: "4, 5",
    fcHelp:
      "0x04=Read Variable, 0x05=Write Variable, 0x1D=Request Download, 0x1E=Download Block, 0x1F=Download Ended, 0x28=PI Service (PLC Control), 0x29=PLC Stop",
    addrLabel: "Variable addresses",
    addrPlaceholder: "DB1.DBX0.0, MW100",
    addrHelp:
      "S7 addressing: DBx.DBXy.z (data blocks), Mx (merkers), Ix (inputs), Qx (outputs). DB number identifies the data block.",
    showDbNumber: true,
    notes:
      "S7comm shares TCP port 102 with IEC 61850 MMS (differentiated by COTP protocol ID). Memory areas: 0x81=Inputs, 0x82=Outputs, 0x83=Merkers, 0x84=Data Blocks, 0x1C=Counters, 0x1D=Timers.",
  },
  mms: {
    label: "IEC 61850 MMS",
    port: "102",
    fcLabel: "MMS service types",
    fcPlaceholder: "",
    fcHelp:
      "MMS services: Read (confirmed), Write (confirmed), GetNameList, GetVariableAccessAttributes, DefineNamedVariableList, DeleteNamedVariableList, ObtainFile, Report, GOOSE-control. Service codes are ASN.1 context tags.",
    addrLabel: "Named variables",
    addrPlaceholder: "LLN0$BR$brcb01",
    addrHelp:
      "IEC 61850 variable names follow domain/item naming: LogicalDevice/LogicalNode$FC$DataObject (e.g., XCBR1$ST$Pos). FC = Functional Constraint (ST=Status, MX=Measured, CO=Control).",
    notes:
      "MMS is the application layer for IEC 61850 substation automation. Uses ISO/ACSE transport over TPKT/COTP on port 102. Shares port with S7comm (differentiated by COTP protocol ID byte).",
  },
  bacnet: {
    label: "BACnet/IP",
    port: "47808",
    fcLabel: "Service choices",
    fcPlaceholder: "12, 14, 15",
    fcHelp:
      "Confirmed: 12=ReadProperty, 14=WriteProperty, 15=WritePropertyMultiple, 5=SubscribeCOV, 26=ReadPropertyMultiple. Unconfirmed: 0=I-Am, 1=I-Have, 8=Who-Is, 7=Who-Has, 2=COV-Notification",
    addrLabel: "Object type / instance",
    addrPlaceholder: "analog-input:1, binary-output:5",
    addrHelp:
      "BACnet objects are type:instance pairs. Common types: analog-input (0), analog-output (1), analog-value (2), binary-input (3), binary-output (4), binary-value (5), device (8).",
    showObjectType: true,
    showPropertyId: true,
    notes:
      "BACnet/IP uses UDP port 47808 (0xBAC0). BVLC (BACnet Virtual Link Control) encapsulates NPDU and APDU layers. Property IDs: 85=Present Value, 28=Description, 77=Object Name.",
  },
  opcua: {
    label: "OPC UA",
    port: "4840",
    fcLabel: "Service types",
    fcPlaceholder: "",
    fcHelp:
      "Services: OpenSecureChannel, CloseSecureChannel, CreateSession, ActivateSession, Read, Write, Browse, BrowseNext, Call, CreateSubscription, Publish, CreateMonitoredItems",
    addrLabel: "Node IDs",
    addrPlaceholder: "ns=2;s=MyVariable",
    addrHelp:
      "OPC UA node IDs: ns=<namespace>;i=<numeric> or ns=<namespace>;s=<string>. Namespace 0 is the OPC UA standard namespace. Application-specific nodes typically use ns=1 or ns=2.",
    notes:
      "OPC UA uses a binary protocol over TCP. The decoder identifies message types (HEL, ACK, OPN, CLO, MSG) and extracts service IDs from MSG chunks. Security is negotiated at the secure channel level.",
  },
};

export const ICS_PROTOCOL_KEYS = Object.keys(ICS_PROTOCOLS);

export function icsProtoMeta(name: string): ICSProtoMeta {
  return (
    ICS_PROTOCOLS[name] ?? {
      label: name,
      port: "",
      fcLabel: "Function codes",
      fcPlaceholder: "",
      fcHelp: "",
      addrLabel: "Addresses",
      addrPlaceholder: "",
      addrHelp: "",
    }
  );
}

export function zoneLabel(zone: Zone): string {
  return zone.alias ? `${zone.alias} (${zone.name})` : zone.name;
}

export function zoneName(zones: Zone[], name: string): string {
  const match = zones.find((z) => z.name === name);
  return match ? zoneLabel(match) : name;
}

function ip4ToInt(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  const nums = parts.map((p) => Number(p));
  if (nums.some((n) => !Number.isFinite(n) || n < 0 || n > 255)) return null;
  return ((nums[0] << 24) | (nums[1] << 16) | (nums[2] << 8) | nums[3]) >>> 0;
}

function intToIP4(n: number): string {
  const v = n >>> 0;
  return `${(v >>> 24) & 255}.${(v >>> 16) & 255}.${(v >>> 8) & 255}.${v & 255}`;
}

function maskFromPrefix(prefix: number): number | null {
  if (!Number.isFinite(prefix) || prefix < 0 || prefix > 32) return null;
  if (prefix === 0) return 0;
  return (0xffffffff << (32 - prefix)) >>> 0;
}

export function firstHostInCIDR(cidr: string): string | null {
  const raw = cidr.trim();
  const slash = raw.lastIndexOf("/");
  if (slash <= 0) return null;
  const ip = raw.slice(0, slash);
  const pfx = Number(raw.slice(slash + 1));
  const ipInt = ip4ToInt(ip);
  const mask = maskFromPrefix(pfx);
  if (ipInt == null || mask == null) return null;
  const net = ipInt & mask;
  const first = (net + 1) >>> 0;
  return intToIP4(first);
}

export function pickWanIface(ifs: Interface[]): Interface | null {
  const byName = ifs.find((i) => i.name === "wan");
  if (byName) return byName;
  const byZone = ifs.find((i) => (i.zone || "").toLowerCase() === "wan");
  return byZone ?? null;
}

export function pickWanCIDR(state: InterfaceState | null): string | null {
  if (!state) return null;
  for (const addr of state.addrs || []) {
    const s = String(addr);
    if (!s.includes("/")) continue;
    if (s.includes(":")) continue;
    if (s.startsWith("169.254.")) continue;
    return s;
  }
  return null;
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
  { key: "cip", label: "CIP / EtherNet/IP", port: "44818", desc: "Service codes, object classes, CIP paths" },
  { key: "s7comm", label: "S7comm", port: "102", desc: "Memory areas, DB numbers, read/write ops" },
  { key: "mms", label: "IEC 61850 MMS", port: "102", desc: "MMS service requests, named variables" },
  { key: "bacnet", label: "BACnet/IP", port: "47808", desc: "Service types, object types, property IDs" },
  { key: "opcua", label: "OPC UA", port: "4840", desc: "Service types, node IDs, browse/read/write" },
];

export const ICS_PROTOCOL_OPTIONS: Record<
  string,
  {
    fcLabel: string;
    fcHelp: string;
    addrLabel: string;
    addrHelp: string;
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
    addrLabel: "Station addresses",
    addrHelp: "Source and destination addresses (0-65534)",
  },
  cip: {
    fcLabel: "Service codes",
    fcHelp: "0x4C=Read Tag, 0x4D=Write Tag, 0x52=Multiple Service",
    addrLabel: "CIP path",
    addrHelp: "Object class / instance path",
    hasObjectClasses: true,
  },
  s7comm: {
    fcLabel: "Function codes",
    fcHelp: "0x04=Read, 0x05=Write, 0x28=Setup Comm, 0x29=PLC Stop",
    addrLabel: "Memory area / DB",
    addrHelp: "DB numbers, memory area types",
  },
  mms: {
    fcLabel: "Service types",
    fcHelp: "Read, Write, GetNameList, Define, Report",
    addrLabel: "Named variables",
    addrHelp: "Domain/variable name patterns",
  },
  bacnet: {
    fcLabel: "Service types",
    fcHelp: "ReadProperty, WriteProperty, SubscribeCOV, WhoIs",
    addrLabel: "Object type / instance",
    addrHelp: "e.g. analog-input:1, binary-output:5",
  },
  opcua: {
    fcLabel: "Service types",
    fcHelp: "Read, Write, Browse, Call, CreateSubscription",
    addrLabel: "Node IDs",
    addrHelp: "Namespace and identifier patterns",
  },
};
