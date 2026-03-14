import type { Zone } from "../../lib/api";

export const ICS_PROTOCOLS: Record<string, { label: string; port: number }> = {
  modbus: { label: "Modbus/TCP", port: 502 },
  dnp3: { label: "DNP3", port: 20000 },
  cip: { label: "CIP / EtherNet/IP", port: 44818 },
  s7comm: { label: "S7comm (Siemens)", port: 102 },
  bacnet: { label: "BACnet/IP", port: 47808 },
  opcua: { label: "OPC UA", port: 4840 },
  mms: { label: "IEC 61850 MMS", port: 102 },
};

export function zoneLabel(zone: Zone): string {
  return zone.alias ? `${zone.alias} (${zone.name})` : zone.name;
}

export function genId(): string {
  return `wiz-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
}

export type WizardId =
  | "lan-internet"
  | "publish-service"
  | "ics-comm"
  | "inter-zone";

export type CardDef = {
  id: WizardId;
  title: string;
  description: string;
  color: string;
  steps: string[];
};

export const CARDS: CardDef[] = [
  {
    id: "lan-internet",
    title: "Allow LAN Internet Access",
    description:
      "Enable internal hosts to reach the Internet via SNAT masquerade.",
    color: "bg-[var(--amber)]",
    steps: ["Select LAN zone", "Select WAN zone", "Review & Apply"],
  },
  {
    id: "publish-service",
    title: "Publish Internal Service",
    description:
      "Expose an internal server to external traffic with DNAT port forwarding.",
    color: "bg-amber",
    steps: [
      "Server details",
      "Select protocol",
      "Select ingress zone",
      "Review & Apply",
    ],
  },
  {
    id: "ics-comm",
    title: "Allow ICS Communication",
    description:
      "Permit industrial protocol traffic between zones with DPI enforcement.",
    color: "bg-cyan-400",
    steps: [
      "Select ICS protocol",
      "Select zones",
      "Access level",
      "Review & Apply",
    ],
  },
  {
    id: "inter-zone",
    title: "Inter-Zone Communication",
    description:
      "Allow traffic between two zones with optional protocol/port filtering.",
    color: "bg-purple-400",
    steps: [
      "Source zone",
      "Destination zone",
      "Protocols & ports",
      "Review & Apply",
    ],
  },
];

export const COMMON_PROTOCOLS: { label: string; name: string; port: string }[] =
  [
    { label: "HTTP (80)", name: "tcp", port: "80" },
    { label: "HTTPS (443)", name: "tcp", port: "443" },
    { label: "SSH (22)", name: "tcp", port: "22" },
    { label: "RDP (3389)", name: "tcp", port: "3389" },
    { label: "DNS (53)", name: "udp", port: "53" },
    { label: "SNMP (161)", name: "udp", port: "161" },
    { label: "NTP (123)", name: "udp", port: "123" },
    { label: "ICMP", name: "icmp", port: "" },
  ];
