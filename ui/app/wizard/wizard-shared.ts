import { validateIPv4, validatePort } from "../../lib/validate";

export const ICS_PROTOCOLS: Record<string, { label: string; port: number }> = {
  modbus: { label: "Modbus/TCP", port: 502 },
  dnp3: { label: "DNP3", port: 20000 },
  iec104: { label: "IEC 60870-5-104", port: 2404 },
  cip: { label: "CIP / EtherNet/IP", port: 44818 },
};

/**
 * Why the publish-service server address cannot be staged, or null when it
 * can. A port forward's destination must be IPv4.
 */
export function serverIpError(value: string): string | null {
  return value.trim() ? validateIPv4(value) : "Enter an IPv4 address.";
}

/** Why the publish-service port cannot be staged, or null when it can. */
export function serverPortError(value: string): string | null {
  return value.trim() ? validatePort(value) : "Enter a port.";
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
      "Prepare Internet access for internal hosts using outbound address sharing (SNAT).",
    color: "bg-(--amber)",
    steps: ["Select LAN zone", "Select WAN zone", "Review & Stage"],
  },
  {
    id: "publish-service",
    title: "Publish Internal Service",
    description:
      "Prepare external access to an internal server using port forwarding (DNAT).",
    color: "bg-amber",
    steps: [
      "Server details",
      "Select protocol",
      "Select ingress zone",
      "Review & Stage",
    ],
  },
  {
    id: "ics-comm",
    title: "Allow ICS Communication",
    description:
      "Prepare industrial protocol rules between zones, with a separate inspection mode.",
    color: "",
    steps: [
      "Select ICS protocol",
      "Select zones",
      "Access level",
      "Review & Stage",
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
      "Review & Stage",
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
