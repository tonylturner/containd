"use client";

import { ReactNode } from "react";

export type NavItem = { href: string; label: string };
export type NavGroup = {
  label: string;
  items: NavItem[];
  defaultCollapsed?: boolean;
};

function IconShield() {
  return (
    <svg
      viewBox="0 0 24 24"
      className="h-4 w-4"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.5}
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </svg>
  );
}

function IconNetwork() {
  return (
    <svg
      viewBox="0 0 24 24"
      className="h-4 w-4"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.5}
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <rect x="2" y="2" width="6" height="6" rx="1" />
      <rect x="16" y="2" width="6" height="6" rx="1" />
      <rect x="9" y="16" width="6" height="6" rx="1" />
      <path d="M5 8v3a3 3 0 003 3h8a3 3 0 003-3V8M12 14v2" />
    </svg>
  );
}

function IconMonitor() {
  return (
    <svg
      viewBox="0 0 24 24"
      className="h-4 w-4"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.5}
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M22 12h-4l-3 9L9 3l-3 9H2" />
    </svg>
  );
}

function IconWrench() {
  return (
    <svg
      viewBox="0 0 24 24"
      className="h-4 w-4"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.5}
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M14.7 6.3a1 1 0 000 1.4l1.6 1.6a1 1 0 001.4 0l3.77-3.77a6 6 0 01-7.94 7.94l-6.91 6.91a2.12 2.12 0 01-3-3l6.91-6.91a6 6 0 017.94-7.94l-3.76 3.76z" />
    </svg>
  );
}

function IconServer() {
  return (
    <svg
      viewBox="0 0 24 24"
      className="h-4 w-4"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.5}
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <rect x="2" y="2" width="20" height="8" rx="2" />
      <rect x="2" y="14" width="20" height="8" rx="2" />
      <circle cx="6" cy="6" r="1" fill="currentColor" />
      <circle cx="6" cy="18" r="1" fill="currentColor" />
    </svg>
  );
}

function IconSettings() {
  return (
    <svg
      viewBox="0 0 24 24"
      className="h-4 w-4"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.5}
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <circle cx="12" cy="12" r="3" />
      <path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z" />
    </svg>
  );
}

export const NAV_ICONS: Record<string, () => ReactNode> = {
  "Policy & Rules": IconShield,
  Network: IconNetwork,
  Monitoring: IconMonitor,
  Operations: IconWrench,
  Services: IconServer,
  System: IconSettings,
};

export function docsHrefForPath(pathname: string): string {
  const mappings: Array<{ prefix: string; href: string }> = [
    { prefix: "/firewall/", href: "/docs/policy-model/" },
    { prefix: "/wizard/", href: "/docs/policy-model/" },
    { prefix: "/ics/", href: "/docs/ics-dpi/" },
    { prefix: "/ids/", href: "/docs/ids-rules/" },
    { prefix: "/templates/", href: "/docs/policy-model/" },
    { prefix: "/zones/", href: "/docs/policy-model/" },
    { prefix: "/interfaces/", href: "/docs/policy-model/" },
    { prefix: "/routing/", href: "/docs/config-format/" },
    { prefix: "/nat/", href: "/docs/policy-model/" },
    { prefix: "/dhcp/", href: "/docs/services/" },
    { prefix: "/vpn/", href: "/docs/services/" },
    { prefix: "/monitoring/", href: "/docs/api-reference/" },
    { prefix: "/topology/", href: "/docs/architecture/" },
    { prefix: "/flows/", href: "/docs/api-reference/" },
    { prefix: "/events/", href: "/docs/api-reference/" },
    { prefix: "/alerts/", href: "/docs/ids-rules/" },
    { prefix: "/assets/", href: "/docs/ics-dpi/" },
    { prefix: "/diagnostics/", href: "/docs/api-reference/" },
    { prefix: "/dataplane/", href: "/docs/dataplane/" },
    { prefix: "/pcap/", href: "/docs/ics-dpi/" },
    { prefix: "/system/services/", href: "/docs/services/" },
    { prefix: "/proxies/", href: "/docs/services/" },
    { prefix: "/config/", href: "/docs/config-format/" },
    { prefix: "/system/settings/", href: "/docs/api-reference/" },
    { prefix: "/system/users/", href: "/docs/api-reference/" },
  ];
  const match = mappings.find((entry) => pathname.startsWith(entry.prefix));
  return match?.href ?? "/docs/";
}

function parseOptionalDate(raw?: string): Date | null {
  if (!raw) return null;
  const parsed = new Date(raw);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

export function isMFAGraceExpired(raw?: string): boolean {
  const deadline = parseOptionalDate(raw);
  if (!deadline) return true;
  return Date.now() >= deadline.getTime();
}

export function formatOptionalDate(raw?: string): string | null {
  const deadline = parseOptionalDate(raw);
  if (!deadline) return null;
  return deadline.toLocaleString();
}

export function buildNavGroups(isAdmin: boolean): NavGroup[] {
  const groups: NavGroup[] = [
    {
      label: "Policy & Rules",
      items: [
        { href: "/firewall/", label: "Firewall Rules" },
        { href: "/ics/", label: "ICS Rules" },
        { href: "/ids/", label: "IDS Rules" },
        { href: "/templates/", label: "Policy Templates" },
        { href: "/wizard/", label: "Policy Wizard" },
      ],
      defaultCollapsed: false,
    },
    {
      label: "Network",
      items: [
        { href: "/zones/", label: "Zones" },
        { href: "/interfaces/", label: "Interfaces" },
        { href: "/routing/", label: "Routing" },
        { href: "/nat/", label: "NAT" },
        { href: "/dhcp/", label: "DHCP" },
        { href: "/vpn/", label: "VPN" },
      ],
      defaultCollapsed: true,
    },
    {
      label: "Monitoring",
      items: [
        { href: "/monitoring/", label: "Telemetry" },
        { href: "/topology/", label: "Topology" },
        { href: "/flows/", label: "Active Flows" },
        { href: "/events/", label: "Events" },
        { href: "/alerts/", label: "IDS Alerts" },
        { href: "/assets/", label: "Assets" },
      ],
      defaultCollapsed: true,
    },
    {
      label: "Operations",
      items: [
        { href: "/diagnostics/", label: "Diagnostics" },
        { href: "/dataplane/", label: "PCAP Capture" },
        { href: "/pcap/", label: "PCAP Analysis" },
        { href: "/audit/", label: "Audit Log" },
        { href: "/sessions/", label: "Sessions" },
      ],
      defaultCollapsed: true,
    },
    {
      label: "Services",
      items: [
        { href: "/system/services/", label: "Service Status" },
        { href: "/system/services/dns/", label: "DNS" },
        { href: "/system/services/ntp/", label: "NTP" },
        { href: "/system/services/syslog/", label: "Syslog" },
        { href: "/proxies/", label: "Proxies" },
        { href: "/system/services/av/", label: "Antivirus" },
      ],
      defaultCollapsed: true,
    },
  ];
  if (isAdmin) {
    groups.push({
      label: "System",
      items: [
        { href: "/config/", label: "Configuration" },
        { href: "/system/settings/", label: "Settings" },
        { href: "/system/users/", label: "Users" },
      ],
      defaultCollapsed: true,
    });
  }
  return groups;
}
