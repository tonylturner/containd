"use client";

import Link from "next/link";
import type { ServiceName, ServicesStatus } from "../lib/api-service-status";
import { TechnicalDetails } from "./TechnicalDetails";

const services: Record<ServiceName, { label: string; href: string }> = {
  syslog: { label: "Syslog", href: "/system/services/syslog/" },
  dns: { label: "DNS", href: "/system/services/dns/" },
  ntp: { label: "NTP", href: "/system/services/ntp/" },
  av: { label: "Antivirus / ICAP", href: "/system/services/av/" },
  proxy: { label: "Proxies", href: "/proxies/" },
  dhcp: { label: "DHCP", href: "/dhcp/" },
  wireguard: { label: "WireGuard", href: "/vpn/" },
  openvpn: { label: "OpenVPN", href: "/vpn/" },
};

/** Shared compact summary above both configuration forms and the overview. */
export function ServiceFaultBanner({ status, loading, only, repairLinks = false }: {
  status: ServicesStatus | null;
  loading: boolean;
  only?: ServiceName[];
  repairLinks?: boolean;
}) {
  if (loading) return null;
  if (!status) return (
    <aside role="status" aria-label="Service faults" className="mb-4 rounded-xs border border-amber/30 bg-amber/10 px-4 py-3 text-sm text-amber">
      Service status unavailable. Refresh to check for service faults.
    </aside>
  );
  const faults = status.faults.filter((fault) => !only || only.includes(fault.service));
  if (!faults.length) return null;
  const avPolicy = status.av.available ? status.av.gate?.fail_policy ?? status.av.failPolicy : undefined;
  return (
    <aside role="status" aria-label="Service faults" className="mb-4 rounded-xs border border-amber/30 bg-amber/10 px-4 py-3 text-sm text-(--text)">
      <ul className="space-y-3">
        {faults.map((fault) => {
          const service = services[fault.service];
          const quarantined = fault.kind === "config";
          return (
            <li key={fault.service} className="break-words">
              <div className="flex flex-wrap items-baseline gap-x-3">
                <h2 className="font-semibold text-amber">{service.label} — {quarantined ? "Settings need attention" : "Service could not run"}</h2>
                {repairLinks && <Link href={service.href} className="text-xs underline">Configure {service.label}</Link>}
              </div>
              <TechnicalDetails>{fault.message}</TechnicalDetails>
              <p className="mt-1 text-xs">
                {quarantined
                  ? "These saved settings were rejected. Edit or clear them, then commit to apply. Unrelated edits can still be saved."
                  : "Applying configuration again retries this service. Check the service, then commit to apply again."}
              </p>
              {quarantined && fault.service !== "av" && <p className="mt-1 text-xs">
                Remote clients cannot connect unless access is explicitly allowed.
                {(fault.service === "wireguard" || fault.service === "openvpn") &&
                  ` ${service.label} tunnel settings were rejected: rules targeting this tunnel do not match traffic.`}
              </p>}
              {quarantined && fault.service === "av" && <p className="mt-1 text-xs">
                Scanner unavailable; scan selection and fail policy still apply.{" "}
                {avPolicy === "closed"
                  ? "Closed policy still blocks unscanned selected traffic except the configured ICS bypass."
                  : avPolicy === "open"
                    ? "Open policy permits selected traffic unscanned."
                    : "Closed policy still blocks unscanned selected traffic except the configured ICS bypass; open policy permits it."}
              </p>}
            </li>
          );
        })}
      </ul>
    </aside>
  );
}
