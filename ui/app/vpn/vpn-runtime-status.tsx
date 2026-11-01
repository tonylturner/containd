"use client";

import { Skeleton } from "../../components/Skeleton";
import { Sparkline } from "../../components/Sparkline";

import type { ServicesStatus } from "../../lib/api";

export function VPNRuntimeStatusCard({
  loading,
  servicesStatus,
}: {
  loading: boolean;
  servicesStatus: ServicesStatus | null;
}) {
  const svcStatus = servicesStatus?.vpn;
  const wireguardFaulted = servicesStatus?.wireguard?.state === "faulted";
  const openvpnFaulted = servicesStatus?.openvpn?.state === "faulted";
  return (
    <section aria-label="VPN runtime status" className="mb-4 rounded-xs border bg-(--surface) p-5 shadow-card backdrop-blur-sm">
      <h2 className="text-sm font-semibold text-(--text)">Runtime status</h2>
      {loading ? (
        <div className="mt-3 space-y-2">
          <Skeleton className="h-16 w-full" />
          <Skeleton className="h-8 w-1/2" />
        </div>
      ) : (
        <div className="mt-3 grid gap-2 text-sm text-(--text) md:grid-cols-2">
          {!svcStatus && <p role="status" className="md:col-span-2">Unknown — live VPN status unavailable. Use Refresh to retry.</p>}
          <div>
            WireGuard:{" "}
            <span className={wireguardFaulted ? "text-amber" : "text-(--text)"}>
              {wireguardFaulted ? "faulted" : typeof svcStatus?.wireguard_enabled !== "boolean" ? "Unknown" : svcStatus.wireguard_enabled ? "enabled" : "disabled"}
            </span>
          </div>
          <div>
            OpenVPN:{" "}
            <span className={openvpnFaulted ? "text-amber" : "text-(--text)"}>
              {openvpnFaulted ? "faulted" : typeof svcStatus?.openvpn_running !== "boolean" ? "Unknown" : svcStatus.openvpn_running ? "running" : "stopped"}
            </span>
            {svcStatus?.openvpn_pid ? <span className="text-(--text-muted)"> (pid {svcStatus.openvpn_pid})</span> : null}
          </div>
          {svcStatus?.openvpn_mode === "server" ? (
            <>
              <div>
                Server tunnel: <span className="text-(--text)">{svcStatus?.openvpn_server_tunnel || "n/a"}</span>
              </div>
              <div>
                Public endpoint:{" "}
                <span className="text-(--text)">{svcStatus?.openvpn_server_endpoint || "n/a"}</span>
              </div>
            </>
          ) : null}
          <div className="md:col-span-2">
            Rate: <span className="text-(--text)">{typeof svcStatus?.rate_per_min === "number" ? svcStatus.rate_per_min.toFixed(1) : "Unknown"} / min</span>
          </div>
          <div className="md:col-span-2">
            Errors: <span>{typeof svcStatus?.errors_rate_per_min === "number" ? svcStatus.errors_rate_per_min.toFixed(1) : "Unknown"} / min</span>
          </div>
          <div className="md:col-span-2">
            OpenVPN config: <span className="text-(--text)">{svcStatus?.openvpn_config_path || "n/a"}</span>
          </div>
          {svcStatus?.openvpn_last_error ? (
            <div className="md:col-span-2 rounded-xs border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400">
              {svcStatus.openvpn_last_error}
            </div>
          ) : null}
          {svcStatus?.sparkline?.length ? (
            <div className="md:col-span-2">
              <Sparkline
                values={svcStatus.sparkline}
                color="var(--primary)"
                background="linear-gradient(180deg, rgba(37,99,235,0.08), rgba(6,182,212,0.04))"
                title="VPN events per minute"
              />
            </div>
          ) : null}
        </div>
      )}
    </section>
  );
}
