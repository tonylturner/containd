"use client";

import { Skeleton } from "../../components/Skeleton";
import { Sparkline } from "../../components/Sparkline";

import type { NormalizedVPNConfig, VPNServiceStatus } from "./vpn-shared";

export function VPNRuntimeStatusCard({
  cfg,
  loading,
  svcStatus,
  vpnSpark,
}: {
  cfg: NormalizedVPNConfig;
  loading: boolean;
  svcStatus: VPNServiceStatus | null;
  vpnSpark: number[];
}) {
  return (
    <div className="mb-4 rounded-xs border bg-(--surface) p-5 shadow-card backdrop-blur-sm">
      <h2 className="text-sm font-semibold text-(--text)">Runtime status</h2>
      {loading ? (
        <div className="mt-3 space-y-2">
          <Skeleton className="h-16 w-full" />
          <Skeleton className="h-8 w-1/2" />
        </div>
      ) : (
        <div className="mt-3 grid gap-2 text-sm text-(--text) md:grid-cols-2">
          <div>
            WireGuard enabled:{" "}
            <span className="text-(--text)">{cfg.wireguard.enabled ? "yes" : "no"}</span>
          </div>
          <div>
            OpenVPN running:{" "}
            <span className="text-(--text)">{svcStatus?.openvpn_running ? "yes" : "no"}</span>
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
            Rate: <span className="text-(--text)">{typeof (svcStatus as any)?.rate_per_min === "number" ? (svcStatus as any)?.rate_per_min.toFixed(1) : "0.0"} / min</span>
          </div>
          <div className="md:col-span-2">
            Errors: <span>{typeof (svcStatus as any)?.errors_rate_per_min === "number" ? (svcStatus as any)?.errors_rate_per_min.toFixed(1) : "0.0"} / min</span>
          </div>
          <div className="md:col-span-2">
            OpenVPN config: <span className="text-(--text)">{svcStatus?.openvpn_config_path || "n/a"}</span>
          </div>
          {svcStatus?.openvpn_last_error ? (
            <div className="md:col-span-2 rounded-xs border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400">
              {svcStatus.openvpn_last_error}
            </div>
          ) : null}
          <div className="md:col-span-2">
            <Sparkline
              values={vpnSpark}
              color="var(--primary)"
              background="linear-gradient(180deg, rgba(37,99,235,0.08), rgba(6,182,212,0.04))"
              title="Session activity trend"
            />
          </div>
        </div>
      )}
    </div>
  );
}
