"use client";

import { useCallback, useEffect, useState } from "react";
import {
  api,
  SystemStats,
  SystemInspection,
  Interface,
  InterfaceState,
  FlowSummary,
  fetchHealth,
  ServicesStatus,
} from "../../lib/api";
import s from "./physical.module.css";
import ts from "./topology.module.css";

/* ════════════════════════════════════════════════════════════════════
   TYPES
   ════════════════════════════════════════════════════════════════════ */

interface PhysicalData {
  stats: SystemStats | null;
  inspection: SystemInspection | null;
  health: { component?: string; build?: string; time?: string } | null;
  interfaces: Interface[];
  ifaceState: InterfaceState[];
  flows: FlowSummary[];
  services: ServicesStatus | null;
}

type LayerId = "host" | "runtime" | "container" | "process";

interface SecurityFlag {
  level: "ok" | "warn" | "crit";
  title: string;
  desc: string;
}

/* ════════════════════════════════════════════════════════════════════
   HELPERS
   ════════════════════════════════════════════════════════════════════ */

function fmtBytes(b: number): string {
  if (b <= 0) return "0 B";
  if (b < 1024) return `${b} B`;
  if (b < 1048576) return `${(b / 1024).toFixed(1)} KB`;
  if (b < 1073741824) return `${(b / 1048576).toFixed(1)} MB`;
  return `${(b / 1073741824).toFixed(1)} GB`;
}

function fmtUptime(raw: string): string {
  if (!raw || raw === "\u2014") return "\u2014";
  // Go duration format: "72h3m4s" or similar
  const h = raw.match(/(\d+)h/);
  const m = raw.match(/(\d+)m/);
  const totalH = h ? parseInt(h[1]) : 0;
  const totalM = m ? parseInt(m[1]) : 0;
  const days = Math.floor(totalH / 24);
  const hours = totalH % 24;
  return `${days}d ${hours}h ${totalM}m`;
}

const DANGER_CAPS = new Set(["CAP_SYS_ADMIN", "CAP_NET_ADMIN", "CAP_SYS_RAWIO", "CAP_DAC_OVERRIDE"]);
const WARN_CAPS = new Set(["CAP_NET_RAW", "CAP_SYS_PTRACE", "CAP_SYS_MODULE", "CAP_MKNOD"]);

/* ════════════════════════════════════════════════════════════════════
   SECURITY FLAGS COMPUTATION
   ════════════════════════════════════════════════════════════════════ */

function computeFlags(d: PhysicalData): SecurityFlag[] {
  const flags: SecurityFlag[] = [];
  const insp = d.inspection;
  const stats = d.stats;

  if (!insp) return [{ level: "warn", title: "Inspection data unavailable", desc: "Cannot compute security posture without /api/v1/system/inspection" }];

  // CRIT flags
  if (insp.container.privileged) {
    flags.push({ level: "crit", title: "Running --privileged", desc: "Full host capability access. Required for packet filtering but increases blast radius if compromised." });
  }
  if (insp.security.dockerSocketMounted) {
    flags.push({ level: "crit", title: "Docker socket mounted", desc: "/var/run/docker.sock is accessible. Container can control host Docker daemon." });
  }
  const authEnv = insp.container.envVars.find((e) => e.key === "CONTAIND_AUTH");
  if (authEnv?.value === "relaxed") {
    flags.push({ level: "crit", title: "CONTAIND_AUTH=relaxed", desc: "Authentication is in relaxed mode. All API calls bypass credential checks." });
  }
  if (insp.container.seccompProfile === "unconfined") {
    flags.push({ level: "crit", title: "Seccomp unconfined", desc: "No syscall filtering. Container has unrestricted kernel surface." });
  }

  // WARN flags
  if (stats && stats.container.memLimitBytes === 0) {
    flags.push({ level: "warn", title: "No memory cgroup limit", desc: "Container can consume all host RAM. Set --memory in production." });
  }
  if (insp.security.cgroupCPUQuota === "max" || insp.security.cgroupCPUQuota === "unlimited") {
    flags.push({ level: "warn", title: "CPU quota unlimited", desc: "No CPU cgroup limit set. Container can saturate all cores." });
  }
  if (insp.container.networkMode === "host") {
    flags.push({ level: "warn", title: "Host network namespace", desc: "--net=host expected for a firewall, but container sees all host interfaces." });
  }
  const configMount = insp.container.mounts.find((m) => m.containerPath.includes("/config"));
  if (configMount?.mode?.toLowerCase().includes("rw")) {
    flags.push({ level: "warn", title: "Config volume is writable", desc: `${configMount.containerPath} mounted RW. Consider RO + config reload via signal.` });
  }
  if (insp.container.restartCount > 0) {
    flags.push({ level: "warn", title: `${insp.container.restartCount} container restart(s)`, desc: "Container has restarted since host boot. Check logs for crash cause." });
  }
  if (!insp.container.readonlyRootfs) {
    flags.push({ level: "warn", title: "Root filesystem not read-only", desc: "Container rootfs is writable. Set --read-only for defense in depth." });
  }
  if (!insp.security.cgroupPIDsLimit || insp.security.cgroupPIDsLimit === "max") {
    flags.push({ level: "warn", title: "PIDs limit not set", desc: "No fork bomb protection. Set pids_limit in docker-compose or --pids-limit on docker run." });
  }
  // Check for RW mounts that could be sensitive
  const rwMounts = insp.container.mounts.filter((m) => {
    const mode = m.mode?.toLowerCase() || "";
    if (!mode.includes("rw")) return false;
    // Skip expected RW mounts (overlay root, /etc/resolv.conf, /etc/hostname, /etc/hosts)
    const skip = ["/etc/resolv.conf", "/etc/hostname", "/etc/hosts"];
    return !skip.includes(m.containerPath);
  });
  if (rwMounts.length > 0) {
    const paths = rwMounts.map((m) => m.containerPath).join(", ");
    flags.push({ level: "warn", title: `${rwMounts.length} writable volume mount(s)`, desc: `Writable mounts: ${paths}. Mount read-only where possible (:ro).` });
  }
  const hasLabEnv = insp.container.envVars.some((e) => /lab|debug/i.test(e.value));
  if (hasLabEnv) {
    flags.push({ level: "warn", title: "Lab/debug env detected", desc: "Environment variables contain 'lab' or 'debug'. Not suitable for production." });
  }
  if (!insp.container.noNewPrivileges) {
    flags.push({ level: "warn", title: "no-new-privileges not set", desc: "Process can gain privileges via setuid/setgid binaries. Set security_opt: no-new-privileges in production." });
  }

  // OK flags
  if (!insp.security.dockerSocketMounted) {
    flags.push({ level: "ok", title: "Docker socket not mounted", desc: "No /var/run/docker.sock bind mount. Container cannot escape to host Docker daemon." });
  }
  const certsMount = insp.container.mounts.find((m) => m.containerPath.includes("/certs"));
  if (certsMount?.mode?.toLowerCase().includes("ro")) {
    flags.push({ level: "ok", title: "Certs volume read-only", desc: `${certsMount.containerPath} mounted RO. Certificate files are protected.` });
  }
  if (insp.security.cgroupPIDsLimit && insp.security.cgroupPIDsLimit !== "max") {
    flags.push({ level: "ok", title: `PIDs limit set (${insp.security.cgroupPIDsLimit})`, desc: "Fork bomb protection active via cgroup PIDs controller." });
  }
  if (insp.container.noNewPrivileges) {
    flags.push({ level: "ok", title: "no-new-privileges enabled", desc: "Process cannot gain additional privileges via setuid/setgid." });
  }

  return flags;
}

/* ════════════════════════════════════════════════════════════════════
   SUB-COMPONENTS
   ════════════════════════════════════════════════════════════════════ */

function KV({ k, v, vc }: { k: string; v: string; vc?: string }) {
  return (
    <div className={s.kvRow}>
      <span className={s.kvKey}>{k}</span>
      <span className={`${s.kvVal} ${vc ? s[vc] || "" : ""}`} style={vc ? { color: `var(--topo-${vc === "green" ? "green" : vc === "cyan" ? "cyan" : vc === "amber" ? "" : ""})` } : undefined}>
        {v}
      </span>
    </div>
  );
}

function KVc({ k, v, color }: { k: string; v: string; color?: string }) {
  return (
    <div className={s.kvRow}>
      <span className={s.kvKey}>{k}</span>
      <span className={s.kvVal} style={color ? { color } : undefined}>{v}</span>
    </div>
  );
}

function ResBar({ name, val, pct, color }: { name: string; val: string; pct: number; color: string }) {
  return (
    <div className={s.resRow}>
      <div className={s.resHeader}>
        <span className={s.resName}>{name}</span>
        <span className={s.resVal}>{val}</span>
      </div>
      <div className={s.resBarWrap}>
        <div className={s.resBar} style={{ width: `${Math.min(100, pct)}%`, background: color }} />
      </div>
    </div>
  );
}

/* ════════════════════════════════════════════════════════════════════
   MAIN COMPONENT
   ════════════════════════════════════════════════════════════════════ */

export default function PhysicalView() {
  const [data, setData] = useState<PhysicalData | null>(null);
  const [selectedLayer, setSelectedLayer] = useState<LayerId | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchData = useCallback(async () => {
    const [stats, inspection, health, interfaces, ifaceState, flows, services] =
      await Promise.all([
        api.getSystemStats().catch(() => null),
        api.getSystemInspection().catch(() => null),
        fetchHealth().catch(() => null),
        api.listInterfaces().catch(() => []),
        api.listInterfaceState().catch(() => []),
        api.listFlows().catch(() => []),
        api.getServicesStatus().catch(() => null),
      ]);
    setData({
      stats: stats as SystemStats | null,
      inspection: inspection as SystemInspection | null,
      health,
      interfaces: (interfaces as Interface[]) || [],
      ifaceState: (ifaceState as InterfaceState[]) || [],
      flows: (flows as FlowSummary[]) || [],
      services: services as ServicesStatus | null,
    });
    setLoading(false);
  }, []);

  useEffect(() => {
    fetchData();
    const iv = setInterval(fetchData, 30000);
    return () => clearInterval(iv);
  }, [fetchData]);

  if (loading || !data) {
    return (
      <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100%", fontFamily: "var(--mono)", fontSize: 10, color: "var(--text-dim)" }}>
        Loading inspection data...
      </div>
    );
  }

  const st = data.stats;
  const insp = data.inspection;
  const flags = computeFlags(data);

  // Derived values
  const hostKernel = insp?.host.kernel || "\u2014";
  const hostOS = insp?.host.os || "\u2014";
  const hostArch = insp?.host.arch || "\u2014";
  const hostUptime = insp?.host.hostUptime ? fmtUptime(insp.host.hostUptime) : "\u2014";
  const numCPU = st?.cpu.numCPU || insp?.host.numCPU || 0;
  const cpuPct = st?.cpu.usagePercent ?? 0;
  const memTotal = st?.memory.totalBytes ?? 0;
  const memUsed = st?.memory.usedBytes ?? 0;
  const memPct = st?.memory.usagePercent ?? 0;
  const diskTotal = st?.disk.totalBytes ?? 0;
  const diskUsed = st?.disk.usedBytes ?? 0;
  const diskPct = st?.disk.usagePercent ?? 0;

  const dockerVer = insp?.runtime.dockerVersion || "\u2014";
  const containerdVer = insp?.runtime.containerdVersion || "\u2014";
  const cgroupDriver = insp?.runtime.cgroupDriver || "\u2014";
  const storageDriver = insp?.runtime.storageDriver || "\u2014";
  const dockerSock = insp?.security.dockerSocketMounted ?? false;
  const cpuQuota = insp?.security.cgroupCPUQuota || "\u2014";
  const pidsLimit = insp?.security.cgroupPIDsLimit || "\u2014";
  const memLimit = st?.container.memLimitBytes ?? 0;

  const containerId = insp?.container.id || st?.container.id || "\u2014";
  const containerImage = insp?.container.image || data.health?.build || "\u2014";
  const restartPolicy = insp?.container.restartPolicy || "\u2014";
  const restartCount = insp?.container.restartCount ?? 0;
  const networkMode = insp?.container.networkMode || "\u2014";
  const privileged = insp?.container.privileged ?? false;
  const containerUptime = st?.container.uptime ? fmtUptime(st.container.uptime) : "\u2014";
  const capabilities = insp?.container.capabilities || [];
  const mounts = insp?.container.mounts || [];
  const envVars = insp?.container.envVars || [];

  const goroutines = st?.runtime.goroutines ?? 0;
  const heapAlloc = st?.runtime.heapAllocMB ?? 0;
  const heapSys = st?.runtime.heapSysMB ?? 0;
  const processUptime = st?.runtime.uptime ? fmtUptime(st.runtime.uptime) : "\u2014";
  const sessionCount = data.flows.length;
  const fdCount = insp?.process.fdCount ?? 0;
  const fdSoft = insp?.process.fdSoftLimit ?? 0;
  const fdHard = insp?.process.fdHardLimit ?? 0;
  const goVersion = insp?.process.goVersion || "\u2014";
  const buildVersion = data.health?.build || "\u2014";

  const layerCls = (id: LayerId) =>
    `${s.layer} ${s[`layer${id.charAt(0).toUpperCase() + id.slice(1)}`]} ${selectedLayer === id ? s.layerActive : ""}`;

  // Uptime divergence
  const hostUptimeMs = parseUptimeMs(insp?.host.hostUptime || "");
  const containerUptimeMs = parseUptimeMs(st?.container.uptime || "");
  const uptimeRatio = hostUptimeMs > 0 ? Math.min(100, (containerUptimeMs / hostUptimeMs) * 100) : 0;

  const critCount = flags.filter((f) => f.level === "crit").length;
  const warnCount = flags.filter((f) => f.level === "warn").length;

  return (
    <div className={ts.workspace} style={{ gridTemplateColumns: "1fr 300px" }}>
      <div className={s.stackView}>

        {/* ── LAYER 1: HOST ── */}
        <div className={layerCls("host")} onClick={() => setSelectedLayer("host")}>
          <div className={s.layerConnector}>
            <div className={s.layerNode}>H</div>
            <div className={s.layerWire} />
          </div>
          <div className={s.layerCard}>
            <div className={s.layerHeader}>
              <div className={s.layerTitleGroup}>
                <span className={s.layerTitle}>HOST MACHINE</span>
                <span className={s.layerSubtitle}>{hostOS} &middot; {hostKernel} &middot; {hostArch}</span>
              </div>
              <div className={s.layerBadges}>
                <span className={`${s.badge} ${s.badgeInfo}`}>{hostArch}</span>
                <span className={`${s.badge} ${s.badgeOk}`}>ONLINE</span>
              </div>
            </div>
            <div className={s.layerBody}>
              <div className={s.layerSection}>
                <div className={s.layerSectionLabel}>System</div>
                <KVc k="OS" v={hostOS} />
                <KVc k="Kernel" v={hostKernel} color="#06b6d4" />
                <KVc k="Architecture" v={hostArch} />
                <KVc k="Host uptime" v={hostUptime} color="#22c55e" />
              </div>
              <div className={s.layerSection}>
                <div className={s.layerSectionLabel}>Resources</div>
                <ResBar name="CPU" val={`${numCPU} vCPU \u00b7 ${cpuPct.toFixed(0)}%`} pct={cpuPct} color={cpuPct > 80 ? "#ef4444" : cpuPct > 50 ? "#f59e0b" : "#22c55e"} />
                <ResBar name="RAM" val={`${fmtBytes(memTotal)} total \u00b7 ${fmtBytes(memUsed)} used`} pct={memPct} color="#06b6d4" />
                <ResBar name="DISK" val={`${fmtBytes(diskTotal)} \u00b7 ${fmtBytes(diskUsed)} used`} pct={diskPct} color={diskPct > 80 ? "#ef4444" : "#f59e0b"} />
              </div>
              <div className={s.layerSectionFull}>
                <div className={s.layerSectionLabel}>Host Interfaces</div>
                <div className={s.ifacePills}>
                  {data.ifaceState.map((ifc) => (
                    <div key={ifc.name} className={s.ifacePill}>
                      <span className={s.ifacePillName}>{ifc.name}</span>
                      <span className={s.ifacePillIp}>{ifc.addrs?.[0] || "\u2014"}</span>
                      <span className={s.ifacePillType}>{ifc.up ? "up" : "down"} &middot; mtu {ifc.mtu}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* gap */}
        <div className={s.layerGap}>
          <div className={s.arrowCol}>
            <div className={s.arrowLine} style={{ background: "linear-gradient(#164e63, #3b0764)" }} />
          </div>
          <div className={s.arrowLabelCol}>
            <span className={s.arrowChip}>--net={networkMode}</span>
            {networkMode === "host" && <span style={{ color: "#f59e0b", fontSize: 8 }}>host network namespace shared</span>}
          </div>
        </div>

        {/* ── LAYER 2: CONTAINER RUNTIME ── */}
        <div className={layerCls("runtime")} onClick={() => setSelectedLayer("runtime")}>
          <div className={s.layerConnector}>
            <div className={s.layerNode}>R</div>
            <div className={s.layerWire} />
          </div>
          <div className={s.layerCard}>
            <div className={s.layerHeader}>
              <div className={s.layerTitleGroup}>
                <span className={s.layerTitle}>CONTAINER RUNTIME</span>
                <span className={s.layerSubtitle}>Docker {dockerVer} &middot; containerd {containerdVer}</span>
              </div>
              <div className={s.layerBadges}>
                <span className={`${s.badge} ${s.badgeOk}`}>ENGINE UP</span>
                {memLimit === 0 && <span className={`${s.badge} ${s.badgeWarn}`}>NO MEM LIMIT</span>}
              </div>
            </div>
            <div className={s.layerBody}>
              <div className={s.layerSection}>
                <div className={s.layerSectionLabel}>Engine</div>
                <KVc k="Docker version" v={dockerVer} color="#a855f7" />
                <KVc k="containerd" v={containerdVer} />
                <KVc k="Cgroup driver" v={cgroupDriver} color="#06b6d4" />
                <KVc k="Storage driver" v={storageDriver} />
                <KVc k="Docker socket" v={dockerSock ? "MOUNTED" : "NOT mounted"} color={dockerSock ? "#ef4444" : "#22c55e"} />
              </div>
              <div className={s.layerSection}>
                <div className={s.layerSectionLabel}>cgroup Limits</div>
                <div className={s.resRow}>
                  <div className={s.resHeader}>
                    <span className={s.resName}>CPU quota</span>
                    <span className={s.resVal} style={{ color: cpuQuota === "max" || cpuQuota === "unlimited" ? "#f59e0b" : "#22c55e" }}>{cpuQuota}</span>
                  </div>
                  {(cpuQuota === "max" || cpuQuota === "unlimited") ? (
                    <div className={s.resBarDashed}><div className={s.resBar} style={{ width: "100%", background: "rgba(245,158,11,0.15)" }} /></div>
                  ) : (
                    <div className={s.resBarWrap}><div className={s.resBar} style={{ width: "30%", background: "#22c55e" }} /></div>
                  )}
                </div>
                <div className={s.resRow}>
                  <div className={s.resHeader}>
                    <span className={s.resName}>Memory limit</span>
                    <span className={s.resVal} style={{ color: memLimit > 0 ? "#22c55e" : "#ef4444" }}>{memLimit > 0 ? fmtBytes(memLimit) : "NOT SET"}</span>
                  </div>
                  {memLimit > 0 ? (
                    <div className={s.resBarWrap}><div className={s.resBar} style={{ width: `${st?.container.memPercent ?? 0}%`, background: "#22c55e" }} /></div>
                  ) : (
                    <div className={s.resBarDashed}><div className={s.resBar} style={{ width: "100%", background: "rgba(239,68,68,0.12)" }} /></div>
                  )}
                </div>
                <div className={s.resRow}>
                  <div className={s.resHeader}>
                    <span className={s.resName}>PIDs limit</span>
                    <span className={s.resVal} style={{ color: pidsLimit !== "max" && pidsLimit !== "\u2014" ? "#22c55e" : "#f59e0b" }}>{pidsLimit}</span>
                  </div>
                  <div className={s.resBarWrap}><div className={s.resBar} style={{ width: pidsLimit !== "max" && pidsLimit !== "\u2014" ? "8%" : "100%", background: pidsLimit !== "max" ? "#22c55e" : "rgba(245,158,11,0.15)" }} /></div>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* gap */}
        <div className={s.layerGap}>
          <div className={s.arrowCol}>
            <div className={s.arrowLine} style={{ background: "linear-gradient(#3b0764, #7c2d12)" }} />
          </div>
          <div className={s.arrowLabelCol}>
            <span className={s.arrowChip}>docker run</span>
            <span style={{ color: "var(--text-dim)", fontSize: 8 }}>image: {containerImage} &middot; restart: {restartPolicy}</span>
          </div>
        </div>

        {/* ── LAYER 3: CONTAINER ── */}
        <div className={layerCls("container")} onClick={() => setSelectedLayer("container")}>
          <div className={s.layerConnector}>
            <div className={s.layerNode}>C</div>
            <div className={s.layerWire} />
          </div>
          <div className={s.layerCard}>
            <div className={s.layerHeader}>
              <div className={s.layerTitleGroup}>
                <span className={s.layerTitle}>CONTAINER</span>
                <span className={s.layerSubtitle}>{containerId} &middot; {containerImage}</span>
              </div>
              <div className={s.layerBadges}>
                {privileged && <span className={`${s.badge} ${s.badgeOrange}`}>PRIVILEGED</span>}
                <span className={`${s.badge} ${s.badgeOk}`}>RUNNING</span>
                {hasLabEnv(envVars) && <span className={`${s.badge} ${s.badgeWarn}`}>LAB MODE</span>}
              </div>
            </div>
            <div className={s.layerBody}>
              <div className={s.layerSection}>
                <div className={s.layerSectionLabel}>Identity</div>
                <KVc k="Container ID" v={containerId} color="#f97316" />
                <KVc k="Image" v={containerImage} />
                <KVc k="Restart policy" v={restartPolicy} color="#06b6d4" />
                <KVc k="Container uptime" v={containerUptime} color="#22c55e" />
                <KVc k="Restart count" v={restartCount > 0 ? `${restartCount}` : "0"} color={restartCount > 0 ? "#f59e0b" : "#22c55e"} />
              </div>

              <div className={s.layerSection}>
                <div className={s.layerSectionLabel}>Uptime vs Host</div>
                <div className={s.uptimeCompare}>
                  <div className={s.uptimeBarLabel}><span>HOST</span><span>{hostUptime}</span></div>
                  <div className={s.uptimeTrack}>
                    <div className={s.uptimeFill} style={{ width: "100%", background: "rgba(6,182,212,0.3)", flex: 1 }} />
                  </div>
                </div>
                <div className={s.uptimeCompare} style={{ marginTop: 4 }}>
                  <div className={s.uptimeBarLabel}><span>CONTAINER</span><span>{containerUptime}</span></div>
                  <div className={s.uptimeTrack}>
                    <div className={s.uptimeFill} style={{ width: `${uptimeRatio}%`, background: "rgba(249,115,22,0.5)" }} />
                    {restartCount > 0 && (
                      <span style={{ fontFamily: "var(--mono)", fontSize: 8, color: "#f59e0b" }}>{restartCount} restart(s) since host boot</span>
                    )}
                  </div>
                </div>
              </div>

              {capabilities.length > 0 && (
                <div className={s.layerSectionFull}>
                  <div className={s.layerSectionLabel}>Linux Capabilities</div>
                  <div className={s.capsGrid}>
                    {capabilities.map((cap) => (
                      <span key={cap} className={`${s.capTag} ${DANGER_CAPS.has(cap) ? s.capDanger : WARN_CAPS.has(cap) ? s.capWarn : s.capNormal}`}>{cap.replace("CAP_", "")}</span>
                    ))}
                  </div>
                  <div style={{ marginTop: 8, fontFamily: "var(--mono)", fontSize: 8, color: "var(--text-dim)" }}>
                    {privileged && <><span style={{ color: "#f97316" }}>--privileged</span> &middot; </>}
                    seccomp: <span style={{ color: insp?.container.seccompProfile === "unconfined" ? "#f59e0b" : "#22c55e" }}>{insp?.container.seccompProfile || "\u2014"}</span>
                    {" "}&middot; AppArmor: <span style={{ color: insp?.container.apparmorProfile === "unconfined" ? "#f59e0b" : "#22c55e" }}>{insp?.container.apparmorProfile || "\u2014"}</span>
                  </div>
                </div>
              )}

              {mounts.length > 0 && (
                <div className={s.layerSectionFull}>
                  <div className={s.layerSectionLabel}>Volume Mounts</div>
                  <table className={s.mountTable}>
                    <thead><tr><th>Host path</th><th>Container path</th><th style={{ textAlign: "right" }}>Mode</th></tr></thead>
                    <tbody>
                      {mounts.map((m, i) => (
                        <tr key={i}>
                          <td>{m.hostPath}</td>
                          <td>{m.containerPath}</td>
                          <td style={{ textAlign: "right" }}>
                            <span className={m.mode.toLowerCase().includes("ro") ? s.mountRo : s.mountRw}>{m.mode.toUpperCase()}</span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* gap */}
        <div className={s.layerGap}>
          <div className={s.arrowCol}>
            <div className={s.arrowLine} style={{ background: "linear-gradient(#7c2d12, #78490a)" }} />
          </div>
          <div className={s.arrowLabelCol}>
            <span className={s.arrowChip}>exec</span>
            <span style={{ color: "var(--text-dim)", fontSize: 8 }}>pid 1 &middot; /usr/bin/containd</span>
          </div>
        </div>

        {/* ── LAYER 4: PROCESS ── */}
        <div className={layerCls("process")} onClick={() => setSelectedLayer("process")}>
          <div className={s.layerConnector}>
            <div className={s.layerNode}>P</div>
          </div>
          <div className={s.layerCard}>
            <div className={s.layerHeader}>
              <div className={s.layerTitleGroup}>
                <span className={s.layerTitle}>CONTAIND PROCESS</span>
                <span className={s.layerSubtitle}>pid 1 &middot; {buildVersion} &middot; {goroutines} goroutines</span>
              </div>
              <div className={s.layerBadges}>
                <span className={`${s.badge} ${s.badgeOk}`}>ACTIVE</span>
                <span className={`${s.badge} ${s.badgePurple}`}>{sessionCount} SESSIONS</span>
              </div>
            </div>
            <div className={s.layerBody}>
              <div className={s.layerSection}>
                <div className={s.layerSectionLabel}>Runtime</div>
                <KVc k="PID" v="1" color="#f59e0b" />
                <KVc k="Go version" v={goVersion} />
                <KVc k="Goroutines" v={String(goroutines)} />
                <KVc k="Heap alloc" v={`${heapAlloc.toFixed(1)} MB`} />
                <KVc k="Heap sys" v={`${heapSys.toFixed(1)} MB`} />
                <KVc k="Process uptime" v={processUptime} color="#22c55e" />
              </div>

              <div className={s.layerSection}>
                <div className={s.layerSectionLabel}>Sessions &amp; FDs</div>
                <KVc k="Total sessions" v={String(sessionCount)} color="#a855f7" />
                <KVc k="Open FDs" v={String(fdCount)} />
                <KVc k="FD limit (soft)" v={String(fdSoft)} color={fdSoft <= 1024 ? "#f59e0b" : undefined} />
                <KVc k="FD limit (hard)" v={String(fdHard)} />
              </div>

              <div className={s.layerSectionFull}>
                <div className={s.layerSectionLabel}>Bound Interfaces (in-process)</div>
                <div className={s.ifacePills}>
                  {data.interfaces.map((ifc) => (
                    <div key={ifc.name} className={`${s.ifacePill} ${s.ifacePillAmber}`}>
                      <span className={s.ifacePillName}>{ifc.device || ifc.name}</span>
                      <span className={s.ifacePillIp}>{ifc.addresses?.[0] || "\u2014"}</span>
                      <span className={s.ifacePillType} style={{ color: "#22c55e" }}>{ifc.zone || "\u2014"} &middot; up</span>
                    </div>
                  ))}
                </div>
              </div>

              {envVars.length > 0 && (
                <div className={s.layerSectionFull}>
                  <div className={s.layerSectionLabel}>Environment</div>
                  {envVars.map((e) => (
                    <KVc key={e.key} k={e.key} v={e.value} color={/relaxed|lab|debug/i.test(e.value) ? "#ef4444" : undefined} />
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>

        <div style={{ height: 32 }} />
      </div>

      {/* DETAIL PANEL */}
      <div className={ts.detailPanel}>
        <div className={ts.panelHeader}>
          <span className={ts.panelTitle}>{selectedLayer ? selectedLayer.toUpperCase() : "PHYSICAL VIEW"}</span>
          {selectedLayer && <button className={ts.panelClose} onClick={() => setSelectedLayer(null)}>&#x2715;</button>}
        </div>
        <div className={ts.panelBody}>
          {/* Security flags summary */}
          <div className={ts.panelSection}>
            <div className={ts.panelSectionLabel}>Security Flags {critCount > 0 && <span style={{ color: "#ef4444" }}>({critCount} CRIT)</span>} {warnCount > 0 && <span style={{ color: "#f59e0b" }}>({warnCount} WARN)</span>}</div>
            <div className={s.flagList}>
              {flags.map((f, i) => (
                <div key={i} className={`${s.flag} ${f.level === "crit" ? s.flagCrit : f.level === "warn" ? s.flagWarn : s.flagOk}`}>
                  <div className={s.flagDot} style={{ background: f.level === "crit" ? "#ef4444" : f.level === "warn" ? "#f59e0b" : "#22c55e" }} />
                  <div className={s.flagBody}>
                    <div className={s.flagTitle}>{f.title}</div>
                    <div className={s.flagDesc}>{f.desc}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {!selectedLayer && (
            <div className={ts.panelSection}>
              <div className={ts.panelSectionLabel}>Click a layer for details</div>
              <div style={{ fontFamily: "var(--mono)", fontSize: 9, color: "var(--text-dim)", lineHeight: 1.6 }}>
                Select HOST, RUNTIME, CONTAINER, or PROCESS layer to inspect that level in depth.
              </div>
            </div>
          )}

          {selectedLayer && <LayerDetail layer={selectedLayer} data={data} />}
        </div>
      </div>
    </div>
  );
}

/* ════════════════════════════════════════════════════════════════════
   LAYER DETAIL PANEL
   ════════════════════════════════════════════════════════════════════ */

function LayerDetail({ layer, data }: { layer: LayerId; data: PhysicalData }) {
  const st = data.stats;
  const insp = data.inspection;

  const sections = LAYER_SECTIONS[layer]?.(st, insp, data) || [];

  return (
    <>
      {sections.map((sec, si) => (
        <div key={si} className={ts.panelSection}>
          <div className={ts.panelSectionLabel}>{sec.label}</div>
          {sec.rows.map((r, ri) => (
            <div key={ri} className={ts.detailRow}>
              <span className={ts.detailKey}>{r.k}</span>
              <span className={ts.detailVal} style={r.color ? { color: r.color } : undefined}>{r.v}</span>
            </div>
          ))}
        </div>
      ))}
    </>
  );
}

interface DetailSection {
  label: string;
  rows: { k: string; v: string; color?: string }[];
}

const LAYER_SECTIONS: Record<LayerId, (st: SystemStats | null, insp: SystemInspection | null, data: PhysicalData) => DetailSection[]> = {
  host: (st, insp) => [
    { label: "OS & Kernel", rows: [
      { k: "OS", v: insp?.host.os || "\u2014" },
      { k: "Kernel", v: insp?.host.kernel || "\u2014", color: "#06b6d4" },
      { k: "Architecture", v: insp?.host.arch || "\u2014" },
      { k: "Host uptime", v: insp?.host.hostUptime ? fmtUptime(insp.host.hostUptime) : "\u2014", color: "#22c55e" },
    ]},
    { label: "CPU", rows: [
      { k: "vCPU count", v: String(st?.cpu.numCPU || insp?.host.numCPU || 0) },
      { k: "Current usage", v: `${(st?.cpu.usagePercent ?? 0).toFixed(1)}%`, color: (st?.cpu.usagePercent ?? 0) > 50 ? "#f59e0b" : "#22c55e" },
    ]},
    { label: "Memory", rows: [
      { k: "Total RAM", v: fmtBytes(st?.memory.totalBytes ?? 0) },
      { k: "Used", v: `${fmtBytes(st?.memory.usedBytes ?? 0)} (${(st?.memory.usagePercent ?? 0).toFixed(1)}%)`, color: "#22c55e" },
      { k: "Available", v: fmtBytes(st?.memory.availableBytes ?? 0), color: "#22c55e" },
    ]},
    { label: "Storage", rows: [
      { k: "Total", v: fmtBytes(st?.disk.totalBytes ?? 0) },
      { k: "Used", v: `${fmtBytes(st?.disk.usedBytes ?? 0)} (${(st?.disk.usagePercent ?? 0).toFixed(1)}%)`, color: "#f59e0b" },
      { k: "Available", v: fmtBytes(st?.disk.availableBytes ?? 0) },
    ]},
  ],
  runtime: (st, insp) => [
    { label: "Docker Engine", rows: [
      { k: "Version", v: insp?.runtime.dockerVersion || "\u2014", color: "#a855f7" },
      { k: "containerd", v: insp?.runtime.containerdVersion || "\u2014" },
    ]},
    { label: "Runtime Config", rows: [
      { k: "Storage driver", v: insp?.runtime.storageDriver || "\u2014" },
      { k: "Cgroup driver", v: insp?.runtime.cgroupDriver || "\u2014", color: "#06b6d4" },
    ]},
    { label: "Security Profile", rows: [
      { k: "Docker socket mount", v: insp?.security.dockerSocketMounted ? "PRESENT" : "NOT present", color: insp?.security.dockerSocketMounted ? "#ef4444" : "#22c55e" },
    ]},
    { label: "cgroup Limits", rows: [
      { k: "CPU quota", v: insp?.security.cgroupCPUQuota || "\u2014", color: (insp?.security.cgroupCPUQuota === "max" || insp?.security.cgroupCPUQuota === "unlimited") ? "#f59e0b" : "#22c55e" },
      { k: "Memory limit", v: (st?.container.memLimitBytes ?? 0) > 0 ? fmtBytes(st!.container.memLimitBytes) : "NOT SET", color: (st?.container.memLimitBytes ?? 0) > 0 ? "#22c55e" : "#ef4444" },
      { k: "PIDs limit", v: insp?.security.cgroupPIDsLimit || "\u2014", color: (insp?.security.cgroupPIDsLimit && insp.security.cgroupPIDsLimit !== "max") ? "#22c55e" : "#f59e0b" },
    ]},
  ],
  container: (st, insp, data) => [
    { label: "Identity", rows: [
      { k: "Container ID", v: insp?.container.id || st?.container.id || "\u2014", color: "#f97316" },
      { k: "Image", v: insp?.container.image || data.health?.build || "\u2014" },
      { k: "Restart policy", v: insp?.container.restartPolicy || "\u2014", color: "#06b6d4" },
      { k: "Container uptime", v: st?.container.uptime ? fmtUptime(st.container.uptime) : "\u2014", color: "#22c55e" },
      { k: "Restart count", v: String(insp?.container.restartCount ?? 0), color: (insp?.container.restartCount ?? 0) > 0 ? "#f59e0b" : "#22c55e" },
    ]},
    { label: "Privileges", rows: [
      { k: "Privileged mode", v: insp?.container.privileged ? "YES" : "NO", color: insp?.container.privileged ? "#ef4444" : "#22c55e" },
      { k: "Seccomp profile", v: insp?.container.seccompProfile || "\u2014", color: insp?.container.seccompProfile === "unconfined" ? "#f59e0b" : undefined },
      { k: "AppArmor profile", v: insp?.container.apparmorProfile || "\u2014", color: insp?.container.apparmorProfile === "unconfined" ? "#f59e0b" : undefined },
      { k: "Read-only rootfs", v: insp?.container.readonlyRootfs ? "yes" : "no", color: insp?.container.readonlyRootfs ? "#22c55e" : "#f59e0b" },
      { k: "No-new-privileges", v: insp?.container.noNewPrivileges ? "true" : "false", color: insp?.container.noNewPrivileges ? "#22c55e" : "#f59e0b" },
    ]},
    { label: "Network", rows: [
      { k: "Network mode", v: insp?.container.networkMode || "\u2014", color: insp?.container.networkMode === "host" ? "#f59e0b" : undefined },
    ]},
    ...(insp?.container.envVars?.length ? [{
      label: "Environment", rows: insp.container.envVars.map((e) => ({
        k: e.key, v: e.value, color: /relaxed|lab|debug/i.test(e.value) ? "#ef4444" : undefined,
      })),
    }] : []),
  ],
  process: (st, insp, data) => [
    { label: "Process", rows: [
      { k: "PID", v: "1", color: "#f59e0b" },
      { k: "Go version", v: insp?.process.goVersion || "\u2014" },
      { k: "Goroutines", v: String(st?.runtime.goroutines ?? 0) },
      { k: "Heap alloc", v: `${(st?.runtime.heapAllocMB ?? 0).toFixed(1)} MB` },
      { k: "Heap sys", v: `${(st?.runtime.heapSysMB ?? 0).toFixed(1)} MB` },
      { k: "GC pause avg", v: `${(st?.runtime.gcPauseMsAvg ?? 0).toFixed(2)} ms` },
    ]},
    { label: "Configuration", rows: [
      { k: "Build", v: data.health?.build || "\u2014", color: "#f59e0b" },
      { k: "Node ID", v: insp?.container.id || st?.container.id || "\u2014" },
    ]},
    { label: "Active Sessions", rows: [
      { k: "Total sessions", v: String(data.flows.length), color: "#a855f7" },
    ]},
    { label: "File Descriptors", rows: [
      { k: "Open FDs", v: String(insp?.process.fdCount ?? 0) },
      { k: "FD limit (soft)", v: String(insp?.process.fdSoftLimit ?? 0), color: (insp?.process.fdSoftLimit ?? 0) <= 1024 ? "#f59e0b" : undefined },
      { k: "FD limit (hard)", v: String(insp?.process.fdHardLimit ?? 0) },
    ]},
  ],
};

function hasLabEnv(envVars: { key: string; value: string }[]): boolean {
  return envVars.some((e) => /lab|debug/i.test(e.value));
}

function parseUptimeMs(raw: string): number {
  if (!raw) return 0;
  let ms = 0;
  const h = raw.match(/(\d+)h/);
  const m = raw.match(/(\d+)m/);
  const sec = raw.match(/(\d+(?:\.\d+)?)s/);
  if (h) ms += parseInt(h[1]) * 3600000;
  if (m) ms += parseInt(m[1]) * 60000;
  if (sec) ms += parseFloat(sec[1]) * 1000;
  return ms;
}
