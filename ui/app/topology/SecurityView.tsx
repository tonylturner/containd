"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, Zone, Conduit, ConduitMap } from "../../lib/api";
import s from "./security.module.css";
import ts from "./topology.module.css";

/* ════════════════════════════════════════════════════════════════════
   IEC 62443-3-3 SR DEFINITIONS — DO NOT MODIFY SCORING LOGIC
   ════════════════════════════════════════════════════════════════════ */

interface SRDef {
  id: string;
  sl: number;
  label: string;
  source: "zone" | "conduit";
  check: (z: ZoneView, cs: Conduit[]) => boolean;
}

const SR_DEFS: SRDef[] = [
  { id: "SR-1.1",  sl: 1, label: "Human interface identification & authentication",          source: "zone",    check: (z) => z.id !== "internet" },
  { id: "SR-3.3",  sl: 1, label: "Security functionality verification",                       source: "zone",    check: () => true },
  { id: "SR-5.1",  sl: 1, label: "Network segmentation — zone has explicit policy",           source: "zone",    check: (_, cs) => cs.some((c) => c.defaultDeny || c.state === "block") },
  { id: "SR-2.8",  sl: 1, label: "Auditable events — conduit traffic logged",                  source: "conduit", check: (_, cs) => cs.every((c) => c.auditLogged) },
  { id: "SR-1.2",  sl: 2, label: "Software process & device identification (IDS)",             source: "conduit", check: (_, cs) => cs.filter((c) => c.state !== "block").every((c) => c.ids === "full" || c.ids === "partial") },
  { id: "SR-3.1",  sl: 2, label: "Communication integrity — TLS on active conduits",           source: "conduit", check: (_, cs) => cs.filter((c) => c.state === "allow" || c.state === "partial").every((c) => c.tlsEnforced) },
  { id: "SR-5.2",  sl: 2, label: "Zone boundary protection — explicit default deny",           source: "zone",    check: (_, cs) => cs.some((c) => c.defaultDeny) },
  { id: "SR-5.4",  sl: 2, label: "Application partitioning — protocol whitelisting",           source: "conduit", check: (_, cs) => cs.filter((c) => c.state !== "block").every((c) => c.protoWhitelist) },
  { id: "SR-1.13", sl: 3, label: "Access via untrusted networks requires MFA",                 source: "conduit", check: (_, cs) => cs.filter((c) => c.state !== "block").every((c) => c.mfaRequired) },
  { id: "SR-2.12", sl: 3, label: "Non-repudiation — signed/tamper-evident audit log",          source: "zone",    check: () => false },
  { id: "SR-3.2",  sl: 3, label: "Malicious code protection — AV scanning on conduit",         source: "conduit", check: (_, cs) => cs.filter((c) => c.state !== "block").every((c) => c.avEnabled) },
  { id: "SR-5.4b", sl: 3, label: "Full DPI + protocol whitelist on all active conduits",       source: "conduit", check: (_, cs) => cs.filter((c) => c.state !== "block").every((c) => c.protoWhitelist && c.ids === "full") },
];

/* ════════════════════════════════════════════════════════════════════
   TYPES
   ════════════════════════════════════════════════════════════════════ */

interface ZoneView {
  id: string;
  name: string;
  sl_t: number;
  color: string;
  hosts: number;
  consequence: string;
  overrides: Record<string, boolean>;
}

interface SRCheck extends SRDef {
  met: boolean;
  auto: boolean;
  overridden: boolean;
}

/* ════════════════════════════════════════════════════════════════════
   HELPERS
   ════════════════════════════════════════════════════════════════════ */

const ZONE_COLORS: Record<string, string> = {
  internet: "#6b7280", wan: "#ef4444", dmz: "#f97316",
  lan: "#f59e0b", mgmt: "#22c55e", enclave: "#a855f7",
  corp: "#f59e0b", ot: "#a855f7", scada: "#a855f7",
};

function zoneColor(name: string): string {
  const lower = name.toLowerCase();
  for (const [k, v] of Object.entries(ZONE_COLORS)) {
    if (lower.includes(k)) return v;
  }
  // Cycle through colors based on hash
  const colors = ["#06b6d4", "#a855f7", "#f59e0b", "#22c55e", "#ef4444", "#f97316"];
  let h = 0;
  for (let i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) | 0;
  return colors[Math.abs(h) % colors.length];
}

function mapZone(z: Zone): ZoneView {
  return {
    id: z.name.toLowerCase().replace(/[^a-z0-9]+/g, "_"),
    name: z.name.toUpperCase(),
    sl_t: z.slTarget ?? 0,
    color: zoneColor(z.name),
    hosts: 0,
    consequence: z.consequence || "",
    overrides: z.slOverrides || {},
  };
}

function scoreZone(zone: ZoneView, conduits: ConduitMap): { sl_a: number; checks: SRCheck[] } {
  const cs = Object.entries(conduits)
    .filter(([k]) => k.startsWith(zone.id + "\u2192"))
    .map(([, v]) => v);
  const checks: SRCheck[] = SR_DEFS.map((sr) => {
    const auto = sr.check(zone, cs);
    const overridden = zone.overrides.hasOwnProperty(sr.id);
    const met = overridden ? zone.overrides[sr.id] : auto;
    return { ...sr, met, auto, overridden };
  });
  let sl_a = 0;
  for (let lvl = 1; lvl <= 3; lvl++) {
    if (checks.filter((c) => c.sl <= lvl).every((c) => c.met)) sl_a = lvl;
    else break;
  }
  return { sl_a, checks };
}

function slColor(sl_a: number, sl_t: number): string {
  return sl_a >= sl_t ? "var(--topo-green)" : sl_a === sl_t - 1 ? "var(--amber)" : "var(--topo-red)";
}

const MAX_ZONES = 6;

/* ════════════════════════════════════════════════════════════════════
   MAIN COMPONENT
   ════════════════════════════════════════════════════════════════════ */

export default function SecurityView() {
  const [allZones, setAllZones] = useState<ZoneView[]>([]);
  const [conduits, setConduits] = useState<ConduitMap>({});
  const [activeIds, setActiveIds] = useState<string[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const searchRef = useRef<HTMLInputElement>(null);

  const fetchData = useCallback(async () => {
    try {
      setError(null);
      const [zones, conds] = await Promise.all([
        api.listZones(),
        api.getSecurityConduits(),
      ]);
      const zv = ((zones as Zone[]) || []).map(mapZone);
      setAllZones(zv);
      setConduits((conds as ConduitMap) || {});
      setActiveIds((prev) => prev.length ? prev : zv.slice(0, Math.min(MAX_ZONES, zv.length)).map((z) => z.id));
      setLoading(false);
    } catch (e) {
      setError(String(e));
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);

  const activeZones = useMemo(() => allZones.filter((z) => activeIds.includes(z.id)), [allZones, activeIds]);

  // Gap count across ALL zones
  const gapCount = useMemo(() => {
    let g = 0;
    allZones.forEach((z) => { const { sl_a } = scoreZone(z, conduits); if (sl_a < z.sl_t) g++; });
    return g;
  }, [allZones, conduits]);

  // ── Zone selector ──
  const addZone = useCallback((id: string) => {
    setActiveIds((prev) => {
      if (prev.includes(id) || prev.length >= MAX_ZONES) return prev;
      return [...prev, id];
    });
    setDropdownOpen(false);
    setSearchQuery("");
  }, []);

  const removeZone = useCallback((id: string) => {
    setActiveIds((prev) => {
      if (prev.length <= 1) return prev;
      const next = prev.filter((z) => z !== id);
      return next;
    });
    setSelected((prev) => {
      if (!prev) return prev;
      const [fi, ti] = prev.split("\u2192");
      if (fi === id || ti === id) return null;
      return prev;
    });
  }, []);

  const candidates = useMemo(() => {
    const q = searchQuery.toLowerCase().trim();
    return allZones.filter((z) => !activeIds.includes(z.id) && (q === "" || z.name.toLowerCase().includes(q) || z.id.includes(q)));
  }, [allZones, activeIds, searchQuery]);

  // ── SL-T editor ──
  const setSLTarget = useCallback((zoneId: string, lvl: number) => {
    setAllZones((prev) => prev.map((z) => z.id === zoneId ? { ...z, sl_t: lvl } : z));
    // Fire-and-forget PATCH
    const zone = allZones.find((z) => z.id === zoneId);
    if (zone) {
      const origName = zone.name.charAt(0) + zone.name.slice(1).toLowerCase();
      api.updateZone(origName, { slTarget: lvl }).catch(() => {});
    }
  }, [allZones]);

  // ── SR override ──
  const toggleOverride = useCallback((zoneId: string, srId: string, newVal: boolean) => {
    setAllZones((prev) => prev.map((z) => {
      if (z.id !== zoneId) return z;
      const ov = { ...z.overrides };
      if (ov.hasOwnProperty(srId)) delete ov[srId];
      else ov[srId] = newVal;
      return { ...z, overrides: ov };
    }));
    // Fire-and-forget PATCH
    const zone = allZones.find((z) => z.id === zoneId);
    if (zone) {
      const ov = { ...zone.overrides };
      if (ov.hasOwnProperty(srId)) delete ov[srId];
      else ov[srId] = newVal;
      const origName = zone.name.charAt(0) + zone.name.slice(1).toLowerCase();
      api.updateZone(origName, { slOverrides: ov }).catch(() => {});
    }
  }, [allZones]);

  // ── Cell selection ──
  const selectCell = useCallback((key: string) => {
    setSelected(key);
  }, []);

  if (loading) {
    return (
      <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100%", fontFamily: "var(--mono)", fontSize: 10, color: "var(--text-dim)" }}>
        Loading security matrix...
      </div>
    );
  }

  if (error) {
    return (
      <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", height: "100%", gap: 12 }}>
        <div style={{ fontFamily: "var(--mono)", fontSize: 10, color: "var(--topo-red)" }}>Failed to load security data</div>
        <button onClick={fetchData} style={{ fontFamily: "var(--mono)", fontSize: 9, padding: "4px 12px", border: "1px solid var(--topo-border)", background: "transparent", color: "var(--amber)", cursor: "pointer" }}>Retry</button>
      </div>
    );
  }

  const selectedConduit = selected ? conduits[selected] : null;
  const selectedFrom = selected ? allZones.find((z) => z.id === selected.split("\u2192")[0]) : null;
  const selectedTo = selected ? allZones.find((z) => z.id === selected.split("\u2192")[1]) : null;

  return (
    <div className={ts.workspace} style={{ gridTemplateColumns: "1fr 320px" }}>
      <div className={s.matrixPane}>
        <div className={s.matrixHeader}>
          <div className={s.matrixTitle}>ZONE &middot; CONDUIT MATRIX</div>
          <div className={s.matrixSubtitle}>Each cell is a conduit &mdash; click to inspect policy, IDS coverage, and IEC 62443 SR compliance. SL-A/T shown on zone headers.</div>
        </div>

        {/* Zone selector bar */}
        <div className={s.zoneSelectorBar}>
          <span className={s.zoneSelectorLabel}>Zones</span>
          <div className={s.zoneChips}>
            {activeIds.map((id) => {
              const z = allZones.find((zz) => zz.id === id);
              if (!z) return null;
              const { sl_a } = scoreZone(z, conduits);
              const sc = slColor(sl_a, z.sl_t);
              return (
                <div key={id} className={s.zoneChip} style={{ borderColor: z.color + "60", background: z.color + "12" }}>
                  <div className={s.zoneChipDot} style={{ background: z.color }} />
                  <span className={s.zoneChipName} style={{ color: z.color }}>{z.name}</span>
                  <span style={{ fontFamily: "var(--mono)", fontSize: 7, color: sc, marginLeft: 3 }}>SL{sl_a}/{z.sl_t}</span>
                  {activeIds.length > 1 && (
                    <span className={s.zoneChipRemove} onClick={() => removeZone(id)} title="Remove">&times;</span>
                  )}
                </div>
              );
            })}
          </div>
          <div className={s.zoneSearchWrap}>
            <input
              ref={searchRef}
              className={s.zoneSearch}
              placeholder="+ Add zone..."
              value={searchQuery}
              onChange={(e) => { setSearchQuery(e.target.value); setDropdownOpen(true); }}
              onFocus={() => setDropdownOpen(true)}
              onBlur={() => setTimeout(() => setDropdownOpen(false), 150)}
              onKeyDown={(e) => { if (e.key === "Escape") { setDropdownOpen(false); searchRef.current?.blur(); } }}
              disabled={activeIds.length >= MAX_ZONES}
            />
            {dropdownOpen && (
              <div className={s.zoneDropdown}>
                {candidates.length === 0 ? (
                  <div style={{ padding: "8px 12px", fontFamily: "var(--mono)", fontSize: 8, color: "var(--text-dim)" }}>No matching zones</div>
                ) : candidates.map((z) => {
                  const { sl_a } = scoreZone(z, conduits);
                  const sc = slColor(sl_a, z.sl_t);
                  return (
                    <div key={z.id} className={`${s.zoneDropdownItem} ${activeIds.length >= MAX_ZONES ? s.zoneDropdownItemDisabled : ""}`} onMouseDown={() => addZone(z.id)}>
                      <div className={s.zoneDropdownDot} style={{ background: z.color }} />
                      <span className={s.zoneDropdownName} style={{ color: z.color }}>{z.name}</span>
                      <span className={s.zoneDropdownSl} style={{ color: sc }}>SL{sl_a}/{z.sl_t}</span>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
          <span className={s.zoneLimitNote}>
            {activeIds.length >= MAX_ZONES ? "max zones reached" : `${MAX_ZONES - activeIds.length} slot${MAX_ZONES - activeIds.length !== 1 ? "s" : ""} remaining`}
          </span>
        </div>

        {/* Matrix grid */}
        <div className={s.matrixScroll}>
          <div className={s.gridWrap}>
            {/* Column headers */}
            <div className={s.gridColHeaders}>
              {activeZones.map((z) => {
                const { sl_a } = scoreZone(z, conduits);
                const sc = slColor(sl_a, z.sl_t);
                return (
                  <div key={z.id} className={s.colHeader}>
                    <div className={s.colZoneDot} style={{ background: z.color, boxShadow: `0 0 6px ${z.color}60` }} />
                    <div className={s.colZoneName} style={{ color: z.color }}>{z.name}</div>
                    <div className={s.colSl} style={{ color: sc }}>SL{sl_a}/{z.sl_t}</div>
                  </div>
                );
              })}
            </div>

            {/* Rows */}
            {activeZones.map((fromZ, ri) => {
              const { sl_a: fa } = scoreZone(fromZ, conduits);
              const sc = slColor(fa, fromZ.sl_t);
              return (
                <div key={fromZ.id} className={s.gridRow}>
                  <div className={s.rowHeader}>
                    <div className={s.rowZoneInfo}>
                      <div className={s.rowZoneName} style={{ color: fromZ.color }}>{fromZ.name}</div>
                      <div className={s.rowZoneSub} style={{ color: sc }}>SL-A:{fa} / SL-T:{fromZ.sl_t}</div>
                    </div>
                    <div className={s.rowZoneDot} style={{ background: fromZ.color, boxShadow: `0 0 5px ${fromZ.color}60` }} />
                  </div>
                  {activeZones.map((toZ, ci) => {
                    if (fromZ.id === toZ.id) {
                      return (
                        <div key={toZ.id} className={`${s.cell} ${s.cellDiag}`} style={{ animationDelay: `${ri * 0.04 + ci * 0.02}s` }}>
                          <div className={s.cellAccent} />
                          <div className={s.cellBody}>
                            <span style={{ fontFamily: "var(--display)", fontSize: 7, color: "var(--text-dim)", letterSpacing: 1 }}>{fromZ.name.slice(0, 4)}</span>
                          </div>
                        </div>
                      );
                    }
                    const key = `${fromZ.id}\u2192${toZ.id}`;
                    const cd = conduits[key];
                    const isSelected = selected === key;
                    if (!cd) {
                      return (
                        <div key={toZ.id} className={`${s.cell} ${s.cellUnmodeled} ${isSelected ? s.cellSelected : ""}`} style={{ animationDelay: `${ri * 0.04 + ci * 0.02}s` }} onClick={() => selectCell(key)}>
                          <div className={s.cellAccent} />
                          <div className={s.cellBody}><div className={s.cellState}>&mdash;</div></div>
                        </div>
                      );
                    }
                    const stateCls = cd.state === "allow" ? s.cellAllow : cd.state === "block" ? s.cellBlock : cd.state === "partial" ? s.cellPartial : s.cellUnmodeled;
                    const idsClass = cd.ids === "full" ? s.idsFull : cd.ids === "partial" ? s.idsPartial : s.idsNone;
                    const idsText = cd.ids === "full" ? "IDS" : cd.ids === "partial" ? "~IDS" : "NO IDS";
                    const volColor = cd.state === "allow" ? "#22c55e" : cd.state === "partial" ? "#f59e0b" : "#374151";
                    const proto = cd.proto || [];
                    const gaps = cd.gaps || [];
                    const topProtos = proto.slice(0, 2).map((p) => p.n).join(" \u00b7 ") || "\u2014";
                    return (
                      <div key={toZ.id} className={`${s.cell} ${stateCls} ${isSelected ? s.cellSelected : ""}`} style={{ animationDelay: `${ri * 0.04 + ci * 0.02}s` }} onClick={() => selectCell(key)}>
                        <div className={s.cellAccent} />
                        {gaps.length > 0 && <div className={s.cellFindings}><div className={s.findingDot} style={{ background: "var(--amber)" }} /></div>}
                        <div className={s.cellBody}>
                          <div className={s.cellState}>{cd.state === "unmodeled" ? "NONE" : cd.state.toUpperCase()}</div>
                          <div className={s.cellProto}>{topProtos}</div>
                        </div>
                        <div className={`${s.cellIds} ${idsClass}`}>{idsText}</div>
                        <div className={s.cellTraffic} style={{ background: volColor, opacity: 0.15 + cd.traffic * 0.5 }} />
                      </div>
                    );
                  })}
                </div>
              );
            })}
          </div>
        </div>

        {/* Legend */}
        <div className={s.legend}>
          <div className={s.legendItem}><div className={s.lSwatch} style={{ background: "rgba(34,197,94,0.12)", borderColor: "rgba(34,197,94,0.4)" }} />Allow</div>
          <div className={s.legendItem}><div className={s.lSwatch} style={{ background: "rgba(239,68,68,0.1)", borderColor: "rgba(239,68,68,0.4)" }} />Block</div>
          <div className={s.legendItem}><div className={s.lSwatch} style={{ background: "rgba(245,158,11,0.1)", borderColor: "rgba(245,158,11,0.4)" }} />Partial</div>
          <div className={s.legendItem}><div className={s.lSwatch} style={{ background: "rgba(107,114,128,0.08)", borderColor: "rgba(107,114,128,0.3)" }} />Unmodeled</div>
          <div style={{ width: 1, height: 12, background: "var(--topo-border)", margin: "0 4px" }} />
          <div className={s.legendItem}><div className={s.lDot} style={{ background: "var(--topo-green)" }} />IDS full</div>
          <div className={s.legendItem}><div className={s.lDot} style={{ background: "var(--amber)" }} />IDS partial</div>
          <div className={s.legendItem}><div className={s.lDot} style={{ background: "var(--topo-red)" }} />No IDS</div>
          <div style={{ width: 1, height: 12, background: "var(--topo-border)", margin: "0 4px" }} />
          <div className={s.legendItem}><span style={{ fontFamily: "var(--mono)", fontSize: 8, color: "var(--amber)" }}>SL-A/T</span> = achieved / target</div>
        </div>
      </div>

      {/* Detail panel */}
      <div className={ts.detailPanel}>
        <div className={ts.panelHeader}>
          <span className={ts.panelTitle}>{selectedFrom && selectedTo ? `${selectedFrom.name} \u2192 ${selectedTo.name}` : "SELECT A CELL"}</span>
          {selectedConduit && (
            <span style={{
              fontFamily: "var(--mono)", fontSize: 8, padding: "2px 7px", borderRadius: 1,
              background: selectedConduit.state === "allow" ? "#14532d" : selectedConduit.state === "block" ? "#7f1d1d" : selectedConduit.state === "partial" ? "#78490a" : "#1f2937",
              color: selectedConduit.state === "allow" ? "#22c55e" : selectedConduit.state === "block" ? "#ef4444" : selectedConduit.state === "partial" ? "#f59e0b" : "#6b7280",
            }}>{selectedConduit.state.toUpperCase()}</span>
          )}
          {!selectedConduit && <span style={{ fontFamily: "var(--mono)", fontSize: 8, padding: "2px 7px", borderRadius: 1, background: "#78490a", color: "#f59e0b" }}>IEC 62443</span>}
        </div>
        <div className={ts.panelBody}>
          {selectedConduit && selectedFrom && selectedTo ? (
            <PanelContent conduit={selectedConduit} fromZ={selectedFrom} toZ={selectedTo} conduits={conduits} setSLTarget={setSLTarget} toggleOverride={toggleOverride} />
          ) : (
            <div className={s.empty}>
              <div className={s.emptyIcon}>&#x2B21;</div>
              <div className={s.emptyText}>Click any conduit cell to inspect its policy, IDS coverage, and IEC 62443 SR compliance.<br /><br />SL-T is editable per zone. SR checks are auto-computed but can be manually overridden.</div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

/* ════════════════════════════════════════════════════════════════════
   PANEL CONTENT
   ════════════════════════════════════════════════════════════════════ */

function PanelContent({ conduit, fromZ, toZ, conduits, setSLTarget, toggleOverride }: {
  conduit: Conduit;
  fromZ: ZoneView;
  toZ: ZoneView;
  conduits: ConduitMap;
  setSLTarget: (zoneId: string, lvl: number) => void;
  toggleOverride: (zoneId: string, srId: string, newVal: boolean) => void;
}) {
  const idsLabel: Record<string, string> = { full: "Full coverage", partial: "Partial", none: "None" };
  const idsColor: Record<string, string> = { full: "var(--topo-green)", partial: "var(--amber)", none: "var(--topo-red)" };

  return (
    <>
      {/* Conduit info */}
      <div className={s.ps}>
        <div className={s.psLabel}>Conduit</div>
        <DR k="From" v={fromZ.name} vc={fromZ.color} />
        <DR k="To" v={toZ.name} vc={toZ.color} />
        <DR k="IDS coverage" v={idsLabel[conduit.ids]} vc={idsColor[conduit.ids]} />
        <DR k="Traffic" v={`${Math.round(conduit.traffic * 100)}% of baseline`} />
      </div>

      {/* Source zone SL */}
      <SLSection zone={fromZ} label="Source zone" conduits={conduits} setSLTarget={setSLTarget} toggleOverride={toggleOverride} />

      {/* Dest zone SL */}
      <SLSection zone={toZ} label="Destination zone" conduits={conduits} setSLTarget={setSLTarget} toggleOverride={toggleOverride} />

      {/* Protocols */}
      {(conduit.proto || []).length > 0 && (
        <div className={s.ps}>
          <div className={s.psLabel}>Protocols</div>
          <div className={s.protoRow}>
            {(conduit.proto || []).map((p, i) => (
              <span key={i} className={`${s.proto} ${p.t === "allowed" ? s.protoAllowed : p.t === "denied" ? s.protoDenied : s.protoInspect}`}>{p.n}</span>
            ))}
          </div>
        </div>
      )}

      {/* Rules */}
      {(conduit.rules || []).length > 0 && (
        <div className={s.ps}>
          <div className={s.psLabel}>Rules</div>
          {(conduit.rules || []).map((r, i) => (
            <div key={i} className={s.dr}><span className={s.dk}>&middot;</span><span className={s.dv} style={{ color: "var(--text-mid)", textAlign: "left", paddingLeft: 6, flex: 1 }}>{r}</span></div>
          ))}
        </div>
      )}

      {/* Gaps */}
      {(conduit.gaps || []).length > 0 && (
        <div className={s.ps}>
          <div className={s.psLabel}>Gaps ({(conduit.gaps || []).length})</div>
          {(conduit.gaps || []).map((g, i) => <div key={i} className={s.gapItem}>{g}</div>)}
        </div>
      )}

      {/* MITRE */}
      {(conduit.mitre || []).length > 0 && (
        <div className={s.ps}>
          <div className={s.psLabel}>MITRE Vectors</div>
          {(conduit.mitre || []).map((m, i) => <div key={i} className={s.mitreItem}>{m}</div>)}
        </div>
      )}
    </>
  );
}

/* ════════════════════════════════════════════════════════════════════
   SL SECTION — zone scoring + SR rows
   ════════════════════════════════════════════════════════════════════ */

function SLSection({ zone, label, conduits, setSLTarget, toggleOverride }: {
  zone: ZoneView;
  label: string;
  conduits: ConduitMap;
  setSLTarget: (zoneId: string, lvl: number) => void;
  toggleOverride: (zoneId: string, srId: string, newVal: boolean) => void;
}) {
  const { sl_a, checks } = scoreZone(zone, conduits);
  const sc = slColor(sl_a, zone.sl_t);
  const blocking = checks.filter((c) => !c.met && c.sl <= zone.sl_t).length;

  return (
    <div className={s.ps}>
      <div className={s.psLabel}>{label} &mdash; {zone.name}</div>
      <div className={s.dr}>
        <span className={s.dk}>Consequence</span>
        <span className={s.dv} style={{ color: "var(--text-mid)", textAlign: "left", flex: 1, paddingLeft: 8, fontSize: 8 }}>{zone.consequence || "\u2014"}</span>
      </div>
      <div style={{ marginTop: 8 }}>
        <div style={{ fontFamily: "var(--mono)", fontSize: 8, color: "var(--text-dim)", marginBottom: 4, letterSpacing: 1 }}>SL TARGET &mdash; click to set</div>
        <div className={s.slEditor}>
          <span className={s.slEditorLabel}>SL-T</span>
          {[0, 1, 2, 3].map((lvl) => (
            <button key={lvl} className={`${s.slPipBtn} ${lvl === zone.sl_t ? s.slPipSelected : lvl < zone.sl_t ? s.slPipBelow : ""}`} onClick={() => setSLTarget(zone.id, lvl)}>{lvl}</button>
          ))}
        </div>
        <div style={{ fontFamily: "var(--mono)", fontSize: 7, color: "var(--text-dim)", marginTop: 4 }}>
          Equivalent to <span style={{ color: "var(--topo-cyan)" }}>sl_target: {zone.sl_t}</span> in zone config
        </div>
      </div>
      <div className={s.slAchievedBadge}>
        <div>
          <div style={{ fontFamily: "var(--mono)", fontSize: 7, color: "var(--text-dim)", letterSpacing: 1, marginBottom: 2 }}>SL ACHIEVED</div>
          <div className={s.slAchievedVal} style={{ color: sc }}>SL-{sl_a}</div>
        </div>
        <div style={{ flex: 1, paddingLeft: 10 }}>
          <div style={{ fontFamily: "var(--mono)", fontSize: 8, color: "var(--text-mid)" }}>
            {sl_a >= zone.sl_t ? `Meets SL-${zone.sl_t} target` : `Gap: target SL-${zone.sl_t}, achieved SL-${sl_a}`}
          </div>
          <div style={{ fontFamily: "var(--mono)", fontSize: 7, color: "var(--text-dim)", marginTop: 2 }}>{blocking} blocking SR{blocking !== 1 ? "s" : ""} not met</div>
        </div>
      </div>
      <div style={{ marginTop: 10 }}>
        {checks.map((c) => {
          const reqd = c.sl <= zone.sl_t;
          return (
            <div key={c.id} className={s.srRow}>
              <div className={s.srLeft}>
                <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
                  <span className={s.srId}>{c.id}</span>
                  {reqd
                    ? <span style={{ fontFamily: "var(--mono)", fontSize: 7, color: "var(--amber)" }}>REQ SL-{c.sl}</span>
                    : <span style={{ fontFamily: "var(--mono)", fontSize: 7, color: "var(--text-dim)" }}>OPT SL-{c.sl}</span>}
                </div>
                <span className={s.srName}>{c.label}</span>
                <span className={s.srSource}>{c.source} &middot; {c.overridden ? "manually overridden" : "auto-detected"}</span>
              </div>
              <div className={s.srRight}>
                <span className={`${s.srStatus} ${c.overridden ? s.srManual : c.met ? s.srMet : s.srNotMet}`}>
                  {c.overridden ? "OVERRIDE" : c.met ? "MET" : "NOT MET"}
                </span>
                <button className={`${s.srOverrideBtn} ${c.overridden ? s.srOverrideBtnActive : ""}`} onClick={() => toggleOverride(zone.id, c.id, !c.met)}>
                  {c.overridden ? "REVERT" : c.met ? "MARK FAIL" : "MARK MET"}
                </button>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function DR({ k, v, vc }: { k: string; v: string; vc?: string }) {
  return (
    <div className={s.dr}>
      <span className={s.dk}>{k}</span>
      <span className={s.dv} style={vc ? { color: vc } : undefined}>{v}</span>
    </div>
  );
}
