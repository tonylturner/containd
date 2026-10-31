"use client";

import { useAsyncRefresh } from "../../hooks/useAsyncRefresh";

import { useCallback, useMemo, useRef, useState } from "react";
import { useConfigRefresh } from "../../lib/use-config-refresh";
import { useToast } from "../../components/ToastProvider";
import { api, Conduit, ConduitMap } from "../../lib/api";
import { type ZoneView, MAX_SL, mapZone, scoreZone, slColor } from "../../lib/security-scoring";
import { summarizeTargets, targetSummaryText } from "./security-summary";
import s from "./security.module.css";
import ts from "./topology.module.css";

const MAX_ZONES = 6;

/* ════════════════════════════════════════════════════════════════════
   MAIN COMPONENT
   ════════════════════════════════════════════════════════════════════ */

export default function SecurityView() {
  const toast = useToast();
  const zoneNames = useRef(new Map<string, string>());
  const [allZones, setAllZones] = useState<ZoneView[]>([]);
  const [conduits, setConduits] = useState<ConduitMap>({});
  const [activeIds, setActiveIds] = useState<string[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [panelOpen, setPanelOpen] = useState(true);
  const [zoom, setZoom] = useState(1);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const searchRef = useRef<HTMLInputElement>(null);

  const { initialLoading: loading, loading: refreshing, refresh: fetchData } = useAsyncRefresh(useCallback(async () => {
    try {
      const [zones, conds] = await Promise.all([
        api.listZones(),
        api.getSecurityConduits(),
      ]);
      setError(null);
      if (!zones || !conds) throw new Error("Failed to load security data");
      zoneNames.current = new Map(zones.map((z) => [mapZone(z).id, z.name]));
      const zv = zones.map(mapZone);
      setAllZones(zv);
      setConduits((conds as ConduitMap) || {});
      setActiveIds((prev) => prev.length ? prev : zv.slice(0, Math.min(MAX_ZONES, zv.length)).map((z) => z.id));
    } catch (e) {
      setError(String(e));
    }
  }, []));

  useConfigRefresh(fetchData);

  const activeZones = useMemo(() => allZones.filter((z) => activeIds.includes(z.id)), [allZones, activeIds]);
  const targets = useMemo(() => summarizeTargets(allZones, conduits), [allZones, conduits]);

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

  // Candidate zone mutations must succeed before the view changes.
  const setSLTarget = useCallback(async (zoneId: string, lvl: number) => {
    const name = zoneNames.current.get(zoneId);
    if (!name) return;
    const result = await api.updateZone(name, { slTarget: lvl });
    if (!result.ok) { toast(result.error || "Failed to stage zone target", "error"); return; }
    toast("Zone target staged — commit to apply.", "success");
    await fetchData();
  }, [fetchData, toast]);

  const toggleOverride = useCallback(async (zoneId: string, srId: string, newVal: boolean) => {
    const zone = allZones.find((z) => z.id === zoneId);
    const name = zoneNames.current.get(zoneId);
    if (!zone || !name) return;
    const ov = { ...zone.overrides };
    if (Object.prototype.hasOwnProperty.call(ov, srId)) delete ov[srId];
    else ov[srId] = newVal;
    const result = await api.updateZone(name, { slOverrides: ov });
    if (!result.ok) { toast(result.error || "Failed to stage zone override", "error"); return; }
    toast("Zone override staged — commit to apply.", "success");
    await fetchData();
  }, [allZones, fetchData, toast]);

  // ── Cell selection ──
  const selectCell = useCallback((key: string) => {
    setSelected(key);
    setPanelOpen(true);
  }, []);

  const zoomIn = () => setZoom((z) => Math.min(2, +(z + 0.1).toFixed(1)));
  const zoomOut = () => setZoom((z) => Math.max(0.5, +(z - 0.1).toFixed(1)));
  const zoomReset = () => setZoom(1);

  if (loading) {
    return (
      <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100%", fontFamily: "var(--mono)", fontSize: 10, color: "var(--text-dim)" }}>
        Loading security matrix...
      </div>
    );
  }

  if (error && !refreshing) {
    return (
      <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", height: "100%", gap: 12 }}>
        <div style={{ fontFamily: "var(--mono)", fontSize: 10, color: "var(--topo-red)" }}>{error}</div>
        <button onClick={fetchData} style={{ fontFamily: "var(--mono)", fontSize: 9, padding: "4px 12px", border: "1px solid var(--topo-border)", background: "transparent", color: "var(--amber)", cursor: "pointer" }}>Retry</button>
      </div>
    );
  }

  const selectedConduit = selected ? conduits[selected] : null;
  const selectedFrom = selected ? allZones.find((z) => z.id === selected.split("\u2192")[0]) : null;
  const selectedTo = selected ? allZones.find((z) => z.id === selected.split("\u2192")[1]) : null;

  return (
    <div className={ts.workspace} style={{ gridTemplateColumns: panelOpen ? "1fr 320px" : "1fr" }}>
      <div className={s.matrixPane}>
        <div className={s.matrixHeader}>
          <div className={s.matrixTitle}>ZONE &middot; CONDUIT MATRIX</div>
          <div className={s.matrixSubtitle}>Zone targets are candidate settings; conduit observations are live. Each cell is a conduit &mdash; click to inspect policy, IDS coverage, and IEC 62443 SR requirement checks. Check-based SL / SL-T shown on zone headers. Automated checks tag requirements from observed policy; not a standards assessment.</div>
          <div role="status" aria-label="Zones below target" className={s.targetSummary}>
            <span style={{ color: targets.below.length > 0 ? "var(--amber)" : targets.total > 0 ? "var(--topo-green)" : "var(--text-dim)" }}>{targetSummaryText(targets)}</span>
            {targets.below.map((z) => (
              <span key={z.id} className={s.targetGap} style={{ color: slColor(z.sl_a, z.sl_t) }}>{z.name} SL{z.sl_a}/{z.sl_t}</span>
            ))}
          </div>
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
          <div className={s.gridWrap} style={{ transform: `scale(${zoom})`, transformOrigin: "top left", transition: "transform .15s" }}>
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
                      <div className={s.rowZoneSub} style={{ color: sc }}>SL checks:{fa} / SL-T:{fromZ.sl_t}</div>
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
          <div className={s.legendItem}><span style={{ fontFamily: "var(--mono)", fontSize: 8, color: "var(--amber)" }}>SL/T</span> = check-based / target</div>
        </div>
        {!panelOpen && <button className={ts.panelToggle} onClick={() => setPanelOpen(true)} title="Show detail panel">&#x25C0;</button>}
        <div className={ts.zoomControls}>
          <button className={ts.zoomBtn} onClick={zoomIn} title="Zoom in">+</button>
          <div className={ts.zoomLevel} onClick={zoomReset} style={{ cursor: "pointer" }}>{Math.round(zoom * 100)}%</div>
          <button className={ts.zoomBtn} onClick={zoomOut} title="Zoom out">&minus;</button>
        </div>
      </div>

      {/* Detail panel */}
      {panelOpen && (
        <div className={ts.detailPanel}>
          <div className={ts.panelHeader}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, flex: 1, minWidth: 0 }}>
              <span className={ts.panelTitle} style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{selectedFrom && selectedTo ? `${selectedFrom.name} \u2192 ${selectedTo.name}` : "SELECT A CELL"}</span>
              {selectedConduit && (
                <span style={{
                  fontFamily: "var(--mono)", fontSize: 8, padding: "2px 7px", borderRadius: 1, flexShrink: 0,
                  background: selectedConduit.state === "allow" ? "#14532d" : selectedConduit.state === "block" ? "#7f1d1d" : selectedConduit.state === "partial" ? "#78490a" : "#1f2937",
                  color: selectedConduit.state === "allow" ? "#22c55e" : selectedConduit.state === "block" ? "#ef4444" : selectedConduit.state === "partial" ? "#f59e0b" : "#6b7280",
                }}>{selectedConduit.state.toUpperCase()}</span>
              )}
              {!selectedConduit && <span style={{ fontFamily: "var(--mono)", fontSize: 8, padding: "2px 7px", borderRadius: 1, background: "#78490a", color: "#f59e0b", flexShrink: 0 }}>IEC 62443</span>}
            </div>
            <button className={ts.panelClose} onClick={() => setPanelOpen(false)}>&#x25B6;</button>
          </div>
          <div className={ts.panelBody}>
            {selectedConduit && selectedFrom && selectedTo ? (
              <PanelContent conduit={selectedConduit} fromZ={selectedFrom} toZ={selectedTo} conduits={conduits} setSLTarget={setSLTarget} toggleOverride={toggleOverride} />
            ) : (
              <div className={s.empty}>
                <div className={s.emptyIcon}>&#x2B21;</div>
                <div className={s.emptyText}>Click any conduit cell to inspect its policy, IDS coverage, and IEC 62443 SR requirement checks.<br /><br />SL-T is editable per zone. SR checks are automated but can be manually overridden.</div>
              </div>
            )}
          </div>
        </div>
      )}
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
      {conduit.proto?.length > 0 && (
        <div className={s.ps}>
          <div className={s.psLabel}>Protocols</div>
          <div className={s.protoRow}>
            {conduit.proto.map((p, i) => (
              <span key={i} className={`${s.proto} ${p.t === "allowed" ? s.protoAllowed : p.t === "denied" ? s.protoDenied : s.protoInspect}`}>{p.n}</span>
            ))}
          </div>
        </div>
      )}

      {/* Rules */}
      {conduit.rules?.length > 0 && (
        <div className={s.ps}>
          <div className={s.psLabel}>Rules</div>
          {conduit.rules.map((r, i) => (
            <div key={i} className={s.dr}><span className={s.dk}>&middot;</span><span className={s.dv} style={{ color: "var(--text-mid)", textAlign: "left", paddingLeft: 6, flex: 1 }}>{r}</span></div>
          ))}
        </div>
      )}

      {/* Gaps */}
      {conduit.gaps?.length > 0 && (
        <div className={s.ps}>
          <div className={s.psLabel}>Gaps ({conduit.gaps.length})</div>
          {conduit.gaps.map((g, i) => <div key={i} className={s.gapItem}>{g}</div>)}
        </div>
      )}

      {/* MITRE */}
      {conduit.mitre?.length > 0 && (
        <div className={s.ps}>
          <div className={s.psLabel}>MITRE Vectors</div>
          {conduit.mitre.map((m, i) => <div key={i} className={s.mitreItem}>{m}</div>)}
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
          {Array.from({ length: MAX_SL + 1 }, (_, lvl) => (
            <button key={lvl} aria-label={`Stage ${zone.name} target SL ${lvl}`} className={`${s.slPipBtn} ${lvl === zone.sl_t ? s.slPipSelected : lvl < zone.sl_t ? s.slPipBelow : ""}`} onClick={() => setSLTarget(zone.id, lvl)}>{lvl}</button>
          ))}
        </div>
        <div style={{ fontFamily: "var(--mono)", fontSize: 7, color: "var(--text-dim)", marginTop: 4 }}>
          Equivalent to <span style={{ color: "var(--topo-cyan)" }}>sl_target: {zone.sl_t}</span> in zone config
        </div>
      </div>
      <div className={s.slAchievedBadge}>
        <div>
          <div style={{ fontFamily: "var(--mono)", fontSize: 7, color: "var(--text-dim)", letterSpacing: 1, marginBottom: 2 }}>CHECK-BASED SL</div>
          <div className={s.slAchievedVal} style={{ color: sc }}>SL-{sl_a}</div>
        </div>
        <div style={{ flex: 1, paddingLeft: 10 }}>
          <div style={{ fontFamily: "var(--mono)", fontSize: 8, color: "var(--text-mid)" }}>
            {sl_a >= zone.sl_t ? `SL-${zone.sl_t} target checks pass` : `Unmet checks for SL-${zone.sl_t}; check-based SL-${sl_a}`}
          </div>
          <div style={{ fontFamily: "var(--mono)", fontSize: 7, color: "var(--text-dim)", marginTop: 2 }}>{blocking} unmet SR check{blocking !== 1 ? "s" : ""} for target</div>
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
                <span className={s.srSource}>{c.source} &middot; {c.overridden ? "manually overridden" : "automated check"}</span>
              </div>
              <div className={s.srRight}>
                <span className={`${s.srStatus} ${c.overridden ? s.srManual : c.met ? s.srMet : s.srNotMet}`}>
                  {c.overridden ? "OVERRIDE" : c.met ? "CHECK PASS" : "CHECK FAIL"}
                </span>
                <button className={`${s.srOverrideBtn} ${c.overridden ? s.srOverrideBtnActive : ""}`} onClick={() => toggleOverride(zone.id, c.id, !c.met)}>
                  {c.overridden ? "REVERT" : c.met ? "MARK FAIL" : "MARK PASS"}
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
