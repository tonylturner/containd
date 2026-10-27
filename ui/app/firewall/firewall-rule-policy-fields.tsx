"use client";

import Link from "next/link";
import { useId, useMemo } from "react";

import { InfoTip } from "../../components/InfoTip";
import type { RuleAction } from "../../lib/api";
import {
  RULE_ACTIONS,
  WEEKDAYS,
  actionInfo,
  type PolicyDraft,
} from "./firewall-rule-policy";

function timezones(): string[] {
  try {
    return Intl.supportedValuesOf("timeZone");
  } catch {
    return [];
  }
}

const label = "block text-[10px] font-medium text-(--text-muted) mb-1";
const check = "h-4 w-4 rounded-sm border-white/20 bg-(--surface)";

/** Action, rate limit, tag, identities and schedule of a rule form. */
export function RulePolicyFields({
  draft,
  onChange,
}: {
  draft: PolicyDraft;
  onChange: (draft: PolicyDraft) => void;
}) {
  const tzList = useId();
  const zones = useMemo(timezones, []);
  const set = (patch: Partial<PolicyDraft>) => onChange({ ...draft, ...patch });
  const info = actionInfo(draft.action);
  const toggleDay = (day: string, on: boolean) =>
    set({ days: on ? [...draft.days, day] : draft.days.filter((d) => d !== day) });

  return (
    <div className="mt-3 space-y-3">
      <div className="grid gap-3 md:grid-cols-4">
        <div>
          <label className={label}>Action</label>
          <select aria-label="Action" value={draft.action} onChange={(e) => set({ action: e.target.value as RuleAction })} className="input-industrial w-full">
            <optgroup label="Decides">
              {RULE_ACTIONS.filter((a) => a.decides).map((a) => <option key={a.value} value={a.value}>{a.value}</option>)}
            </optgroup>
            <optgroup label="Effect (never admits)">
              {RULE_ACTIONS.filter((a) => !a.decides).map((a) => <option key={a.value} value={a.value}>{a.value}</option>)}
            </optgroup>
          </select>
        </div>
        {draft.action === "RATE_LIMIT" && (
          <>
            <div>
              <label className={label}>Packets per second <span className="text-(--text-dim)">(1-1000000)</span></label>
              <input aria-label="Packets per second" inputMode="numeric" value={draft.pps} onChange={(e) => set({ pps: e.target.value })} placeholder="100" className="input-industrial w-full" />
            </div>
            <div>
              <label className={label}>Burst <span className="text-(--text-dim)">(packets; blank = pps)</span></label>
              <input aria-label="Burst" inputMode="numeric" value={draft.burst} onChange={(e) => set({ burst: e.target.value })} placeholder="0" className="input-industrial w-full" />
            </div>
          </>
        )}
        {draft.action === "TAG" && (
          <div>
            <label className={label}>Tag <span className="text-(--text-dim)">(a-z 0-9 _ . -)</span></label>
            <input aria-label="Tag" value={draft.tag} onChange={(e) => set({ tag: e.target.value })} placeholder="eng-access" className="input-industrial w-full" />
          </div>
        )}
        <div className="md:col-span-2">
          <label className={label}>
            Identities <span className="text-(--text-dim)">(labels, comma-separated)</span>
          </label>
          <input aria-label="Identities" value={draft.identities} onChange={(e) => set({ identities: e.target.value })} placeholder="any opener" className="input-industrial w-full" />
        </div>
      </div>
      <p className="text-xs text-(--text-muted)">
        {info.help}
        {draft.identities.trim() !== "" && (
          <>
            {" "}Identities match only connections opened by an address bound to a listed label in{" "}
            <Link href="/identities/" className="text-(--amber) hover:text-(--amber)">Identity Bindings</Link>.
          </>
        )}
      </p>

      <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-sm text-(--text)">
        <label className="flex items-center gap-2">
          <input type="checkbox" aria-label="Schedule" checked={draft.scheduled} disabled={draft.action === "TAG" && !draft.scheduled} onChange={(e) => set({ scheduled: e.target.checked })} className={check} />
          Schedule
          <InfoTip label="The rule applies only inside a recurring window. The end is exclusive; an end before the start runs overnight. Established connections follow the window too." />
        </label>
        {draft.action === "TAG" && (
          <span className="text-xs text-(--text-muted)">A TAG rule takes no schedule: its label is fixed when the connection opens.</span>
        )}
      </div>
      {draft.scheduled && (
        <div className="grid gap-3 md:grid-cols-4">
          <fieldset className="md:col-span-4">
            <legend className={label}>Days <span className="text-(--text-dim)">(none = every day)</span></legend>
            <div className="flex flex-wrap gap-3 text-xs text-(--text)">
              {WEEKDAYS.map((day) => (
                <label key={day} className="flex items-center gap-1.5">
                  <input type="checkbox" aria-label={day} checked={draft.days.includes(day)} onChange={(e) => toggleDay(day, e.target.checked)} className={check} />
                  {day.slice(0, 3)}
                </label>
              ))}
            </div>
          </fieldset>
          <div>
            <label className={label}>Start <span className="text-(--text-dim)">(blank = 00:00)</span></label>
            <input aria-label="Start time" type="time" value={draft.start} onChange={(e) => set({ start: e.target.value })} className="input-industrial w-full" />
          </div>
          <div>
            <label className={label}>End <span className="text-(--text-dim)">(exclusive; blank = end of day)</span></label>
            <input aria-label="End time" type="time" value={draft.end} onChange={(e) => set({ end: e.target.value })} className="input-industrial w-full" />
          </div>
          <div className="md:col-span-2">
            <label className={label}>Timezone <span className="text-(--text-dim)">(IANA; blank = UTC)</span></label>
            <input aria-label="Timezone" list={tzList} value={draft.timezone} onChange={(e) => set({ timezone: e.target.value })} placeholder="UTC" className="input-industrial w-full" />
            <datalist id={tzList}>
              {zones.map((z) => <option key={z} value={z} />)}
            </datalist>
          </div>
        </div>
      )}
    </div>
  );
}
