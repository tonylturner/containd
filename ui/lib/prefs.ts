const SHOW_TIPS_KEY = "containd.prefs.show_tips";
const DISMISSED_TIPS_KEY = "containd.prefs.dismissed_tips";
const CLI_HISTORY_KEY = "containd.prefs.cli_history";

function readBool(key: string, fallback: boolean): boolean {
  if (typeof window === "undefined") return fallback;
  try {
    const v = localStorage.getItem(key);
    if (v === null) return fallback;
    return v === "1" || v === "true";
  } catch {
    return fallback;
  }
}

function writeBool(key: string, value: boolean) {
  if (typeof window === "undefined") return;
  try {
    localStorage.setItem(key, value ? "1" : "0");
    window.dispatchEvent(new CustomEvent("containd:prefs"));
  } catch {}
}

export function getShowTips(): boolean {
  return readBool(SHOW_TIPS_KEY, true);
}

export function setShowTips(value: boolean) {
  writeBool(SHOW_TIPS_KEY, value);
}

export function getPersistCLIHistory(): boolean {
  return readBool(CLI_HISTORY_KEY, false);
}

export function setPersistCLIHistory(value: boolean) {
  writeBool(CLI_HISTORY_KEY, value);
}

export function getDismissedTips(): Set<string> {
  if (typeof window === "undefined") return new Set();
  try {
    const raw = localStorage.getItem(DISMISSED_TIPS_KEY);
    if (!raw) return new Set();
    const list = JSON.parse(raw);
    if (!Array.isArray(list)) return new Set();
    return new Set(list.filter((v) => typeof v === "string"));
  } catch {
    return new Set();
  }
}

export function dismissTip(id: string) {
  if (typeof window === "undefined") return;
  try {
    const current = getDismissedTips();
    current.add(id);
    localStorage.setItem(DISMISSED_TIPS_KEY, JSON.stringify(Array.from(current)));
    window.dispatchEvent(new CustomEvent("containd:prefs"));
  } catch {}
}

export function clearDismissedTips() {
  if (typeof window === "undefined") return;
  try {
    localStorage.removeItem(DISMISSED_TIPS_KEY);
    window.dispatchEvent(new CustomEvent("containd:prefs"));
  } catch {}
}
