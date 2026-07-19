// HARNESS (out of scan scope). Records which planted vulns were exploited at runtime.
import { CATALOG } from "./catalog";

type State = { exploited: boolean; detail: string; at: number };

class Tracker {
  states: Record<string, State> = {};
  constructor() { CATALOG.forEach(([id]) => (this.states[id] = { exploited: false, detail: "", at: 0 })); }
  mark(id: string, detail = ""): void {
    const s = (this.states[id] ||= { exploited: false, detail: "", at: 0 });
    s.exploited = true;
    if (detail) s.detail = detail.slice(0, 300);
    s.at = Date.now();
  }
  reset(): void { Object.values(this.states).forEach((s) => Object.assign(s, { exploited: false, detail: "", at: 0 })); }
  snapshot() {
    const items = CATALOG.map(([id, cwe, dclass, title, category, entry]) => ({
      id, cwe, dclass, title, category, entry, ...(this.states[id] || { exploited: false, detail: "", at: 0 }),
    }));
    return { total: CATALOG.length, exploited: Object.values(this.states).filter((s) => s.exploited).length, items };
  }
}

export const TRACKER = new Tracker();
