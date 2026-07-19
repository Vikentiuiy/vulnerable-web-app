# HARNESS (out of scan scope). Records which planted vulns were exploited at runtime.
import time
from harness.catalog import CATALOG


class Tracker:
    def __init__(self):
        self.states = {c[0]: {"exploited": False, "detail": "", "at": 0} for c in CATALOG}

    def mark(self, vid, detail=""):
        s = self.states.setdefault(vid, {"exploited": False, "detail": "", "at": 0})
        s["exploited"] = True
        if detail:
            s["detail"] = detail[:300]
        s["at"] = int(time.time() * 1000)

    def reset(self):
        for s in self.states.values():
            s.update(exploited=False, detail="", at=0)

    def snapshot(self):
        items = []
        for cid, cwe, dclass, title, category, entry in CATALOG:
            s = self.states.get(cid, {"exploited": False, "detail": "", "at": 0})
            items.append({"id": cid, "cwe": cwe, "dclass": dclass, "title": title,
                          "category": category, "entry": entry, **s})
        return {"total": len(CATALOG),
                "exploited": sum(1 for s in self.states.values() if s["exploited"]),
                "items": items}


TRACKER = Tracker()
