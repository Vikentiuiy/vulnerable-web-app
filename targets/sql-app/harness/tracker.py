# HARNESS (out of scan scope).
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

    def snapshot(self):
        items = [{"id": c[0], "cwe": c[1], "dclass": c[2], "title": c[3], "category": c[4],
                  "entry": c[5], **self.states.get(c[0], {})} for c in CATALOG]
        return {"total": len(CATALOG), "exploited": sum(1 for s in self.states.values() if s["exploited"]), "items": items}


TRACKER = Tracker()
