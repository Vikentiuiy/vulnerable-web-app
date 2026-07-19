import importlib
import pkgutil

from flask import Flask, jsonify

import vulns
from harness import detector
from harness.tracker import TRACKER


def create_app():
    app = Flask(__name__)
    for mod in pkgutil.iter_modules(vulns.__path__):
        m = importlib.import_module(f"vulns.{mod.name}")
        if hasattr(m, "bp"):
            app.register_blueprint(m.bp)
    detector.install(app)

    @app.get("/api/status")
    def status():
        return jsonify(TRACKER.snapshot())

    @app.get("/")
    def index():
        return {"app": "vuln-sql-app", "dashboard": "/api/status"}

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8085)
