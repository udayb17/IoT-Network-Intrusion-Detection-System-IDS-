"""
app.py  —  Flask API for IoT IDS
Starts the detection engine on startup (Flask 2 + 3 compatible).

Endpoints:
  GET /           → serves templates/index.html
  GET /stats      → JSON status snapshot
  POST /reset     → reset counters

File layout expected:
  iot_ids/
  ├── app.py
  ├── detector.py
  ├── iot_ids_model.pkl
  └── templates/
      └── index.html
"""
import time
import threading
from flask import Flask, jsonify, render_template
from detector import start_detection, shared_state, _lock, _class_names

# CONFIG
NETWORK_INTERFACE = None

app = Flask(__name__)

_detection_started = False
_start_lock = threading.Lock()

def _ensure_started():
    global _detection_started
    with _start_lock:
        if not _detection_started:
            start_detection(interface=NETWORK_INTERFACE)
            _detection_started = True

_ensure_started()

@app.route("/")
def dashboard():
    return render_template("index.html")

@app.route("/login", methods=["POST"])
def login():
    return jsonify({"status": "failed"})

@app.route("/stats")
def stats():
    with _lock:
        snapshot = dict(shared_state)

    snapshot["last_updated"] = time.strftime(
        "%Y-%m-%d %H:%M:%S",
        time.localtime(snapshot["last_updated"])
    )

    return jsonify(snapshot)

@app.route("/reset", methods=["POST"])
def reset():
    with _lock:
        shared_state["status"] = "Normal"
        shared_state["attack_type"] = "—"
        shared_state["total_packets"] = 0
        shared_state["attack_packets"] = 0
        shared_state["normal_packets"] = 0
        shared_state["counts_by_class"] = {n: 0 for n in _class_names.values()}
        shared_state["recent_predictions"] = []
        shared_state["last_updated"] = time.time()

    return jsonify({"ok": True})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
