"""
detector.py  —  Real-time IDS detection engine
Runs in a background daemon thread.  Flask reads `shared_state` directly.

ALL FIXES:
  1. global _last_attack + _last_attack_time declared in _process_packet
  2. Normal traffic label explicitly cleared in _update_status
  3. Heuristic thresholds made NON-OVERLAPPING so each attack maps uniquely
  4. Botnet check runs BEFORE BruteForce in HTTP block
  5. WINDOW_SEC = 30 so flows survive active attacks
  6. 15s grace period on _last_attack prevents label flip after flow eviction
  7. sklearn UserWarning suppressed

  LATEST FIX (DDoS + Botnet only):
  - DDoS:   removed conn_cnt condition — DDoS http.end() per loop grows conn_cnt
            fast and was hitting BruteForce first. Now purely rate + iat_mean.
            Also DDoS check moved BEFORE BruteForce so it is evaluated first.
  - Botnet: raised pkt_rate threshold 8→20 because 10-request bursts push
            instantaneous rate above 8/s even at 150–450ms per-request delay.
            iat_mean > 0.100 (was 0.200) to catch 150ms lower bound of sketch.
            iat_std  > 0.040 added as a Botnet fingerprint — random(150,450)ms
            produces HIGH variance which BruteForce (scripted delay) never has.
"""

import time
import pickle
import threading
import warnings
import numpy as np
import pandas as pd
from collections import defaultdict, deque
from scapy.all import sniff, IP, TCP, UDP, ICMP
from scapy.layers.inet6 import ICMPv6EchoRequest, ICMPv6EchoReply

# Suppress noisy sklearn parallel warning (harmless, does not affect predictions)
warnings.filterwarnings(
    "ignore",
    message=".*sklearn.utils.parallel.delayed.*",
    category=UserWarning,
    module="sklearn",
)

# ──────────────────────────────────────────────
# CONFIG
# ──────────────────────────────────────────────
MODEL_PATH  = "iot_ids_model.pkl"
ESP32_IP    = "10.251.241.19"
WINDOW_SEC  = 30
SMOOTHING   = 5

# Auth ports for traditional brute force (SSH/FTP/Telnet/RDP)
BRUTE_FORCE_PORTS = {22, 21, 23, 3389, 5900, 445, 3306, 5432, 1433}

# C2/botnet ports for traditional botnet
BOTNET_C2_PORTS = {6667, 6668, 6669, 1080, 8443, 4444, 9001, 9030}

# HTTP ports used by your Flask test server
HTTP_PORTS = {80, 5000, 8080, 8000}

# ──────────────────────────────────────────────
# LOAD MODEL
# ──────────────────────────────────────────────
with open(MODEL_PATH, "rb") as f:
    _bundle = pickle.load(f)

_model       = _bundle["model"]
_features    = _bundle["features"]
_class_names = _bundle.get("class_names", {
    0: "Normal", 1: "DDoS", 2: "PortScan", 3: "BruteForce", 4: "Botnet/Other"
})

# ──────────────────────────────────────────────
# SHARED STATE
# ──────────────────────────────────────────────
_lock = threading.Lock()
shared_state = {
    "status":             "Normal",
    "attack_type":        "—",
    "total_packets":      0,
    "attack_packets":     0,
    "normal_packets":     0,
    "counts_by_class":    {name: 0 for name in _class_names.values()},
    "recent_predictions": [],
    "last_updated":       time.time(),
}

# ──────────────────────────────────────────────
# FLOW TRACKER
# ──────────────────────────────────────────────
class FlowTracker:
    def __init__(self, window_sec: float = WINDOW_SEC):
        self.window = window_sec
        self._flows = defaultdict(lambda: {
            "fwd_pkts": 0, "bwd_pkts": 0,
            "fwd_bytes": 0, "bwd_bytes": 0,
            "fwd_header_len": 0, "bwd_header_len": 0,
            "fwd_pkt_lens": [], "bwd_pkt_lens": [],
            "fwd_iats": [], "bwd_iats": [],
            "all_iats": [],
            "flags": defaultdict(int),
            "start_ts": None, "last_fwd_ts": None,
            "last_bwd_ts": None, "last_ts": None,
            "conn_count": 0,
            "psh_count":  0,
        })
        self._lock = threading.Lock()

    def _make_key(self, src, dst, sport, dport, proto):
        if dport in HTTP_PORTS:
            return ("http", src, dst, dport)
        if sport in HTTP_PORTS:
            return ("http", dst, src, sport)
        return (src, dst, sport, dport, proto)

    def add(self, pkt):
        if not pkt.haslayer(IP):
            return None, None

        ip       = pkt[IP]
        src, dst = ip.src, ip.dst
        proto    = ip.proto
        sport    = dport = 0

        if pkt.haslayer(TCP):
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
        elif pkt.haslayer(UDP):
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport

        key     = self._make_key(src, dst, sport, dport, proto)
        ts      = time.time()
        pkt_len = len(pkt)
        ip_hdr  = ip.ihl * 4 if hasattr(ip, "ihl") else 20

        with self._lock:
            fl = self._flows[key]

            if fl["start_ts"] is None:
                fl["start_ts"] = ts

            if fl["last_ts"] is not None:
                fl["all_iats"].append(ts - fl["last_ts"])
            fl["last_ts"] = ts

            if isinstance(key, tuple) and key[0] == "http":
                direction = "fwd" if src == key[1] else "bwd"
            else:
                fwd_key = (src, dst, sport, dport, proto)
                direction = "fwd" if key == fwd_key else "bwd"

            if direction == "fwd":
                if fl["last_fwd_ts"] is not None:
                    fl["fwd_iats"].append(ts - fl["last_fwd_ts"])
                fl["last_fwd_ts"] = ts
                fl["fwd_pkts"]       += 1
                fl["fwd_bytes"]      += pkt_len
                fl["fwd_header_len"] += ip_hdr
                fl["fwd_pkt_lens"].append(pkt_len)
            else:
                if fl["last_bwd_ts"] is not None:
                    fl["bwd_iats"].append(ts - fl["last_bwd_ts"])
                fl["last_bwd_ts"] = ts
                fl["bwd_pkts"]       += 1
                fl["bwd_bytes"]      += pkt_len
                fl["bwd_header_len"] += ip_hdr
                fl["bwd_pkt_lens"].append(pkt_len)

            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                for flag, name in [
                    (0x002, "SYN"), (0x010, "ACK"), (0x020, "URG"),
                    (0x001, "FIN"), (0x004, "RST"), (0x008, "PSH"),
                ]:
                    if tcp.flags & flag:
                        fl["flags"][name] += 1

                if (tcp.flags & 0x002) and not (tcp.flags & 0x010):
                    fl["conn_count"] += 1

            return key, fl

    def get_features(self, key, fl, feature_cols: list) -> pd.DataFrame:
        dur_s     = (fl["last_ts"] - fl["start_ts"]) if fl["start_ts"] else 1e-9
        dur_us    = max(dur_s * 1e6, 1)
        tot_pkts  = fl["fwd_pkts"] + fl["bwd_pkts"]
        tot_bytes = fl["fwd_bytes"] + fl["bwd_bytes"]

        def safe_mean(lst): return float(np.mean(lst)) if lst else 0.0
        def safe_std(lst):  return float(np.std(lst))  if lst else 0.0

        dport     = key[3] if key[0] == "http" else (key[3] if len(key) == 5 else 0)
        proto_val = 6
        if len(key) == 5 and key[0] != "http":
            dport     = key[3]
            proto_val = key[4]

        raw = {
            " Flow Duration":               dur_us,
            " Total Fwd Packets":           fl["fwd_pkts"],
            " Total Backward Packets":      fl["bwd_pkts"],
            " Total Length of Fwd Packets": fl["fwd_bytes"],
            " Total Length of Bwd Packets": fl["bwd_bytes"],
            " Fwd Packet Length Mean":      safe_mean(fl["fwd_pkt_lens"]),
            " Bwd Packet Length Mean":      safe_mean(fl["bwd_pkt_lens"]),
            " Flow Bytes/s":                tot_bytes / dur_s if dur_s else 0,
            " Flow Packets/s":              tot_pkts  / dur_s if dur_s else 0,
            " Flow IAT Mean":               safe_mean(fl["all_iats"]),
            " Flow IAT Std":                safe_std(fl["all_iats"]),
            " Fwd IAT Mean":                safe_mean(fl["fwd_iats"]),
            " Bwd IAT Mean":                safe_mean(fl["bwd_iats"]),
            " Fwd Header Length":           fl["fwd_header_len"],
            " Bwd Header Length":           fl["bwd_header_len"],
            " SYN Flag Count":              fl["flags"].get("SYN", 0),
            " ACK Flag Count":              fl["flags"].get("ACK", 0),
            " URG Flag Count":              fl["flags"].get("URG", 0),
            " FIN Flag Count":              fl["flags"].get("FIN", 0),
            " RST Flag Count":              fl["flags"].get("RST", 0),
            " PSH Flag Count":              fl["flags"].get("PSH", 0),
            "Destination Port":             dport,
            " Protocol":                    proto_val,
        }

        row = {col: raw.get(col, 0) for col in feature_cols}
        return pd.DataFrame([row], columns=feature_cols)

    def evict_old(self):
        now = time.time()
        with self._lock:
            old_keys = [
                k for k, v in self._flows.items()
                if v["last_ts"] and (now - v["last_ts"]) > self.window
            ]
            for k in old_keys:
                del self._flows[k]


_tracker = FlowTracker()

# ──────────────────────────────────────────────
# SMOOTHING
# ──────────────────────────────────────────────
_pred_buffer = deque(maxlen=SMOOTHING)


def _update_status(pred_class: int):
    _pred_buffer.append(pred_class)
    majority = max(set(_pred_buffer), key=_pred_buffer.count)
    label    = _class_names[majority]

    with _lock:
        shared_state["last_updated"] = time.time()
        shared_state["counts_by_class"][label] += 1
        shared_state["total_packets"] += 1
        shared_state["recent_predictions"].append(majority)
        if len(shared_state["recent_predictions"]) > 20:
            shared_state["recent_predictions"].pop(0)

        if majority == 0:
            shared_state["status"]      = "Normal"
            shared_state["attack_type"] = "—"
            shared_state["normal_packets"] += 1
        else:
            shared_state["status"]      = "ATTACK"
            shared_state["attack_type"] = label
            shared_state["attack_packets"] += 1


# ──────────────────────────────────────────────
# LAST ATTACK STATE
# ──────────────────────────────────────────────
_last_attack      = None
_last_attack_time = 0.0


# ──────────────────────────────────────────────
# HEURISTIC HELPER
# ──────────────────────────────────────────────
def _heuristic_pred(fl: dict, key: tuple, pkt_count: int):
    """
    Attack signatures matched to your exact ESP32 sketches:

    ┌─────────────┬─────────────────┬───────────────┬──────────────┬───────────────┐
    │ Attack      │ sketch delay    │ real iat_mean │ pkt_rate     │ iat_std       │
    ├─────────────┼─────────────────┼───────────────┼──────────────┼───────────────┤
    │ DDoS        │ delay(1)        │ 5–40ms        │ >> 50/s      │ low           │
    │ BruteForce  │ delay(20)       │ 25–120ms      │ 10–80/s      │ low (script)  │
    │ Botnet      │ random(150,450) │ 150–500ms     │ variable     │ HIGH (random) │
    │ PortScan    │ raw SYN flood   │ any           │ any          │ SYN-only pkts │
    └─────────────┴─────────────────┴───────────────┴──────────────┴───────────────┘

    Order inside HTTP block:
      1. DDoS first   — pkt_rate > 50 AND iat_mean < 40ms (conn_cnt NOT used,
                        DDoS calls http.end() every loop so conn_cnt grows fast)
      2. Botnet second — iat_std > 40ms (random delay = high variance) AND
                         iat_mean > 100ms. This fires before BruteForce so
                         random-delay traffic is never misclassified.
      3. BruteForce last — pkt_rate > 10 AND iat_mean < 150ms AND iat_std < 60ms
                           (scripted delay = low variance, opposite of Botnet)

    BruteForce and PortScan thresholds are UNCHANGED from previous version.
    """
    if pkt_count < 8:
        return None

    flags     = fl["flags"]
    syn       = flags.get("SYN", 0)
    ack       = flags.get("ACK", 0)
    psh       = flags.get("PSH", 0)
    fwd_bytes = fl["fwd_bytes"]

    if isinstance(key, tuple) and key[0] == "http":
        dport = key[3]
    elif len(key) == 5:
        dport = key[3]
    else:
        dport = 0

    dur_s    = max((fl["last_ts"] - fl["start_ts"]) if fl["start_ts"] else 1e-9, 1e-9)
    all_iats = fl["all_iats"]
    iat_mean = float(np.mean(all_iats)) if all_iats else 999.0
    iat_std  = float(np.std(all_iats))  if all_iats else 0.0
    pkt_rate = pkt_count / dur_s
    conn_cnt = fl.get("conn_count", 0)

    # Calibration log: fires once at pkt 15 — remove after tuning
    if pkt_count == 15:
        print(
            f"[TUNE] dport={dport} rate={pkt_rate:.1f}/s "
            f"iat_mean={iat_mean*1000:.1f}ms iat_std={iat_std*1000:.1f}ms "
            f"conn_cnt={conn_cnt} SYN={syn} ACK={ack} PSH={psh}"
        )

    # ── Raw TCP PortScan ──────────────────────────────────────────────────
    # UNCHANGED — half-open SYN scan: many SYNs, zero ACKs, no payload
    if (
        dport not in HTTP_PORTS
        and syn >= 3
        and ack == 0
        and psh == 0
        and fwd_bytes < 200
    ):
        return 2   # PortScan

    # ── Traditional auth-port BruteForce (SSH / FTP / Telnet / RDP) ──────
    # UNCHANGED
    if dport in BRUTE_FORCE_PORTS and syn == 0 and psh >= 2 and ack >= 3:
        return 3   # BruteForce

    # ── Traditional C2-port Botnet ────────────────────────────────────────
    # UNCHANGED
    if dport in BOTNET_C2_PORTS and syn <= 1 and ack <= 2 and psh <= 1:
        return 4   # Botnet

    # ══ HTTP-based attack detection (port 80 / 5000) ══════════════════════
    if dport in HTTP_PORTS:

        # ── 1. DDoS — checked FIRST ───────────────────────────────────────
        # FIX: conn_cnt condition REMOVED. DDoS sketch calls http.end() every
        # loop iteration so conn_cnt grows as fast as packet count, which was
        # causing it to satisfy the BruteForce conn_cnt >= 3 check first.
        # Now purely rate-based: delay(1ms) → real rate >> 50/s even with WiFi.
        if pkt_rate > 50 and iat_mean < 0.040:
            return 1   # DDoS

        # ── 2. Botnet — checked SECOND ────────────────────────────────────
        # FIX: iat_std > 0.040 added as the Botnet fingerprint.
        # random(150, 450)ms produces HIGH timing variance (std ~85ms typical).
        # BruteForce uses scripted delay(20ms) so its iat_std stays < 0.060.
        # These two conditions are mutually exclusive — Botnet has high std,
        # BruteForce has low std. Botnet checked before BruteForce so it can
        # never fall through to be misclassified.
        # iat_mean threshold lowered to 0.100 to catch the 150ms lower bound.
       # ✅ BOTNET (more realistic thresholds)
        if (
            iat_mean > 0.080   # lowered (was 0.100)
            and iat_std > 0.025   # lowered (was 0.040)
        ):
            return 4   # Botnet
        # ── 3. BruteForce — checked LAST ─────────────────────────────────
        # UNCHANGED thresholds — only reachable if NOT DDoS and NOT Botnet.
        # iat_std < 0.060 is the key gate: scripted delay(20ms) is consistent.
        if (
            15 < pkt_rate <= 80
            and iat_mean < 0.120   # tighter
            and iat_std < 0.030    # VERY IMPORTANT (low variance only)
            and conn_cnt >= 3
        ):
            return 3  # BruteForce

    return None   # defer to ML model


# ──────────────────────────────────────────────
# PACKET CALLBACK
# ──────────────────────────────────────────────
def _process_packet(pkt):
    try:
        if not pkt.haslayer(IP):
            return

        ip = pkt[IP]
        if ESP32_IP and ip.src != ESP32_IP and ip.dst != ESP32_IP:
            return
        if len(pkt) < 40:
            return

        key, fl = _tracker.add(pkt)
        if key is None:
            return

        global _last_attack, _last_attack_time

        # Step 1: ML model prediction
        df        = _tracker.get_features(key, fl, _features)
        pred      = int(_model.predict(df)[0])
        pkt_count = fl["fwd_pkts"]

        # Step 2: Heuristic always runs and takes priority over ML model
        h = _heuristic_pred(fl, key, pkt_count)
        if h is not None:
            pred = h

        # Step 3: Update last attack memory with timestamp
        if pred != 0:
            _last_attack      = pred
            _last_attack_time = time.time()

        # Step 4: Hold attack label for 15s grace period after flow eviction
        elif _last_attack is not None:
            time_since_attack = time.time() - _last_attack_time
            if time_since_attack < 15:
                pred = _last_attack
            else:
                _last_attack = None

        # Step 5: Push to shared state
        _update_status(pred)

        # Detailed debug line
        label     = _class_names.get(pred, "Unknown")
        flags     = fl["flags"]
        all_iats  = fl["all_iats"]
        iat_mean  = float(np.mean(all_iats)) if all_iats else 0.0
        iat_std   = float(np.std(all_iats))  if all_iats else 0.0
        dur_s     = max((fl["last_ts"] - fl["start_ts"]) if fl["start_ts"] else 0, 1e-9)
        rate      = pkt_count / dur_s
        conns     = fl.get("conn_count", 0)
        flow_type = "HTTP-agg" if (isinstance(key, tuple) and key[0] == "http") else "5-tuple"

        print(
            f"[{flow_type}] [{ip.src}->{ip.dst}] "
            f"pkts={pkt_count:4d} conns={conns:3d} "
            f"rate={rate:7.1f}/s "
            f"iat={iat_mean*1000:6.1f}ms±{iat_std*1000:5.1f} "
            f"SYN={flags.get('SYN',0)} PSH={flags.get('PSH',0)} "
            f"{'🚨' if pred else '✅'} ({label})"
        )

    except Exception as e:
        print(f"[detector] Error: {e}")


# ──────────────────────────────────────────────
# BACKGROUND THREAD
# ──────────────────────────────────────────────
def start_detection(interface: str = None):
    def _sniff():
        _evict_loop()
        sniff(
            iface=interface,
            filter="tcp or udp or icmp or icmp6",
            prn=_process_packet,
            store=0,
        )

    t = threading.Thread(target=_sniff, daemon=True, name="ids-sniffer")
    t.start()
    print(f"[detector] Sniffing started (iface={interface or 'default'}, device={ESP32_IP or 'all'})")


def _evict_loop():
    def _run():
        while True:
            time.sleep(WINDOW_SEC)
            _tracker.evict_old()
    threading.Thread(target=_run, daemon=True, name="ids-evict").start()
