#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Multi-IP Modbus TCP Recon + Packet Crafter (Tkinter, Thread Pool, JSONL logging)

Key features:
- Targets input supports CIDR (e.g., 10.0.0.0/29), IPv4 range (10.0.0.10-10.0.0.20), and host[:port] list.
- Thread-pooled multi-host scanning with per-host status/counters.
- Active UID scan via Diagnostic Echo (0x08) with strict validation (UID/TID/LEN/ECHO).
- Optional Device ID fingerprint (0x2B/0x0E).
- Structured logs: <scan_folder>/scan.jsonl and operator.txt; recon_all.csv export.
- Read-only Operator Log with Clear button; Clear Recon button.
- Safe, user-writable scan folders (Documents/ModbusScans or %TEMP% fallback).
- "Choose Output Folder..." button + persistent setting (~/.modbus_scanner_config.json).
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import socket, struct, time, datetime, csv, os, json, queue, uuid, ipaddress, threading, tempfile
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging, logging.handlers
from typing import Dict, Tuple, List, Any
import sys, subprocess  # <-- needed for "Open Log Folder"

APP_TITLE = "Multi-IP Modbus TCP Scanner & Crafter"
DEFAULT_PORT = 502
MAX_WORKERS_DEFAULT = 16

# ------------------------------ Global State ---------------------------------
ui_queue: "queue.Queue[tuple]" = queue.Queue()
scan_folder = None
scan_id = None
stop_event = threading.Event()
executor: ThreadPoolExecutor = None
targets: Dict[Tuple[str, int], Dict[str, Any]] = {}
recon_rows: List[Tuple[str, int, str, str, str, str, str]] = []

# settings persisted in ~/.modbus_scanner_config.json
SETTINGS_PATH = Path.home() / ".modbus_scanner_config.json"
settings = {"output_dir": ""}

# ------------------------------ Settings I/O ---------------------------------
def load_settings():
    global settings
    try:
        if SETTINGS_PATH.exists():
            with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    settings.update(data)
    except Exception:
        pass

def save_settings():
    try:
        with open(SETTINGS_PATH, "w", encoding="utf-8") as f:
            json.dump(settings, f, indent=2)
    except Exception:
        pass

load_settings()

# ------------------------------ Structured Logging ---------------------------
log_q = queue.Queue()

class JsonFormatter(logging.Formatter):
    def format(self, record):
        now = datetime.datetime.now().astimezone().isoformat(timespec="milliseconds")
        payload = {"ts": now, "level": record.levelname}
        extra_fields = getattr(record, "extra_fields", {})
        if isinstance(extra_fields, dict):
            payload.update(extra_fields)
        msg = record.getMessage()
        if msg:
            payload["msg"] = msg
        return json.dumps(payload, ensure_ascii=False)

logger = logging.getLogger("scanner")
logger.setLevel(logging.INFO)
q_handler = logging.handlers.QueueHandler(log_q)
logger.addHandler(q_handler)
listener = None

class UiHandler(logging.Handler):
    def emit(self, record):
        try:
            ui_queue.put(("log_line", record.getMessage()))
        except Exception:
            pass

def start_log_listeners(folder_path: str):
    global listener
    jsonl = os.path.join(folder_path, "scan.jsonl")
    txt = os.path.join(folder_path, "operator.txt")
    json_handler = logging.FileHandler(jsonl, encoding="utf-8")
    json_handler.setFormatter(JsonFormatter())
    text_handler = logging.FileHandler(txt, encoding="utf-8")
    text_handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    ui_handler = UiHandler()
    listener = logging.handlers.QueueListener(log_q, json_handler, text_handler, ui_handler)
    listener.start()

def stop_log_listeners():
    global listener
    if listener:
        listener.stop()
        listener = None

def log_event(level, event, **kw):
    extra = {"extra_fields": {"event": event, **kw}}
    logger.log(level, f"[{kw.get('host','-')}:{kw.get('port','-')}] {event}", extra=extra)

# ------------------------------ Helpers --------------------------------------
def get_scan_base_dir() -> str:
    """
    Returns a writable directory for scan outputs.
    Prefer user setting; otherwise try Documents/ModbusScans, ~/ModbusScans,
    script_dir/ModbusScans, %TEMP%/ModbusScans, then cwd/ModbusScans.
    """
    # 1) User-specified directory (if valid)
    custom = settings.get("output_dir", "").strip()
    if custom:
        try:
            p = Path(custom)
            p.mkdir(parents=True, exist_ok=True)
            if os.access(p, os.W_OK):
                return str(p)
        except Exception:
            pass

    candidates = []
    try:
        home = Path.home()
    except Exception:
        home = None

    if home:
        docs = home / "Documents"
        candidates.append(docs / "ModbusScans")
        candidates.append(home / "ModbusScans")

    # Script directory
    try:
        script_dir = Path(__file__).resolve().parent
        candidates.append(script_dir / "ModbusScans")
    except Exception:
        pass

    # %TEMP%
    candidates.append(Path(tempfile.gettempdir()) / "ModbusScans")

    # CWD as last resort
    try:
        candidates.append(Path(os.getcwd()) / "ModbusScans")
    except Exception:
        pass

    for p in candidates:
        try:
            p.mkdir(parents=True, exist_ok=True)
            if os.access(p, os.W_OK):
                return str(p)
        except Exception:
            continue

    return str(Path(tempfile.gettempdir()))

def mbap_len_ok(resp: bytes) -> bool:
    if len(resp) < 7: return False
    declared_len = int.from_bytes(resp[4:6], 'big')
    return declared_len == (len(resp) - 6)

def build_diag_echo_request(uid: int, payload_hex: str, tid: int) -> bytes:
    data = bytes.fromhex(payload_hex)
    if len(data) != 2:
        raise ValueError("Echo payload must be exactly 2 bytes (e.g., 1234).")
    pdu = bytes([0x08, 0x00, 0x00]) + data
    length = 1 + len(pdu)  # UID + PDU
    mbap = tid.to_bytes(2,'big') + (0).to_bytes(2,'big') + length.to_bytes(2,'big') + bytes([uid])
    return mbap + pdu

def build_dev_id_req(uid: int, tid: int) -> bytes:
    pdu = bytes([0x2B, 0x0E, 0x01, 0x00])  # Basic, object 0
    length = 1 + len(pdu)
    mbap = tid.to_bytes(2,'big') + (0).to_bytes(2,'big') + length.to_bytes(2,'big') + bytes([uid])
    return mbap + pdu

def validate_echo_response_verbose(resp: bytes, expect_tid: int, expect_uid: int,
                                   expect_payload: bytes, do_uid: bool, do_echo: bool, do_len: bool):
    checks = []
    if len(resp) < 12:
        checks.append(("Length >= 12", False, f"got {len(resp)}"))
        return False, checks
    r_tid = int.from_bytes(resp[0:2], 'big')
    r_len = int.from_bytes(resp[4:6], 'big')
    r_uid = resp[6]
    r_fc  = resp[7]
    if do_uid:
        checks.append(("UID match", r_uid == expect_uid, f"{r_uid} vs {expect_uid}"))
        checks.append(("TID match", r_tid == expect_tid, f"{r_tid} vs {expect_tid}"))
    if do_len:
        checks.append(("MBAP LEN", mbap_len_ok(resp), f"declared={r_len}, calc={len(resp)-6}"))
    if do_echo:
        checks.append(("FC==0x08", r_fc == 0x08, f"fc={r_fc:02X}"))
        if len(resp) >= 12:
            sub = int.from_bytes(resp[8:10], 'big')
            data = resp[10:12]
            checks.append(("Sub==0x0000", sub == 0x0000, f"sub={sub:04X}"))
            checks.append(("Echo payload", data == expect_payload, f"{data.hex()} vs {expect_payload.hex()}"))
    ok = all(c[1] for c in checks)
    return ok, checks

def parse_devid_basic(dev: bytes):
    if len(dev) < 12:
        return False, "", "", "", ""
    if dev[7] != 0x2B or dev[8] != 0x0E:
        return False, "", "", "", dev[7:].hex()
    pdu = dev[7:]
    i = 2
    if len(pdu) < i + 5:
        return False, "", "", "", pdu.hex()
    read_code = pdu[i]; i += 1
    conf      = pdu[i]; i += 1
    more      = pdu[i]; i += 1
    next_id   = pdu[i]; i += 1
    count     = pdu[i]; i += 1
    vendor = product = rev = ""
    for _ in range(count):
        if i + 2 > len(pdu): break
        obj_id = pdu[i]; i += 1
        size   = pdu[i]; i += 1
        if i + size > len(pdu): break
        try:
            text = pdu[i:i+size].decode('utf-8', errors='ignore')
        except Exception:
            text = ""
        i += size
        if obj_id == 0x00: vendor = text
        elif obj_id == 0x01: product = text
        elif obj_id == 0x02: rev = text
    return True, vendor, product, rev, pdu.hex()

def canonical_devid_key(vendor: str, product: str, rev: str) -> str:
    return f"{vendor}|{product}|{rev}".strip()

def parse_targets(text: str, default_port: int) -> List[Tuple[str, int]]:
    """
    Supports:
      - CIDR: 192.168.1.0/29
      - Range: 192.168.1.10-192.168.1.20
      - host or host:port, one per line
    """
    res = []
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    for ln in lines:
        try:
            if "/" in ln:
                net = ipaddress.ip_network(ln, strict=False)
                for ip in net.hosts():
                    res.append((str(ip), default_port))
            elif "-" in ln and not ln.count(":") > 1:
                start, end = [x.strip() for x in ln.split("-", 1)]
                ip_s = ipaddress.ip_address(start)
                ip_e = ipaddress.ip_address(end)
                if ip_s.version != 4 or ip_e.version != 4:
                    raise ValueError("Range supports IPv4 only.")
                cur = int(ip_s)
                while cur <= int(ip_e):
                    res.append((str(ipaddress.ip_address(cur)), default_port))
                    cur += 1
            else:
                if ":" in ln:
                    host, p = ln.rsplit(":", 1)
                    port = int(p)
                else:
                    host, port = ln, default_port
                res.append((host, port))
        except Exception as e:
            ui_queue.put(("error_popup", f"Invalid target '{ln}': {e}"))
    # dedupe
    unique = list(dict.fromkeys(res))
    # filter multicast/unspecified/reserved (allow loopback)
    filtered = []
    for host, port in unique:
        try:
            ip = ipaddress.ip_address(host)
            if ip.is_multicast or ip.is_unspecified or ip.is_reserved:
                continue
        except Exception:
            pass
        filtered.append((host, port))
    return filtered

# ------------------------------ Worker ---------------------------------------
def recon_job(host: str, port: int, uid_start: int, uid_end: int, echo_payload_hex: str,
              timeout_s: float, strict_uid: bool, strict_echo: bool, do_len: bool,
              fingerprint_only_active: bool, qps_delay_ms: int, jitter_ms: int):
    if stop_event.is_set():
        return
    tstate = targets.setdefault((host, port), {
        "status": "idle", "stats": {"sent":0,"recv":0,"timeouts":0,"errors":0,"active":0,"rejected":0},
        "fingerprints": {}
    })
    tstate["status"] = "scanning"
    ui_queue.put(("targets_status", host, port, "scanning",
                  tstate["stats"].get("active",0), tstate["stats"].get("errors",0)))

    log_event(logging.INFO, "host_scan_start", scan_id=scan_id, host=host, port=port,
              uid_start=uid_start, uid_end=uid_end, payload=echo_payload_hex)

    payload = bytes.fromhex(echo_payload_hex)
    for uid in range(uid_start, uid_end + 1):
        if stop_event.is_set():
            break
        tid = uid
        try:
            req = build_diag_echo_request(uid, echo_payload_hex, tid)
        except Exception as e:
            row = (host, port, str(uid), "Error", "", "", f"build_err:{e}")
            ui_queue.put(("recon_row", row))
            log_event(logging.ERROR, "build_error", scan_id=scan_id, host=host, port=port, uid=uid, error=str(e))
            continue

        if qps_delay_ms > 0:
            time.sleep(qps_delay_ms / 1000.0)
        if jitter_ms > 0:
            time.sleep(jitter_ms / 1000.0 * 0.5)

        try:
            t0 = time.monotonic()
            with socket.create_connection((host, port), timeout=timeout_s) as s:
                s.sendall(req)
                s.settimeout(timeout_s)
                resp = s.recv(4096)
            rtt_ms = int((time.monotonic() - t0) * 1000)
            resp_hex = resp.hex()
            tstate["stats"]["sent"] += 1
            tstate["stats"]["recv"] += 1
            ok, _checks = validate_echo_response_verbose(resp, tid, uid, payload,
                                                         do_uid=strict_uid, do_echo=strict_echo, do_len=do_len)
            status = "Active" if ok else "Rejected"
            note = "OK" if ok else "Validation failed"
            if ok: tstate["stats"]["active"] += 1
            else:  tstate["stats"]["rejected"] += 1
            row = (host, port, str(uid), status, str(rtt_ms), resp_hex, note)
            ui_queue.put(("recon_row", row))

            # Fingerprint (optional)
            if ok and fingerprint_only_active:
                try:
                    dev_req = build_dev_id_req(uid, tid)
                    with socket.create_connection((host, port), timeout=timeout_s) as s2:
                        s2.sendall(dev_req)
                        s2.settimeout(timeout_s)
                        dev = s2.recv(4096)
                    ok_dev, vendor, product, rev, pdu_hex = parse_devid_basic(dev)
                    if ok_dev:
                        key = canonical_devid_key(vendor, product, rev)
                        fp = tstate["fingerprints"].setdefault(
                            key, {"uids": [], "vendor": vendor, "product": product, "rev": rev, "pdu_hex": pdu_hex}
                        )
                        if uid not in fp["uids"]:
                            fp["uids"].append(uid)
                        ui_queue.put(("fingerprint", host, port, key, fp))
                    else:
                        pdu_fallback = dev[7:].hex() if len(dev) >= 7 else dev.hex()
                        key = f"HEX:{pdu_fallback}"
                        fp = tstate["fingerprints"].setdefault(
                            key, {"uids": [], "vendor": "", "product": "", "rev": "", "pdu_hex": pdu_fallback}
                        )
                        if uid not in fp["uids"]:
                            fp["uids"].append(uid)
                        ui_queue.put(("fingerprint", host, port, key, fp))
                except Exception as fe:
                    log_event(logging.WARNING, "fingerprint_error", scan_id=scan_id, host=host, port=port, uid=uid, error=str(fe))

        except socket.timeout:
            tstate["stats"]["sent"] += 1
            tstate["stats"]["timeouts"] += 1
            row = (host, port, str(uid), "No Reply", "", "", "timeout")
            ui_queue.put(("recon_row", row))
        except ConnectionRefusedError:
            tstate["stats"]["errors"] += 1
            row = (host, port, str(uid), "Error", "", "", "conn_refused")
            ui_queue.put(("recon_row", row))
        except socket.gaierror as e:
            tstate["stats"]["errors"] += 1
            row = (host, port, str(uid), "Error", "", "", f"dns:{e}")
            ui_queue.put(("recon_row", row))
            break
        except Exception as e:
            tstate["stats"]["errors"] += 1
            row = (host, port, str(uid), "Error", "", "", str(e))
            ui_queue.put(("recon_row", row))

    tstate["status"] = "done"
    ui_queue.put(("targets_status", host, port, "done",
                  tstate["stats"].get("active",0), tstate["stats"].get("errors",0)))
    log_event(logging.INFO, "host_scan_end", scan_id=scan_id, host=host, port=port, **tstate["stats"])

# ------------------------------ Tk UI ----------------------------------------
root = tk.Tk()
root.title(APP_TITLE)
root.geometry("1280x900")

# Operator Log (read-only)
log_section = tk.LabelFrame(root, text="Operator Log")
log_section.pack(fill="both", padx=10, pady=(10, 8))
output_text = scrolledtext.ScrolledText(log_section, width=160, height=10, wrap="none", state="disabled")
output_text.pack(fill="both", expand=True)
log_scroll_x = ttk.Scrollbar(log_section, orient="horizontal", command=output_text.xview)
output_text.configure(xscrollcommand=log_scroll_x.set); log_scroll_x.pack(fill="x")

def ui_log(msg: str):
    output_text.configure(state="normal")
    output_text.insert(tk.END, msg + ("\n" if not msg.endswith("\n") else ""))
    output_text.see(tk.END)
    output_text.configure(state="disabled")

# ---- New buttons: Save Log, Copy Log, Open Log Folder, Clear Log
btn_log_tools = tk.Frame(log_section)
btn_log_tools.pack(anchor="e", pady=(4, 0))

def get_operator_log_text() -> str:
    return output_text.get("1.0", tk.END)

def clear_operator_log():
    output_text.configure(state="normal")
    output_text.delete("1.0", tk.END)
    output_text.configure(state="disabled")
    ui_log("[log cleared]")

def save_operator_log_as():
    path = filedialog.asksaveasfilename(
        title="Save Operator Log As...",
        defaultextension=".txt",
        filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
    )
    if not path:
        return
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(get_operator_log_text())
        ui_log(f"[saved] Operator Log exported to {path}")
    except Exception as e:
        messagebox.showerror("Save Log", f"Could not save log:\n{e}")

def copy_operator_log():
    try:
        root.clipboard_clear()
        root.clipboard_append(get_operator_log_text())
        ui_log("[copied] Operator Log copied to clipboard")
    except Exception as e:
        messagebox.showerror("Copy Log", f"Could not copy log:\n{e}")

def open_log_folder():
    # Uses current scan folder if available; otherwise opens base scans directory
    base = scan_folder or (output_dir_var.get().strip() or get_scan_base_dir())
    try:
        if os.name == "nt":
            os.startfile(base)  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.call(["open", base])
        else:
            subprocess.call(["xdg-open", base])
        ui_log(f"[open] Log folder: {base}")
    except Exception as e:
        messagebox.showerror("Open Folder", f"Could not open folder:\n{e}")

tk.Button(btn_log_tools, text="Save Log As…", command=save_operator_log_as).pack(side=tk.LEFT, padx=(0, 6))
tk.Button(btn_log_tools, text="Copy Log", command=copy_operator_log).pack(side=tk.LEFT, padx=(0, 6))
tk.Button(btn_log_tools, text="Open Log Folder", command=open_log_folder).pack(side=tk.LEFT, padx=(0, 6))
tk.Button(btn_log_tools, text="Clear Log", command=clear_operator_log).pack(side=tk.LEFT)

# Output folder chooser + display
outdir_frame = tk.Frame(root); outdir_frame.pack(fill="x", padx=10, pady=(0,4))
tk.Label(outdir_frame, text="Output Folder:").pack(side=tk.LEFT)
output_dir_var = tk.StringVar(value=settings.get("output_dir",""))
output_dir_entry = tk.Entry(outdir_frame, width=80, textvariable=output_dir_var)
output_dir_entry.pack(side=tk.LEFT, padx=6)
def choose_output_folder():
    d = filedialog.askdirectory(title="Choose Output Folder")
    if d:
        output_dir_var.set(d)
        settings["output_dir"] = d
        save_settings()
tk.Button(outdir_frame, text="Choose Output Folder…", command=choose_output_folder).pack(side=tk.LEFT, padx=6)

# Targets panel
targets_frame = tk.LabelFrame(root, text="Targets")
targets_frame.pack(fill="x", padx=10, pady=(0,6))

frm_top = tk.Frame(targets_frame); frm_top.pack(fill="x", padx=6, pady=4)
tk.Label(frm_top, text="Default Port:").pack(side=tk.LEFT)
default_port_entry = tk.Entry(frm_top, width=6)
default_port_entry.insert(0, str(DEFAULT_PORT))
default_port_entry.pack(side=tk.LEFT, padx=(4,10))
tk.Label(frm_top, text="Concurrency:").pack(side=tk.LEFT)
concurrency_var = tk.IntVar(value=MAX_WORKERS_DEFAULT)
tk.Spinbox(frm_top, from_=1, to=128, width=5, textvariable=concurrency_var).pack(side=tk.LEFT, padx=(4,10))
tk.Label(frm_top, text="QPS delay (ms):").pack(side=tk.LEFT)
qps_delay_entry = tk.Entry(frm_top, width=6); qps_delay_entry.insert(0, "50"); qps_delay_entry.pack(side=tk.LEFT, padx=(4,10))
tk.Label(frm_top, text="Jitter (ms):").pack(side=tk.LEFT)
jitter_entry = tk.Entry(frm_top, width=6); jitter_entry.insert(0, "10"); jitter_entry.pack(side=tk.LEFT, padx=(4,10))
auth_var = tk.BooleanVar(value=True)
tk.Checkbutton(frm_top, text="I am authorized to scan these targets", variable=auth_var).pack(side=tk.LEFT, padx=(12,0))

targets_text = scrolledtext.ScrolledText(targets_frame, width=140, height=6, wrap="none")
targets_text.pack(fill="x", padx=6, pady=(4,4))
targets_text.insert(tk.END, "127.0.0.1:5020\n")

btns_tgt = tk.Frame(targets_frame); btns_tgt.pack(fill="x", padx=6, pady=(0,6))
def add_targets():
    try:
        default_port = int(default_port_entry.get().strip())
    except ValueError:
        messagebox.showerror("Port", "Default port must be integer"); return
    tgts = parse_targets(targets_text.get("1.0", tk.END), default_port)
    if not tgts:
        messagebox.showinfo("Targets", "No valid targets parsed"); return
    for host, port in tgts:
        key = (host, port)
        if key not in targets:
            targets[key] = {"status":"idle","stats":{"sent":0,"recv":0,"timeouts":0,"errors":0,"active":0,"rejected":0}, "fingerprints":{}}
            targets_tree.insert("", tk.END, values=(host, port, "idle", "–", "–"))
def clear_targets():
    for item in targets_tree.get_children():
        targets_tree.delete(item)
    targets.clear()

def import_targets_csv():
    path = filedialog.askopenfilename(filetypes=[("CSV","*.csv")])
    if not path: return
    with open(path, "r", newline="") as f:
        r = csv.reader(f)
        for row in r:
            if not row: continue
            host = row[0].strip()
            try: port = int(row[1]) if len(row) > 1 else DEFAULT_PORT
            except: port = DEFAULT_PORT
            if (host, port) not in targets:
                targets[(host,port)] = {"status":"idle","stats":{"sent":0,"recv":0,"timeouts":0,"errors":0,"active":0,"rejected":0}, "fingerprints":{}}
                targets_tree.insert("", tk.END, values=(host, port, "idle", "–", "–"))

def export_targets_csv():
    if not targets:
        messagebox.showinfo("Export Targets", "No targets to export."); return
    path = filedialog.asksaveasfilename(defaultextension=".csv")
    if not path: return
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        for (host,port) in targets.keys():
            w.writerow([host, port])

tk.Button(btns_tgt, text="Add Targets", command=add_targets).pack(side=tk.LEFT, padx=4)
tk.Button(btns_tgt, text="Clear Targets", command=clear_targets).pack(side=tk.LEFT, padx=4)
tk.Button(btns_tgt, text="Import CSV", command=import_targets_csv).pack(side=tk.LEFT, padx=4)
tk.Button(btns_tgt, text="Export CSV", command=export_targets_csv).pack(side=tk.LEFT, padx=4)

targets_tree = ttk.Treeview(targets_frame,
    columns=("host","port","status","active","errors"),
    show="headings", height=6)
for col, txt, w in [("host","Host",260),("port","Port",70),("status","Status",120),("active","Active UIDs",90),("errors","Errors",70)]:
    targets_tree.heading(col, text=txt)
    targets_tree.column(col, width=w, anchor="center" if col!="host" else "w")
targets_tree.pack(fill="x", padx=6, pady=(0,6))

# Recon controls
recon_frame = tk.LabelFrame(root, text="Recon – Multi-Host Active UID Scan (Diagnostic Echo)")
recon_frame.pack(fill="x", padx=10, pady=(0,6))
frm_line = tk.Frame(recon_frame); frm_line.pack(fill="x", padx=8, pady=4)
tk.Label(frm_line, text="UID Start:").pack(side=tk.LEFT)
uid_start_entry = tk.Entry(frm_line, width=6); uid_start_entry.insert(0, "1"); uid_start_entry.pack(side=tk.LEFT, padx=4)
tk.Label(frm_line, text="UID End:").pack(side=tk.LEFT)
uid_end_entry = tk.Entry(frm_line, width=6); uid_end_entry.insert(0, "16"); uid_end_entry.pack(side=tk.LEFT, padx=4)
tk.Label(frm_line, text="Echo Payload (2 bytes hex):").pack(side=tk.LEFT, padx=(12,0))
echo_payload_entry = tk.Entry(frm_line, width=10); echo_payload_entry.insert(0, "1234"); echo_payload_entry.pack(side=tk.LEFT, padx=4)
tk.Label(frm_line, text="Timeout (s):").pack(side=tk.LEFT, padx=(12,0))
timeout_entry = tk.Entry(frm_line, width=6); timeout_entry.insert(0, "3.0"); timeout_entry.pack(side=tk.LEFT, padx=4)

strict_uid_var = tk.BooleanVar(value=True)
strict_echo_var = tk.BooleanVar(value=True)
check_len_var = tk.BooleanVar(value=True)
fp_only_active_var = tk.BooleanVar(value=True)
tk.Checkbutton(frm_line, text="Strict UID/TID", variable=strict_uid_var).pack(side=tk.LEFT, padx=6)
tk.Checkbutton(frm_line, text="Strict Echo", variable=strict_echo_var).pack(side=tk.LEFT, padx=6)
tk.Checkbutton(frm_line, text="Check MBAP LEN", variable=check_len_var).pack(side=tk.LEFT, padx=6)
tk.Checkbutton(frm_line, text="Fingerprint only Active", variable=fp_only_active_var).pack(side=tk.LEFT, padx=6)

recon_btns = tk.Frame(recon_frame); recon_btns.pack(fill="x", padx=8, pady=(0,6))
start_scan_btn = tk.Button(recon_btns, text="Start Scan")
stop_scan_btn  = tk.Button(recon_btns, text="Stop Scan")
export_csv_btn = tk.Button(recon_btns, text="Export Recon CSV")
clear_recon_btn = tk.Button(recon_btns, text="Clear Recon")
start_scan_btn.pack(side=tk.LEFT, padx=4); stop_scan_btn.pack(side=tk.LEFT, padx=4)
export_csv_btn.pack(side=tk.LEFT, padx=4); clear_recon_btn.pack(side=tk.LEFT, padx=4)

# Recon results table
recon_tree = ttk.Treeview(root, columns=("host","port","uid","status","rtt","resp","note"), show="headings", height=12)
for col, txt, w, anchor in [
    ("host","Host",220,"w"),
    ("port","Port",60,"center"),
    ("uid","UID",60,"center"),
    ("status","Status",110,"center"),
    ("rtt","RTT(ms)",90,"e"),
    ("resp","Response (hex)",640,"w"),
    ("note","Note",180,"w")
]:
    recon_tree.heading(col, text=txt); recon_tree.column(col, width=w, anchor=anchor)
recon_tree.pack(fill="both", padx=10, pady=(0,6), expand=True)
recon_x = ttk.Scrollbar(root, orient="horizontal", command=recon_tree.xview)
recon_tree.configure(xscrollcommand=recon_x.set); recon_x.pack(fill="x", padx=10, pady=(0,6))

# Packet crafting (minimal)
craft_frame = tk.LabelFrame(root, text="Packet Crafting & Send")
craft_frame.pack(fill="x", padx=10, pady=(0,10))
send_scope_var = tk.StringVar(value="highlight")
tk.Radiobutton(craft_frame, text="Send to highlighted targets", variable=send_scope_var, value="highlight").pack(anchor="w")
tk.Radiobutton(craft_frame, text="Send to ALL targets", variable=send_scope_var, value="all").pack(anchor="w")
mal_frame = tk.Frame(craft_frame); mal_frame.pack(fill="x", padx=6, pady=(2,0))
tk.Label(mal_frame, text="Manual Hex (MBAP+PDU):").pack(side=tk.LEFT)
hex_entry = tk.Entry(mal_frame, width=130); hex_entry.pack(side=tk.LEFT, padx=6)
mal_opts = {
    "invalid_function": tk.BooleanVar(),
    "out_of_range_address": tk.BooleanVar(),
    "incorrect_length": tk.BooleanVar(),
    "extra_bytes": tk.BooleanVar(),
    "corrupted_header": tk.BooleanVar(),
}
opt_frame = tk.Frame(craft_frame); opt_frame.pack(fill="x", padx=6, pady=(2,6))
tk.Checkbutton(opt_frame, text="Invalid FC", variable=mal_opts["invalid_function"]).pack(side=tk.LEFT, padx=6)
tk.Checkbutton(opt_frame, text="Out-of-Range Addr", variable=mal_opts["out_of_range_address"]).pack(side=tk.LEFT, padx=6)
tk.Checkbutton(opt_frame, text="Incorrect LEN", variable=mal_opts["incorrect_length"]).pack(side=tk.LEFT, padx=6)
tk.Checkbutton(opt_frame, text="Extra Bytes", variable=mal_opts["extra_bytes"]).pack(side=tk.LEFT, padx=6)
tk.Checkbutton(opt_frame, text="Corrupt MBAP", variable=mal_opts["corrupted_header"]).pack(side=tk.LEFT, padx=6)
send_btn = tk.Button(craft_frame, text="Send Packet"); send_btn.pack(anchor="w", padx=6, pady=(0,4))

# ------------------------------ UI Queue Pump --------------------------------
def pump_ui_queue():
    try:
        while True:
            item = ui_queue.get_nowait()
            kind = item[0]
            if kind == "log_line":
                ui_log(item[1])
            elif kind == "recon_row":
                row = item[1]
                recon_rows.append(row)
                recon_tree.insert("", tk.END, values=row)
            elif kind == "fingerprint":
                _, host, port, key, fp = item
                ui_log(f"[{host}:{port}] DeviceID: {key} (UIDs {fp['uids']})")
            elif kind == "error_popup":
                messagebox.showerror("Error", item[1])
            elif kind == "targets_status":
                host, port, status, active, errors = item[1:]
                # Update row in targets_tree
                for iid in targets_tree.get_children():
                    vals = targets_tree.item(iid, "values")
                    if vals and vals[0] == host and str(vals[1]) == str(port):
                        show_active = active if status != "idle" else "–"
                        show_errors = errors if status != "idle" else "–"
                        targets_tree.item(iid, values=(host, port, status, show_active, show_errors))
                        break
    except queue.Empty:
        pass
    root.after(50, pump_ui_queue)

root.after(50, pump_ui_queue)

def update_targets_table_periodic():
    for (host,port), st in targets.items():
        stats = st.get("stats", {})
        ui_queue.put(("targets_status", host, port, st.get("status","idle"),
                      stats.get("active",0), stats.get("errors",0)))
    root.after(500, update_targets_table_periodic)

root.after(500, update_targets_table_periodic)

# ------------------------------ Actions --------------------------------------
def ensure_targets_present_or_autoadd():
    """If targets table empty, auto-parse text box and add them."""
    if targets_tree.get_children():
        return True
    try:
        default_port = int(default_port_entry.get().strip())
    except ValueError:
        default_port = DEFAULT_PORT
    tgts = parse_targets(targets_text.get("1.0", tk.END), default_port)
    for host, port in tgts:
        key = (host, port)
        if key not in targets:
            targets[key] = {"status":"idle","stats":{"sent":0,"recv":0,"timeouts":0,"errors":0,"active":0,"rejected":0}, "fingerprints":{}}
            targets_tree.insert("", tk.END, values=(host, port, "idle", "–", "–"))
    return bool(tgts)

def start_scan():
    global scan_folder, scan_id, executor
    if not auth_var.get():
        if not messagebox.askyesno("Authorization", "You did not confirm authorization. Proceed anyway?"):
            return

    if not ensure_targets_present_or_autoadd():
        messagebox.showinfo("Scan", "No targets to scan."); return

    rows = []
    for iid in targets_tree.get_children():
        vals = targets_tree.item(iid, "values")
        if vals:
            rows.append((vals[0], int(vals[1])))

    try:
        uid_start = int(uid_start_entry.get())
        uid_end   = int(uid_end_entry.get())
    except ValueError:
        messagebox.showerror("UID", "UID Start/End must be integers."); return
    if not (1 <= uid_start <= 247 and 1 <= uid_end <= 247 and uid_start <= uid_end):
        messagebox.showerror("UID", "UID range must be 1..247 and Start ≤ End."); return

    payload_hex = echo_payload_entry.get().strip().replace(" ","")
    try:
        if len(bytes.fromhex(payload_hex)) != 2:
            raise ValueError
    except Exception:
        messagebox.showerror("Echo", "Echo payload must be exactly 2 hex bytes (e.g., 1234)."); return

    try:
        timeout_s = float(timeout_entry.get())
    except ValueError:
        timeout_s = 3.0
    try:
        qps_delay = int(qps_delay_entry.get())
        jitter    = int(jitter_entry.get())
    except ValueError:
        qps_delay, jitter = 50, 10

    # Create scan folder in a writable place
    ts = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    scan_id_local = uuid.uuid4().hex[:8]
    base_dir = output_dir_var.get().strip() or get_scan_base_dir()
    folder = os.path.join(base_dir, f"scan_{ts}_{scan_id_local}")
    try:
        os.makedirs(folder, exist_ok=True)
    except Exception as e:
        fallback_base = os.path.join(tempfile.gettempdir(), "ModbusScans")
        os.makedirs(fallback_base, exist_ok=True)
        folder = os.path.join(fallback_base, f"scan_{ts}_{scan_id_local}")
        os.makedirs(folder, exist_ok=True)
        ui_log(f"[warn] Could not create scan folder in preferred location ({base_dir}): {e}")
        ui_log(f"[info] Using fallback scan folder: {folder}")

    start_log_listeners(folder)

    # Reset recon table + state
    recon_tree.delete(*recon_tree.get_children())
    recon_rows.clear()
    for k in targets:
        targets[k]["status"]="queued"
        targets[k]["stats"]={"sent":0,"recv":0,"timeouts":0,"errors":0,"active":0,"rejected":0}
        targets[k]["fingerprints"]={}

    # Save globals
    global scan_folder, scan_id
    scan_folder, scan_id = folder, scan_id_local
    stop_event.clear()

    ui_log(f"Scan folder: {scan_folder}")
    ui_log(f"Starting scan on {len(rows)} target(s), UID {uid_start}-{uid_end}, timeout {timeout_s}s.")
    log_event(logging.INFO, "scan_start", scan_id=scan_id, folder=scan_folder,
              uid_start=uid_start, uid_end=uid_end, timeout_s=timeout_s,
              strict_uid=strict_uid_var.get(), strict_echo=strict_echo_var.get(),
              check_len=check_len_var.get(), fp_only_active=fp_only_active_var.get(),
              qps_delay_ms=qps_delay, jitter_ms=jitter, targets=len(rows))

    # Launch workers
    try:
        max_workers = max(1, min(128, int(concurrency_var.get())))
    except Exception:
        max_workers = MAX_WORKERS_DEFAULT

    executor = ThreadPoolExecutor(max_workers=max_workers)
    futures = []
    for host, port in rows:
        fut = executor.submit(
            recon_job, host, port, uid_start, uid_end, payload_hex, timeout_s,
            strict_uid_var.get(), strict_echo_var.get(), check_len_var.get(),
            fp_only_active_var.get(), qps_delay, jitter
        )
        futures.append(fut)

    def on_done(_futures):
        csv_path = os.path.join(scan_folder, "recon_all.csv")
        try:
            with open(csv_path, "w", newline="") as f:
                w = csv.writer(f)
                w.writerow(["Host","Port","UID","Status","RTT_ms","ResponseHex","Note"])
                w.writerows(recon_rows)
            ui_log(f"Recon CSV saved: {csv_path}")
        except Exception as e:
            ui_log(f"CSV export error: {e}")

        if not recon_rows:
            ui_log("Scan finished: no responses recorded (all targets unreachable / timed out?).")
        elif not any(r[3] == "Active" for r in recon_rows):
            ui_log("Scan finished: 0 Active UIDs found across all targets.")

        for (host,port), st in targets.items():
            ui_log(f"[{host}:{port}] Summary: {st.get('stats',{})}")

        log_event(logging.INFO, "scan_end", scan_id=scan_id)
        stop_log_listeners()

    def waiter():
        for _ in as_completed(futures):
            pass
        root.after(0, on_done, futures)

    threading.Thread(target=waiter, daemon=True).start()

def stop_scan():
    stop_event.set()
    log_event(logging.WARNING, "cancel", scan_id=scan_id)
    ui_log("Stop requested. Workers will finish current request and exit.")

start_scan_btn.config(command=start_scan)
stop_scan_btn.config(command=stop_scan)

def export_recon_csv():
    if not recon_rows:
        messagebox.showinfo("Export Recon", "No recon results yet."); return
    path = filedialog.asksaveasfilename(defaultextension=".csv")
    if not path: return
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["Host","Port","UID","Status","RTT_ms","ResponseHex","Note"])
        w.writerows(recon_rows)
    ui_log(f"Recon CSV exported: {path}")

export_csv_btn.config(command=export_recon_csv)

def clear_recon():
    recon_tree.delete(*recon_tree.get_children())
    recon_rows.clear()
    ui_log("[recon cleared]")

clear_recon_btn.config(command=clear_recon)

def get_selected_targets(scope: str) -> List[Tuple[str,int]]:
    if scope == "all":
        return list(targets.keys())
    sels = []
    for iid in targets_tree.selection():
        vals = targets_tree.item(iid, "values")
        if vals:
            sels.append((vals[0], int(vals[1])))
    return sels

def apply_malicious_toggles(raw_bytes: bytearray):
    if mal_opts["invalid_function"].get() and len(raw_bytes) > 7:
        raw_bytes[7] = 0x99
    if mal_opts["out_of_range_address"].get() and len(raw_bytes) > 9:
        raw_bytes[8] = 0xFF; raw_bytes[9] = 0xFF
    if mal_opts["incorrect_length"].get() and len(raw_bytes) > 5:
        raw_bytes[4] = 0xFF; raw_bytes[5] = 0xFF
    if mal_opts["extra_bytes"].get():
        raw_bytes += bytes.fromhex("DEADBEEF")
    if mal_opts["corrupted_header"].get() and len(raw_bytes) > 3:
        raw_bytes[2] = 0xFF; raw_bytes[3] = 0xFF
    return raw_bytes

def send_packet():
    scope = send_scope_var.get()
    tgts = get_selected_targets(scope)
    if not tgts:
        messagebox.showinfo("Send", "No targets selected."); return
    hex_data = hex_entry.get().strip().replace(" ","")
    try:
        raw = bytearray.fromhex(hex_data)
    except Exception:
        messagebox.showerror("Hex", "Invalid hex."); return
    raw = apply_malicious_toggles(raw)
    hex_render = raw.hex()
    ui_log(f"Sending to {len(tgts)} target(s): {hex_render[:120]}{'...' if len(hex_render)>120 else ''}")
    timeout_s = 2.0
    for host, port in tgts:
        try:
            with socket.create_connection((host, port), timeout=timeout_s) as s:
                s.sendall(raw)
                s.settimeout(timeout_s)
                resp = s.recv(4096)
            rh = resp.hex()
            ui_log(f"[{host}:{port}] resp: {rh[:160]}{'...' if len(rh)>160 else ''}")
            log_event(logging.INFO, "send_resp", scan_id=scan_id, host=host, port=port,
                      resp_len=len(resp), resp_hex_prefix=rh[:100])
            recon_tree.insert("", tk.END, values=(host, port, "-", "SEND", "", rh, "manual"))
        except Exception as e:
            ui_log(f"[{host}:{port}] send error: {e}")
            log_event(logging.ERROR, "send_error", scan_id=scan_id, host=host, port=port, error=str(e))

send_btn.config(command=send_packet)

# ------------------------------ Shutdown -------------------------------------
def on_close():
    try:
        stop_event.set()
        if executor: executor.shutdown(wait=False, cancel_futures=True)
        stop_log_listeners()
        # persist output dir entry on close
        settings["output_dir"] = output_dir_var.get().strip()
        save_settings()
    except Exception:
        pass
    root.destroy()

root.protocol("WM_DELETE_WINDOW", on_close)

ui_log("Ready. Add targets (CIDR, range, or host:port), then Start Scan.")
ui_log("Note: If no server is running, you should still see Error/No Reply rows.")
root.mainloop()
