#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import tkinter as tk
from tkinter import scrolledtext, filedialog, ttk, messagebox
import socket
import datetime
import struct
import time
import csv

# ------------------------------ Globals ------------------------------
logs = []                 # main app logs (in-memory)
recon_rows = []           # (uid, status, rtt_ms, resp_hex, note)
# fingerprints: key -> {"uids":[...], "pdu_hex": str, "vendor": str, "product": str, "rev": str}
fingerprints = {}
session_sock = None       # optional "connected" test socket

# ------------------------------ GUI Root ------------------------------
root = tk.Tk()
root.title("Raw Modbus TCP Sender (Recon, Strict Validation, Fingerprinting)")
root.geometry("1100x900")

# ============================== MAIN LOG FIRST ===============================
log_section = tk.LabelFrame(root, text="Main Log")
log_section.pack(fill="both", padx=10, pady=(10, 8))
output_text = scrolledtext.ScrolledText(log_section, width=140, height=12, wrap="none")
output_text.pack(fill="both", expand=True)
log_scroll_x = ttk.Scrollbar(log_section, orient="horizontal", command=output_text.xview)
output_text.configure(xscrollcommand=log_scroll_x.set); log_scroll_x.pack(fill="x")

def log_main(msg: str):
    """Append to the visible main log and to the in-memory list."""
    output_text.insert(tk.END, msg)
    output_text.see(tk.END)
    logs.append(msg)

def clear_main_log():
    """Clear main log UI and in-memory list."""
    output_text.delete("1.0", tk.END)
    logs.clear()
    output_text.insert(tk.END, "[Main log cleared]\n")
    output_text.see(tk.END)

def export_log():
    if not logs:
        output_text.insert(tk.END, "\nNo logs to export.\n"); output_text.see(tk.END)
        return
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
    if file_path:
        with open(file_path, "w") as f: f.writelines(logs)
        output_text.insert(tk.END, f"\nLogs saved to: {file_path}\n"); output_text.see(tk.END)

# helper to write in both recon + main logs consistently
def log_both(msg: str):
    recon_output_text.insert(tk.END, msg)
    recon_output_text.see(tk.END)
    log_main(msg)

# ------------------------------ Connection Row ------------------------------
conn_frame = tk.Frame(root)
conn_frame.pack(fill="x", padx=10, pady=(4, 0))

tk.Label(conn_frame, text="Target (Host/IP):").pack(side=tk.LEFT)
ip_entry = tk.Entry(conn_frame, width=28); ip_entry.insert(0, "127.0.0.1"); ip_entry.pack(side=tk.LEFT, padx=(5, 12))

tk.Label(conn_frame, text="Port:").pack(side=tk.LEFT)
port_entry = tk.Entry(conn_frame, width=8); port_entry.insert(0, "5020"); port_entry.pack(side=tk.LEFT, padx=(5, 12))

status_label = tk.Label(conn_frame, text="🔴 Disconnected", fg="red")
status_label.pack(side=tk.LEFT, padx=(8, 12))

def connect_server():
    global session_sock
    ip = ip_entry.get().strip()
    try:
        port = int(port_entry.get().strip())
    except ValueError:
        messagebox.showerror("Input Error", "Port must be an integer.")
        return
    try:
        if session_sock:
            try: session_sock.close()
            except Exception: pass
            session_sock = None
        session_sock = socket.create_connection((ip, port), timeout=2)
        status_label.config(text="🟢 Connected", fg="green")
        log_main(f"[{datetime.datetime.now()}] Connected to {ip}:{port}\n")
    except Exception as e:
        status_label.config(text="🔴 Disconnected", fg="red")
        log_main(f"[{datetime.datetime.now()}] Connect to {ip}:{port} failed: {e}\n")

def disconnect_server():
    global session_sock
    ip = ip_entry.get().strip()
    port = port_entry.get().strip()
    if session_sock:
        try: session_sock.close()
        except Exception: pass
        session_sock = None
    status_label.config(text="🔴 Disconnected", fg="red")
    log_main(f"[{datetime.datetime.now()}] Disconnected from {ip}:{port}\n")

btn_frame_conn = tk.Frame(root)
btn_frame_conn.pack(fill="x", padx=10, pady=(6, 8))
tk.Button(btn_frame_conn, text="Connect", width=12, command=connect_server).pack(side=tk.LEFT, padx=(0, 6))
tk.Button(btn_frame_conn, text="Disconnect", width=12, command=disconnect_server).pack(side=tk.LEFT, padx=(0, 6))
tk.Button(btn_frame_conn, text="Clear Main Log", width=14, command=clear_main_log).pack(side=tk.LEFT, padx=(12, 0))
tk.Button(btn_frame_conn, text="Export Main Log", width=14, command=export_log).pack(side=tk.LEFT, padx=(6, 0))

# ------------------------------ Malicious Options ------------------------------
malicious_frame = tk.LabelFrame(root, text="Malicious Packet Crafting Options")
malicious_frame.pack(fill="x", padx=10, pady=5)

malicious_options = {
    "invalid_function": tk.BooleanVar(),
    "out_of_range_address": tk.BooleanVar(),
    "incorrect_length": tk.BooleanVar(),
    "extra_bytes": tk.BooleanVar(),
    "corrupted_header": tk.BooleanVar()
}
tk.Checkbutton(malicious_frame, text="Invalid Function Code", variable=malicious_options["invalid_function"]).pack(anchor='w')
tk.Checkbutton(malicious_frame, text="Out-of-Range Address", variable=malicious_options["out_of_range_address"]).pack(anchor='w')
tk.Checkbutton(malicious_frame, text="Incorrect Length Field", variable=malicious_options["incorrect_length"]).pack(anchor='w')
tk.Checkbutton(malicious_frame, text="Extra Bytes in Payload", variable=malicious_options["extra_bytes"]).pack(anchor='w')
tk.Checkbutton(malicious_frame, text="Corrupted MBAP Header", variable=malicious_options["corrupted_header"]).pack(anchor='w')

# ------------------------------ Predefined Hex Presets ------------------------------
def fill_predef_packet(event=None):
    val = mal_predef.get()
    preset = ""
    if val == "Invalid Function Code packet":
        preset = "000100000006019900000001"
    elif val == "Out-of-range coil read":
        preset = "0001000000060101FFFF0001"
    elif val == "Incomplete PDU with fake length":
        preset = "00010000001001030000"
    elif val == "Malformed multi-coil write":
        preset = "000100000009010F00000102"
    elif val == "Valid packet with trailing junk":
        preset = "000100000006010300000001DEADBEEF"
    hex_entry.delete(0, tk.END)
    hex_entry.insert(0, preset)

mal_predef = ttk.Combobox(malicious_frame, values=[
    "Invalid Function Code packet",
    "Out-of-range coil read",
    "Incomplete PDU with fake length",
    "Malformed multi-coil write",
    "Valid packet with trailing junk"
], state="readonly", width=40)
mal_predef.pack(anchor="w", padx=10, pady=3)
mal_predef.bind("<<ComboboxSelected>>", fill_predef_packet)

# ------------------------------ Manual Hex Input ------------------------------
tk.Label(root, text="Enter Full Hex Packet:").pack(anchor='w', padx=10)
hex_entry = tk.Entry(root, width=140)
hex_entry.pack(anchor='w', padx=10, pady=5)

# ------------------------------ Subfield Inputs ------------------------------
subfield_toggle_var = tk.BooleanVar()
subfield_toggle = tk.Checkbutton(root, text="Use Subfield Inputs", variable=subfield_toggle_var)
subfield_toggle.pack(anchor='w', padx=10)

subfield_frame = tk.Frame(root)
subfield_frame.pack(anchor='w', padx=10)
subfield_entries = []
subfield_labels = ["Transaction ID", "Protocol ID", "Length", "Unit ID", "Function Code", "Data"]

for i, label in enumerate(subfield_labels):
    tk.Label(subfield_frame, text=label).grid(row=0, column=i, padx=2)
    if label == "Function Code":
        fcode_var = tk.StringVar()
        fcode_dropdown = ttk.Combobox(subfield_frame, textvariable=fcode_var, width=18)
        fcode_dropdown['values'] = [
            "01 Read Coils", "02 Read Discrete Inputs", "03 Read Holding Registers",
            "04 Read Input Registers", "05 Write Single Coil", "06 Write Single Register",
            "0F Write Multiple Coils", "10 Write Multiple Registers",
            "11 Report Slave ID", "17 Read/Write Multiple Registers"
        ]
        fcode_dropdown.set("01 Read Coils")
        fcode_dropdown.bind("<<ComboboxSelected>>", lambda e: autofill_data())
        fcode_dropdown.grid(row=1, column=i, padx=2)
        subfield_entries.append(fcode_dropdown)
    elif label == "Data":
        data_frame = tk.Frame(subfield_frame)
        data_frame.grid(row=1, column=i, padx=2)
        global sub_data_entries
        sub_data_entries = []
        sub_data_labels = ["Start Addr", "Quantity/Value", "Byte Count", "Payload"]
        for j in range(4):
            tk.Label(data_frame, text=sub_data_labels[j]).grid(row=0, column=j, padx=1)
            entry = tk.Entry(data_frame, width=8)
            entry.grid(row=1, column=j, padx=1)
            sub_data_entries.append(entry)
        subfield_entries.append(data_frame)
    else:
        entry = tk.Entry(subfield_frame, width=12)
        entry.grid(row=1, column=i, padx=2)
        subfield_entries.append(entry)

def autofill_data():
    selected_code = fcode_var.get().split()[0]
    default_values = {
        "01": ["0001", "0000", "0006", "01", "01", ["0000", "0001", "", ""]],
        "02": ["0001", "0000", "0006", "01", "02", ["0000", "0001", "", ""]],
        "03": ["0001", "0000", "0006", "01", "03", ["0000", "0001", "", ""]],
        "04": ["0001", "0000", "0006", "01", "04", ["0000", "0001", "", ""]],
        "05": ["0001", "0000", "0006", "01", "05", ["0001", "FF00", "", ""]],
        "06": ["0001", "0000", "0006", "01", "06", ["0001", "000A", "", ""]],
        "0F": ["0001", "0000", "0008", "01", "0F", ["0000", "0001", "01", "FF"]],
        "10": ["0001", "0000", "0009", "01", "10", ["0000", "0001", "02", "000A"]],
        "11": ["0001", "0000", "0002", "01", "11", ["", "", "", ""]],
        "17": ["0001", "0000", "000B", "01", "17", ["0000", "0001", "0000", "0002"]],
    }
    if selected_code in default_values:
        tid, pid, length, uid, fcode, data_parts = default_values[selected_code]
        subfield_entries[0].delete(0, tk.END); subfield_entries[0].insert(0, tid)
        subfield_entries[1].delete(0, tk.END); subfield_entries[1].insert(0, pid)
        subfield_entries[2].delete(0, tk.END); subfield_entries[2].insert(0, length)
        subfield_entries[3].delete(0, tk.END); subfield_entries[3].insert(0, uid)
        fcode_var.set(selected_code)
        for i in range(4):
            sub_data_entries[i].delete(0, tk.END)
            sub_data_entries[i].insert(0, data_parts[i])

# ------------------------------ Raw Send ------------------------------
def send_raw_packet():
    ip = ip_entry.get().strip()
    try:
        port = int(port_entry.get().strip())
    except ValueError:
        messagebox.showerror("Input Error", "Port must be an integer.")
        return

    use_subfields = subfield_toggle_var.get()
    if use_subfields:
        hex_parts = []
        for i, entry in enumerate(subfield_entries):
            if i == 4:
                val = fcode_var.get().split()[0]
            elif i == 5:
                val = "".join(e.get().strip() for e in sub_data_entries)
            else:
                val = entry.get().strip()
            if val != "":
                hex_parts.append(val)
        hex_data = "".join(hex_parts)
    else:
        hex_data = hex_entry.get().replace(" ", "")

    try:
        raw_bytes = bytearray.fromhex(hex_data)
        if malicious_options["invalid_function"].get() and len(raw_bytes) > 7:
            raw_bytes[7] = 0x99
        if malicious_options["out_of_range_address"].get() and len(raw_bytes) > 9:
            raw_bytes[8] = 0xFF; raw_bytes[9] = 0xFF
        if malicious_options["incorrect_length"].get() and len(raw_bytes) > 5:
            raw_bytes[4] = 0xFF; raw_bytes[5] = 0xFF
        if malicious_options["extra_bytes"].get():
            raw_bytes += bytes.fromhex("DEADBEEF")
        if malicious_options["corrupted_header"].get() and len(raw_bytes) > 3:
            raw_bytes[2] = 0xFF; raw_bytes[3] = 0xFF

        hex_render = raw_bytes.hex()
        log_main(f"\n===== SENDING RAW MODBUS TCP PACKET =====\nHex Input: {hex_render}\n")

        with socket.create_connection((ip, port), timeout=2) as s:
            s.sendall(raw_bytes)
            s.settimeout(2)
            response = s.recv(4096)
            response_hex = response.hex()
            log_main(f"Response Packet (Hex): {response_hex}\n")

            decoded_log = f"\n===== DECODED RESPONSE PACKET =====\n"
            if len(response) >= 9:
                tid = response[0:2].hex()
                pid = response[2:4].hex()
                length = response[4:6].hex()
                uid = response[6:7].hex()
                fc = response[7]
                decoded_log += f"Byte 0-1: Transaction ID = {tid}\n"
                decoded_log += f"Byte 2-3: Protocol ID = {pid}\n"
                decoded_log += f"Byte 4-5: Length = {length}\n"
                decoded_log += f"Byte 6:   Unit ID = {uid}\n"
                decoded_log += f"Byte 7:   Function Code = {fc:02X}\n"
                if fc >= 0x80 and len(response) >= 9:
                    exception_code = response[8]
                    msg = {
                        0x01:"Illegal Function",
                        0x02:"Illegal Data Address",
                        0x03:"Illegal Data Value",
                        0x04:"Server Device Failure"
                    }.get(exception_code, "Unknown Error")
                    decoded_log += f"Byte 8:   Exception Code = {exception_code:02X} - {msg}\n"
                elif fc in [0x01, 0x02] and len(response) >= 9:
                    byte_count = response[8]
                    decoded_log += f"Byte 8:   Byte Count = {byte_count}\n"
                    shown_bits = 0
                    for b in response[9:9 + byte_count]:
                        for i in range(8):
                            decoded_log += f"Bit {shown_bits + 1} = {(b >> i) & 0x01}\n"
                            shown_bits += 1
                elif fc in [0x03, 0x04] and len(response) >= 9:
                    byte_count = response[8]
                    regs = []
                    for i in range(0, byte_count, 2):
                        if 9 + i + 2 <= len(response):
                            regs.append(str(struct.unpack('>H', response[9+i:11+i])[0]))
                    decoded_log += f"Byte 8:   Byte Count = {byte_count}\n"
                    decoded_log += f"Byte 9+:  Decoded Registers = {', '.join(regs)}\n"
                elif fc in [0x05, 0x06, 0x10] and len(response) >= 12:
                    address = int.from_bytes(response[8:10], 'big')
                    value = int.from_bytes(response[10:12], 'big')
                    decoded_log += f"Byte 8-9: Address = {address} (0x{address:04X})\n"
                    decoded_log += f"Byte 10-11: Value = {value} (0x{value:04X})\n"
            log_main(decoded_log)
    except Exception as e:
        log_main(f"Error: {e}\n")

button_frame = tk.Frame(root); button_frame.pack(pady=8)
tk.Button(button_frame, text="Send Packet", width=14, command=send_raw_packet).pack(side=tk.LEFT, padx=6)

# ------------------------------ Recon Panel ------------------------------
recon_frame = tk.LabelFrame(root, text="Recon – Active UID Scan (Diagnostic Echo) with Strict Validation")
recon_frame.pack(fill="both", padx=10, pady=6)

frm_line = tk.Frame(recon_frame); frm_line.pack(fill="x", padx=8, pady=4)

tk.Label(frm_line, text="UID Start:").pack(side=tk.LEFT)
uid_start_entry = tk.Entry(frm_line, width=5); uid_start_entry.insert(0, "1"); uid_start_entry.pack(side=tk.LEFT, padx=5)

tk.Label(frm_line, text="UID End:").pack(side=tk.LEFT)
uid_end_entry = tk.Entry(frm_line, width=5); uid_end_entry.insert(0, "16"); uid_end_entry.pack(side=tk.LEFT, padx=5)

tk.Label(frm_line, text="Echo Payload (hex, 2 bytes):").pack(side=tk.LEFT, padx=(12, 0))
echo_payload_entry = tk.Entry(frm_line, width=8); echo_payload_entry.insert(0, "1234"); echo_payload_entry.pack(side=tk.LEFT, padx=5)

tk.Label(frm_line, text="Timeout (s):").pack(side=tk.LEFT, padx=(12, 0))
timeout_entry = tk.Entry(frm_line, width=5); timeout_entry.insert(0, "1.5"); timeout_entry.pack(side=tk.LEFT, padx=5)

# Validation toggles
strict_uid_match = tk.BooleanVar(value=True)
strict_echo_check = tk.BooleanVar(value=True)
fingerprint_after_active = tk.BooleanVar(value=True)
check_mbap_len = tk.BooleanVar(value=True)

tk.Checkbutton(frm_line, text="Strict UID/TID match", variable=strict_uid_match).pack(side=tk.LEFT, padx=8)
tk.Checkbutton(frm_line, text="Strict Echo validation", variable=strict_echo_check).pack(side=tk.LEFT, padx=8)
tk.Checkbutton(frm_line, text="Fingerprint ONLY Active UIDs (0x2B/0x0E)", variable=fingerprint_after_active).pack(side=tk.LEFT, padx=8)
tk.Checkbutton(frm_line, text="Check MBAP LEN consistency", variable=check_mbap_len).pack(side=tk.LEFT, padx=8)

# Scan / Export / Clear buttons
frm_actions = tk.Frame(recon_frame); frm_actions.pack(fill="x", padx=8, pady=(2, 4))
scan_btn = tk.Button(frm_actions, text="Start Scan", width=14)
export_recon_btn = tk.Button(frm_actions, text="Export Recon CSV", width=16)
clear_recon_btn = tk.Button(frm_actions, text="Clear Recon Results", width=16)

scan_btn.pack(side=tk.LEFT, padx=4)
export_recon_btn.pack(side=tk.LEFT, padx=4)
clear_recon_btn.pack(side=tk.LEFT, padx=4)

# Results table (APPENDS across scans)
tree = ttk.Treeview(recon_frame, columns=("uid", "status", "rtt", "resp", "note"), show="headings", height=10)
for col, txt, w in [("uid","UID",60),("status","Status",120),("rtt","RTT (ms)",90),("resp","Response (hex)",600),("note","Note",220)]:
    tree.heading(col, text=txt); tree.column(col, width=w, anchor=("e" if col=="rtt" else "w"))
tree.column("uid", anchor="center"); tree.column("status", anchor="center")
tree.pack(fill="both", padx=8, pady=(0,6))
tree_scroll_x = ttk.Scrollbar(recon_frame, orient="horizontal", command=tree.xview)
tree.configure(xscrollcommand=tree_scroll_x.set); tree_scroll_x.pack(fill="x", padx=8)

# Recon Log (separate from main log) + Clear button
recon_log_frame = tk.Frame(recon_frame)
recon_log_frame.pack(fill="both", padx=8, pady=(6, 8))
tk.Label(recon_log_frame, text="Recon Log:").pack(anchor="w")
recon_output_text = scrolledtext.ScrolledText(recon_log_frame, width=140, height=12, wrap="none")
recon_output_text.pack(fill="both", expand=True)
recon_log_scroll_x = ttk.Scrollbar(recon_log_frame, orient="horizontal", command=recon_output_text.xview)
recon_output_text.configure(xscrollcommand=recon_log_scroll_x.set); recon_log_scroll_x.pack(fill="x")
tk.Button(recon_log_frame, text="Clear Recon Log", width=16, command=lambda: recon_output_text.delete("1.0", tk.END)).pack(anchor="e", pady=(4,0))

# ------------------------------ Recon Helpers ------------------------------
def build_diag_echo_request(uid: int, payload_hex: str, tid: int) -> bytes:
    # PDU: 08 0000 <2 bytes payload>
    data = bytes.fromhex(payload_hex)
    if len(data) != 2:
        raise ValueError("Echo payload must be exactly 2 bytes (e.g., 1234).")
    pdu = bytes([0x08]) + (0).to_bytes(2,'big') + data
    length = 1 + len(pdu)  # UID + PDU
    mbap = tid.to_bytes(2,'big') + (0).to_bytes(2,'big') + length.to_bytes(2,'big') + bytes([uid])
    return mbap + pdu

def build_dev_id_req(uid: int, tid: int) -> bytes:
    # FC=0x2B, MEI=0x0E, Read Device ID (Basic 0x01, object 0)
    pdu = bytes([0x2B, 0x0E, 0x01, 0x00])
    length = 1 + len(pdu)
    mbap = tid.to_bytes(2,'big') + (0).to_bytes(2,'big') + length.to_bytes(2,'big') + bytes([uid])
    return mbap + pdu

def mbap_len_ok(resp: bytes) -> bool:
    if len(resp) < 7: return False
    declared_len = int.from_bytes(resp[4:6], 'big')
    return declared_len == (len(resp) - 6)

def validate_echo_response_verbose(resp: bytes, expect_tid: int, expect_uid: int, expect_payload: bytes, do_uid: bool, do_echo: bool, do_len: bool):
    """
    Return (ok: bool, checks: list[(label, ok, detail)])
    We produce granular checks for logging.
    """
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

# -------- Device ID decoding & canonical key --------
def parse_devid_basic(dev: bytes):
    """
    Parse a Read Device Identification (0x2B/0x0E) response (Basic objects).
    Returns (ok, vendor, product, rev, pdu_hex).
    """
    if len(dev) < 12:  # MBAP(7) + at least FC/MEI + minimal fields
        return False, "", "", "", ""
    if dev[7] != 0x2B or dev[8] != 0x0E:
        return False, "", "", "", dev[7:].hex()

    pdu = dev[7:]  # FC onward
    i = 2  # start after FC(0x2B), MEI(0x0E)
    if len(pdu) < i + 5:
        return False, "", "", "", pdu.hex()

    read_code = pdu[i]; i += 1  # 0x01 expected (Basic)
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
        val = pdu[i:i+size]; i += size
        try:
            text = val.decode('utf-8', errors='ignore')
        except Exception:
            text = ""
        if obj_id == 0x00: vendor = text
        elif obj_id == 0x01: product = text
        elif obj_id == 0x02: rev = text

    return True, vendor, product, rev, pdu.hex()

def canonical_devid_key(vendor: str, product: str, rev: str) -> str:
    return f"{vendor}|{product}|{rev}".strip()

# ------------------------------ Recon Core ------------------------------
def scan_uids():
    ip = ip_entry.get().strip()
    try:
        port = int(port_entry.get().strip())
    except ValueError:
        messagebox.showerror("Input Error", "Port must be an integer.")
        return

    try:
        uid_start = int(uid_start_entry.get()); uid_end = int(uid_end_entry.get())
    except ValueError:
        messagebox.showerror("Input Error", "UID Start/End must be integers."); return
    if not (1 <= uid_start <= 247 and 1 <= uid_end <= 247) or uid_start > uid_end:
        messagebox.showerror("Input Error", "UID range must be 1..247 and Start ≤ End."); return

    payload_hex = echo_payload_entry.get().strip().replace(" ", "")
    try:
        payload = bytes.fromhex(payload_hex)
        if len(payload) != 2:
            raise ValueError
    except Exception:
        messagebox.showerror("Input Error", "Echo payload must be exactly 2 hex bytes (e.g., 1234)."); return

    try:
        timeout_s = float(timeout_entry.get())
    except ValueError:
        timeout_s = 1.5

    head = f"\n===== ACTIVE UID SCAN (strict_uid={strict_uid_match.get()}, strict_echo={strict_echo_check.get()}, mbap_len={check_mbap_len.get()}) {ip}:{port} =====\n"
    log_both(head)

    for uid in range(uid_start, uid_end + 1):
        # ---------- Build Echo Request ----------
        try:
            tid = uid  # TID==UID for simple correlation
            req = build_diag_echo_request(uid, payload_hex, tid)
            req_hex = req.hex()
        except Exception as e:
            log_both(f"[UID {uid}] Build error: {e}\n")
            continue

        # ---------- Send Echo ----------
        try:
            log_both(f"[UID {uid}] >>> Echo Request: {req_hex}\n")
            t0 = time.monotonic()
            with socket.create_connection((ip, port), timeout=timeout_s) as s:
                s.sendall(req)
                s.settimeout(timeout_s)
                resp = s.recv(4096)
            t1 = time.monotonic(); rtt_ms = int((t1 - t0) * 1000)
            resp_hex = resp.hex()
            log_both(f"[UID {uid}] <<< Echo Response: {resp_hex} (RTT={rtt_ms} ms)\n")

            # ---------- Validate Echo (granular) ----------
            ok, checks = validate_echo_response_verbose(
                resp, expect_tid=tid, expect_uid=uid, expect_payload=payload,
                do_uid=strict_uid_match.get(),
                do_echo=strict_echo_check.get(),
                do_len=check_mbap_len.get()
            )
            for label, passed, detail in checks:
                log_both(f"[UID {uid}]    {label}: {'[OK]' if passed else '[FAIL]'} ({detail})\n")

            status = "Active" if ok else "Rejected"
            note = "OK" if ok else "Validation failed"
            row = (str(uid), status, str(rtt_ms), resp_hex, note)
            recon_rows.append(row)
            tree.insert("", tk.END, values=row)

            # ---------- Fingerprint (only when Active + option) ----------
            if ok and fingerprint_after_active.get():
                try:
                    dev_req = build_dev_id_req(uid, tid)
                    dev_req_hex = dev_req.hex()
                    log_both(f"[UID {uid}] >>> DevID Request: {dev_req_hex}\n")
                    with socket.create_connection((ip, port), timeout=timeout_s) as s2:
                        s2.sendall(dev_req)
                        s2.settimeout(timeout_s)
                        dev = s2.recv(4096)
                    dev_hex = dev.hex()
                    log_both(f"[UID {uid}] <<< DevID Response: {dev_hex}\n")

                    # Parse & build canonical key
                    ok_dev, vendor, product, rev, pdu_hex = parse_devid_basic(dev)
                    log_both(f"[UID {uid}]    FC==0x2B & MEI==0x0E: {'[OK]' if (len(dev)>=10 and dev[7]==0x2B and dev[8]==0x0E) else '[FAIL]'}\n")
                    if ok_dev:
                        key = canonical_devid_key(vendor, product, rev)
                        if key not in fingerprints:
                            fingerprints[key] = {"uids": [], "pdu_hex": pdu_hex, "vendor": vendor, "product": product, "rev": rev}
                        if uid not in fingerprints[key]["uids"]:
                            fingerprints[key]["uids"].append(uid)
                        log_both(f"[UID {uid}]    Device ID captured -> Vendor='{vendor}', Product='{product}', Rev='{rev}'\n")
                    else:
                        # fall back to grouping by PDU-only hex if parsing failed
                        pdu_fallback = dev[7:].hex() if len(dev) >= 7 else dev.hex()
                        key = f"HEX:{pdu_fallback}"
                        if key not in fingerprints:
                            fingerprints[key] = {"uids": [], "pdu_hex": pdu_fallback, "vendor": "", "product": "", "rev": ""}
                        if uid not in fingerprints[key]["uids"]:
                            fingerprints[key]["uids"].append(uid)
                        log_both(f"[UID {uid}]    Device ID parsed inadequately; grouped by PDU hex.\n")

                except Exception as fe:
                    log_both(f"[UID {uid}] Device ID error: {fe}\n")

        except socket.timeout:
            row = (str(uid), "No Reply", "", "", "timeout")
            recon_rows.append(row); tree.insert("", tk.END, values=row)
            log_both(f"[UID {uid}] No reply (timeout)\n")
        except Exception as e:
            row = (str(uid), "Error", "", "", str(e))
            recon_rows.append(row); tree.insert("", tk.END, values=row)
            log_both(f"[UID {uid}] Error: {e}\n")

    # ---------- Fingerprint summary ----------
    if fingerprint_after_active.get() and fingerprints:
        log_both("\n--- Device ID fingerprint groups (Active UIDs only) ---\n")
        for key, info in fingerprints.items():
            uids = info["uids"]
            vendor, product, rev = info["vendor"], info["product"], info["rev"]
            pdu_hex = info["pdu_hex"]
            prefix = pdu_hex[:60] + ("..." if len(pdu_hex) > 60 else "")
            if vendor or product or rev:
                label = f"{vendor}|{product}|{rev}"
            else:
                label = f"PDU={prefix}"
            if len(uids) > 1:
                log_both(f"UIDs {uids} share Device ID: {label}\n")
            else:
                log_both(f"UID {uids[0]} has unique Device ID: {label}\n")

# ------------------------------ Recon CSV & Clear ------------------------------
def export_recon_csv():
    if not recon_rows:
        messagebox.showinfo("Export Recon", "No recon results to export yet."); return
    file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV Files", "*.csv")])
    if not file_path: return
    try:
        with open(file_path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["UID", "Status", "RTT_ms", "ResponseHex", "Note"])
            w.writerows(recon_rows)
        msg = f"Recon CSV saved to: {file_path}\n"
        log_main(msg)
    except Exception as e:
        messagebox.showerror("Export Error", f"Failed to save CSV: {e}")

def clear_recon_results():
    global recon_rows, fingerprints
    tree.delete(*tree.get_children())
    recon_rows = []
    fingerprints = {}
    recon_output_text.insert(tk.END, f"[{datetime.datetime.now()}] Recon results cleared.\n"); recon_output_text.see(tk.END)

scan_btn.config(command=scan_uids)
export_recon_btn.config(command=export_recon_csv)
clear_recon_btn.config(command=clear_recon_results)

# ------------------------------ Mainloop ------------------------------
root.mainloop()
