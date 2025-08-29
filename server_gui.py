#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import tkinter as tk
from tkinter import ttk, messagebox
import asyncio
import threading
import sys
import logging

from pymodbus.server import StartAsyncTcpServer
from pymodbus.datastore import (
    ModbusServerContext, ModbusSlaveContext, ModbusSequentialDataBlock
)
from pymodbus.device import ModbusDeviceIdentification

# ----------------------------
# Logging -> helpful to see drops/decodes
# ----------------------------
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("modbus.server")

# ----------------------------
# DualZeroOneDataBlock:
#   - Accepts either 0-based or 1-based addresses from the server stack
#   - Still enforces strict range; outside -> validate(False) -> 0x02
# ----------------------------
class DualZeroOneDataBlock(ModbusSequentialDataBlock):
    def __init__(self, address, values):
        super().__init__(address, values)
        self._end = self.address + len(self.values) - 1

    def _in_range(self, addr, count):
        return self.address <= addr <= self._end and (addr + count - 1) <= self._end

    def _normalize(self, address, count):
        # Prefer 0-based; if not, try 1-based
        if self._in_range(address, count):
            return address
        alt = address - 1
        if self._in_range(alt, count):
            return alt
        return None

    def validate(self, address, count=1):
        ok = self._normalize(address, count) is not None
        return ok  # False triggers exception 0x02 upstream

    def getValues(self, address, count=1):
        base = self._normalize(address, count)
        if base is None:
            # Let server map this to 0x02; raising IndexError is OK here too.
            raise IndexError("Illegal Data Address")
        return super().getValues(base, count)

    def setValues(self, address, values):
        count = len(values)
        base = self._normalize(address, count)
        if base is None:
            raise IndexError("Illegal Data Address")
        return super().setValues(base, values)


# ----------------------------
# Helpers: build a data store
# ----------------------------
def make_slave_context():
    # Ranges: HR 0..99, IR 0..99, DI 0..99, CO 0..19
    store = ModbusSlaveContext(
        hr=DualZeroOneDataBlock(0, [0] * 100),   # Holding Registers
        ir=DualZeroOneDataBlock(0, [0] * 100),   # Input Registers
        di=DualZeroOneDataBlock(0, [0] * 100),   # Discrete Inputs
        co=DualZeroOneDataBlock(0, [0] * 20),    # Coils
        # Some pymodbus versions don't accept zero_mode in ctor; set below if present
    )
    # Try to prefer zero-based addressing if the attribute exists
    try:
        store.zero_mode = True
    except Exception:
        pass
    return store


# ----------------------------
# Identity (used by 0x11 and 0x2B/0x0E if present)
# ----------------------------
identity = ModbusDeviceIdentification()
identity.VendorName          = "Modbus SERVER GUI"
identity.ProductCode         = "MODSERV"
identity.ProductName         = "Modbus Server"
identity.ModelName           = "MODSERV GUI"
identity.MajorMinorRevision  = "1.0"
identity.VendorUrl           = "http://localhost"
identity.UserApplicationName = "DemoApp"
identity.ApplicationVersion  = "1.0.0"

def set_identity_triplet(vendor: str, product: str, rev: str):
    vendor  = (vendor or "").strip()  or "Vendor"
    product = (product or "").strip() or "Product"
    rev     = (rev or "").strip()     or "1.0"
    identity.VendorName         = vendor
    identity.ProductCode        = product
    identity.MajorMinorRevision = rev
    identity.ModelName          = vendor
    identity.ProductName        = f"{vendor} {product}"

# Prime once
set_identity_triplet(identity.VendorName, identity.ProductCode, identity.MajorMinorRevision)

# ----------------------------
# GUI App
# ----------------------------
class ModbusServerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Modbus GUI Server")

        # Shared data store + context
        self.store = make_slave_context()
        self.context = ModbusServerContext(slaves=self.store, single=True)

        # Thread handle
        self._server_thread = None

        # Bind and port
        self.bind_ip_var = tk.StringVar(value="0.0.0.0")
        self.port_var    = tk.StringVar(value="5020")

        # Identity triplet
        self.vendor_var  = tk.StringVar(value=identity.VendorName)
        self.product_var = tk.StringVar(value=identity.ProductCode)
        self.rev_var     = tk.StringVar(value=identity.MajorMinorRevision)

        # UID enforcement
        self.enforce_uid_var = tk.BooleanVar(value=False)
        self.allowed_uid_var = tk.StringVar(value="1")

        # ---------- Top controls ----------
        top = tk.Frame(root); top.pack(fill="x", padx=8, pady=6)
        tk.Label(top, text="Bind IP:").pack(side=tk.LEFT)
        tk.Entry(top, textvariable=self.bind_ip_var, width=14).pack(side=tk.LEFT, padx=(4,10))
        tk.Label(top, text="Port:").pack(side=tk.LEFT)
        tk.Entry(top, textvariable=self.port_var, width=8).pack(side=tk.LEFT, padx=(4,12))
        tk.Button(top, text="Start Server", command=self.start_server, width=12).pack(side=tk.LEFT, padx=(0,6))
        tk.Button(top, text="Stop Server",  command=self.stop_server,  width=12).pack(side=tk.LEFT)
        self.status_label = tk.Label(top, text="Status: Stopped", fg="red")
        self.status_label.pack(side=tk.LEFT, padx=(12,0))

        # ---------- Device ID editor ----------
        idf = tk.LabelFrame(root, text="Device Identification (0x11 & 0x2B/0x0E)")
        idf.pack(fill="x", padx=8, pady=(0,8))

        tk.Label(idf, text="Vendor:").grid(row=0, column=0, sticky="w", padx=6, pady=4)
        tk.Entry(idf, textvariable=self.vendor_var, width=28).grid(row=0, column=1, sticky="w")

        tk.Label(idf, text="Product:").grid(row=0, column=2, sticky="w", padx=12)
        tk.Entry(idf, textvariable=self.product_var, width=22).grid(row=0, column=3, sticky="w")

        tk.Label(idf, text="Revision:").grid(row=0, column=4, sticky="w", padx=12)
        tk.Entry(idf, textvariable=self.rev_var, width=10).grid(row=0, column=5, sticky="w")

        tk.Button(idf, text="Apply Device ID", command=self.apply_device_id, width=16).grid(row=0, column=6, padx=12)

        # ---------- Unit ID enforcement ----------
        uidf = tk.LabelFrame(root, text="Unit ID Enforcement")
        uidf.pack(fill="x", padx=8, pady=(0,8))
        tk.Checkbutton(uidf, text="Enforce Unit ID", variable=self.enforce_uid_var,
                       command=self.apply_uid_enforcement).pack(side=tk.LEFT, padx=(6,10))
        tk.Label(uidf, text="Allowed UID:").pack(side=tk.LEFT)
        tk.Entry(uidf, textvariable=self.allowed_uid_var, width=6).pack(side=tk.LEFT, padx=(6,10))

        # Effective config line
        self.config_status = tk.Label(root, text=self._format_config_status(), fg="blue")
        self.config_status.pack(fill="x", padx=8, pady=(0,8))

        # ---------- Notebook with editable tables ----------
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill="both", expand=True, padx=8, pady=(0,8))

        # Holding Registers
        self.holding_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.holding_frame, text="Holding Registers (FC 03)")
        self.holding_table = ttk.Treeview(self.holding_frame, columns=("Address","Value"), show="headings", selectmode="browse")
        self.holding_table.heading("Address", text="Address"); self.holding_table.heading("Value", text="Value")
        self.holding_table.column("Address", width=100, anchor="center")
        self.holding_table.column("Value", width=140, anchor="center")
        self.holding_table.pack(side=tk.LEFT, fill="both", expand=True)
        hscr = ttk.Scrollbar(self.holding_frame, orient="vertical", command=self.holding_table.yview)
        hscr.pack(side=tk.RIGHT, fill="y")
        self.holding_table.configure(yscrollcommand=hscr.set)
        self.holding_table.bind("<Double-1>", self.on_double_click_holding)

        # Coils
        self.coils_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.coils_frame, text="Coils (FC 01/05/0F)")
        self.coil_table = ttk.Treeview(self.coils_frame, columns=("Address","Value"), show="headings", selectmode="browse")
        self.coil_table.heading("Address", text="Address"); self.coil_table.heading("Value", text="Value")
        self.coil_table.column("Address", width=100, anchor="center")
        self.coil_table.column("Value", width=140, anchor="center")
        self.coil_table.pack(side=tk.LEFT, fill="both", expand=True)
        cscr = ttk.Scrollbar(self.coils_frame, orient="vertical", command=self.coil_table.yview)
        cscr.pack(side=tk.RIGHT, fill="y")
        self.coil_table.configure(yscrollcommand=cscr.set)
        self.coil_table.bind("<Double-1>", self.on_double_click_coil)

        # Discrete Inputs
        self.discrete_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.discrete_frame, text="Discrete Inputs (FC 02)")
        self.discrete_table = ttk.Treeview(self.discrete_frame, columns=("Address","Value"), show="headings", selectmode="browse")
        self.discrete_table.heading("Address", text="Address"); self.discrete_table.heading("Value", text="Value")
        self.discrete_table.column("Address", width=100, anchor="center")
        self.discrete_table.column("Value", width=140, anchor="center")
        self.discrete_table.pack(side=tk.LEFT, fill="both", expand=True)
        dscr = ttk.Scrollbar(self.discrete_frame, orient="vertical", command=self.discrete_table.yview)
        dscr.pack(side=tk.RIGHT, fill="y")
        self.discrete_table.configure(yscrollcommand=dscr.set)
        self.discrete_table.bind("<Double-1>", self.on_double_click_discrete)

        # Input Registers
        self.input_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.input_frame, text="Input Registers (FC 04)")
        self.input_table = ttk.Treeview(self.input_frame, columns=("Address","Value"), show="headings", selectmode="browse")
        self.input_table.heading("Address", text="Address"); self.input_table.heading("Value", text="Value")
        self.input_table.column("Address", width=100, anchor="center")
        self.input_table.column("Value", width=140, anchor="center")
        self.input_table.pack(side=tk.LEFT, fill="both", expand=True)
        iscr = ttk.Scrollbar(self.input_frame, orient="vertical", command=self.input_table.yview)
        iscr.pack(side=tk.RIGHT, fill="y")
        self.input_table.configure(yscrollcommand=iscr.set)
        self.input_table.bind("<Double-1>", self.on_double_click_input)

        # Initial table population + periodic refresh
        self.refresh_all_tables()
        self.root.after(1000, self.periodic_refresh)

    # -------- UI helpers --------
    def _format_config_status(self):
        uid_info = "Any UID" if not self.enforce_uid_var.get() else f"UID={self.allowed_uid_var.get().strip()}"
        ident = f"{self.vendor_var.get().strip()} | {self.product_var.get().strip()} | {self.rev_var.get().strip()}"
        bind = f"{self.bind_ip_var.get().strip()}:{self.port_var.get().strip()}"
        return f"Bind: {bind}  •  Serving: {uid_info}  •  Device ID: [{ident}]"

    def apply_device_id(self):
        set_identity_triplet(self.vendor_var.get(), self.product_var.get(), self.rev_var.get())
        self.config_status.config(text=self._format_config_status())
        messagebox.showinfo("Device ID", "Device Identification updated.")

    def apply_uid_enforcement(self):
        self._rebuild_context()
        self.config_status.config(text=self._format_config_status())
        messagebox.showinfo("Unit ID", "Unit ID enforcement updated.\nRestart server to apply if it is running.")

    def _rebuild_context(self):
        """Rebuild ModbusServerContext using the single shared store."""
        if self.enforce_uid_var.get():
            try:
                allowed = int(self.allowed_uid_var.get().strip())
            except ValueError:
                messagebox.showerror("Input Error", "Allowed UID must be an integer 1..247.")
                return
            if not (1 <= allowed <= 247):
                messagebox.showerror("Input Error", "Allowed UID must be 1..247.")
                return
            self.context = ModbusServerContext(slaves={allowed: self.store}, single=False)
        else:
            self.context = ModbusServerContext(slaves=self.store, single=True)

    # -------- Table population / refresh --------
    def refresh_all_tables(self):
        # Holding Registers
        self.holding_table.delete(*self.holding_table.get_children())
        for i, val in enumerate(self.store.getValues(3, 0, count=100)):
            self.holding_table.insert("", "end", values=(i, val))

        # Coils
        self.coil_table.delete(*self.coil_table.get_children())
        for i, val in enumerate(self.store.getValues(1, 0, count=20)):
            self.coil_table.insert("", "end", values=(i, bool(val)))

        # Discrete Inputs
        self.discrete_table.delete(*self.discrete_table.get_children())
        for i, val in enumerate(self.store.getValues(2, 0, count=100)):
            self.discrete_table.insert("", "end", values=(i, bool(val)))

        # Input Registers
        self.input_table.delete(*self.input_table.get_children())
        for i, val in enumerate(self.store.getValues(4, 0, count=100)):
            self.input_table.insert("", "end", values=(i, val))

    def periodic_refresh(self):
        self.refresh_all_tables()
        self.root.after(1000, self.periodic_refresh)

    # -------- Editors (double-click) --------
    def on_double_click_holding(self, event):
        sel = self.holding_table.selection()
        if not sel: return
        item = sel[0]
        addr = int(self.holding_table.item(item, "values")[0])
        oldv = str(self.holding_table.item(item, "values")[1])
        x, y, w, h = self.holding_table.bbox(item, column=1)
        e = tk.Entry(self.holding_table); e.insert(0, oldv)
        e.place(x=x, y=y, width=w, height=h); e.focus()

        def commit(_=None):
            try:
                newv = int(e.get())
                self.store.setValues(3, addr, [newv])
                self.holding_table.set(item, "Value", newv)
            except ValueError:
                pass
            e.destroy()

        e.bind("<Return>", commit)
        e.bind("<FocusOut>", lambda _e: e.destroy())

    def on_double_click_input(self, event):
        sel = self.input_table.selection()
        if not sel: return
        item = sel[0]
        addr = int(self.input_table.item(item, "values")[0])
        oldv = str(self.input_table.item(item, "values")[1])
        x, y, w, h = self.input_table.bbox(item, column=1)
        e = tk.Entry(self.input_table); e.insert(0, oldv)
        e.place(x=x, y=y, width=w, height=h); e.focus()

        def commit(_=None):
            try:
                newv = int(e.get())
                self.store.setValues(4, addr, [newv])
                self.input_table.set(item, "Value", newv)
            except ValueError:
                pass
            e.destroy()

        e.bind("<Return>", commit)
        e.bind("<FocusOut>", lambda _e: e.destroy())

    def on_double_click_coil(self, event):
        sel = self.coil_table.selection()
        if not sel: return
        item = sel[0]
        addr = int(self.coil_table.item(item, "values")[0])
        current = bool(self.store.getValues(1, addr, count=1)[0])
        self.store.setValues(1, addr, [int(not current)])
        self.coil_table.set(item, "Value", str(not current))

    def on_double_click_discrete(self, event):
        sel = self.discrete_table.selection()
        if not sel: return
        item = sel[0]
        addr = int(self.discrete_table.item(item, "values")[0])
        current = bool(self.store.getValues(2, addr, count=1)[0])
        # Discrete inputs are typically read-only, but we let you toggle for demo
        self.store.setValues(2, addr, [int(not current)])
        self.discrete_table.set(item, "Value", str(not current))

    # -------- Server lifecycle --------
    def start_server(self):
        bind_ip = self.bind_ip_var.get().strip()
        try:
            port = int(self.port_var.get().strip())
        except ValueError:
            messagebox.showerror("Input Error", "Port must be an integer.")
            return

        # Rebuild context as per UID enforcement before start
        self._rebuild_context()

        self.status_label.config(text=f"Status: Running on {bind_ip}:{port}", fg="green")
        self._server_thread = threading.Thread(target=self._run_server_thread, args=(bind_ip, port), daemon=True)
        self._server_thread.start()
        self.config_status.config(text=self._format_config_status())

    def stop_server(self):
        self.status_label.config(text="Status: Stopped", fg="red")
        messagebox.showinfo("Server", "Stop requested. Close the app to fully release the port if needed.")

    def _run_server_thread(self, bind_ip: str, port: int):
        async def _serve():
            # Behaviors:
            # - Invalid FC -> Exception 0x01 (default from server).
            # - Out-of-range -> Exception 0x02 (DualZeroOneDataBlock.validate()).
            # - Bad MBAP/length -> no response (ModbusSocketFramer drops).
            # - Extra trailing bytes -> tolerated if parsable; else socket may reset.
            await StartAsyncTcpServer(
                context=self.context,
                identity=identity,
                address=(bind_ip, port),
            )

        if sys.platform.startswith("win"):
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        asyncio.run(_serve())


if __name__ == "__main__":
    root = tk.Tk()
    app = ModbusServerGUI(root)
    root.mainloop()
