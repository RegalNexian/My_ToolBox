# tools/network_security_scanner.py

from __future__ import annotations

import csv
import ftplib
import json
import os
import queue
import socket
import ssl
import subprocess
import sys
import threading
import time
import ipaddress
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Tuple, Set

import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from urllib.parse import quote_plus

# Required helper modules from your project
from base_tool import BaseToolFrame
from theme import (
    BG_COLOR, PANEL_COLOR, TEXT_COLOR,
    style_button, style_label, style_entry, style_textbox
)
from utils import ensure_results_subfolder, get_save_path

TAB_NAME = "Network Security Scanner"

# Optional dependencies (best-effort imports)
try:
    import psutil
except ImportError:
    psutil = None # type: ignore

try:
    import whois # type: ignore
except ImportError:
    whois = None # type: ignore

try:
    import requests
except ImportError:
    requests = None # type: ignore  

try:
    import networkx as nx
    import matplotlib.pyplot as plt
except ImportError:
    nx = None # type: ignore
    plt = None # type: ignore 

try:
    # scapy for traceroute/advanced discovery
    import scapy.all as scapy
except ImportError:
    scapy = None # type: ignore

# ========== Constants ==========
DEFAULT_PORTS = [22, 80, 443, 445, 3389]
COMMON_PORTS_FULL = [
    21, 22, 23, 25, 53, 80, 110, 139, 143, 389, 443, 445, 3389, 5900, 8080, 8443
]
VULN_PORTS_HINTS = {
    21: "FTP — often exposed; ensure no anonymous or default creds.",
    23: "Telnet — insecure plaintext credentials.",
    445: "SMB — historically vulnerable (EternalBlue); patch Windows hosts.",
    3389: "RDP — exposure may allow brute-force; use MFA and IP restriction.",
    5900: "VNC — may allow remote control with weak/no auth.",
}

RESULTS_SUBFOLDER = "Network_Security_Scanner"

# ========== Data classes ==========
@dataclass
class PortInfo:
    """Holds information about a single open port."""
    port: int
    banner: Optional[str] = None
    ssl_issuer: Optional[str] = None
    ssl_valid: Optional[bool] = None


@dataclass
class HostResult:
    """Holds all scan results for a single host."""
    ip: str
    hostname: Optional[str]
    mac: Optional[str]
    open_ports: List[PortInfo]
    os_guess: Optional[str] = None
    whois: Optional[str] = None
    shodan: Optional[str] = None
    traceroute: Optional[List[str]] = None
    last_seen: float = 0.0


# ========== Utilities ==========
def safe_resolve_host(ip: str) -> Optional[str]:
    """Attempt to resolve an IP address to a hostname without crashing."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return None


def get_local_subnet_default() -> str:
    """
    Try to auto-detect the local subnet using psutil if available,
    otherwise fall back to ip via socket and assume /24.
    """
    try:
        if psutil:
            addrs = psutil.net_if_addrs()
            for infos in addrs.values():
                for info in infos:
                    if getattr(info, "family", None) == socket.AF_INET:
                        addr = getattr(info, "address", None)
                        if addr and not addr.startswith("127."):
                            mask = getattr(info, "netmask", None) or "255.255.255.0"
                            network = ipaddress.IPv4Network(f"{addr}/{mask}", strict=False)
                            return str(network)
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        if ip and not ip.startswith("127."):
            return str(ipaddress.IPv4Network(f"{ip}/24", strict=False))
    except (IOError, OSError):
        pass
    return "192.168.1.0/24"


def parse_ports_spec(spec: str) -> List[int]:
    """
    Parse port list expressions: "22,80,443" or "1-1024" etc.
    Returns a sorted unique list.
    """
    if not spec or not spec.strip():
        return DEFAULT_PORTS.copy()
    out: Set[int] = set()
    for part in spec.split(","):
        p = part.strip()
        if not p:
            continue
        if "-" in p:
            try:
                a_str, b_str = p.split("-", 1)
                a_i, b_i = int(a_str), int(b_str)
                if a_i <= b_i:
                    out.update(range(a_i, b_i + 1))
            except ValueError:
                continue
        else:
            try:
                out.add(int(p))
            except ValueError:
                continue
    res = sorted(x for x in out if 1 <= x <= 65535)
    return res or DEFAULT_PORTS.copy()


def banner_grab(ip: str, port: int, timeout: float = 0.8) -> Optional[str]:
    """
    Minimal banner grab attempt: tries a tiny probe and reads up to 1024 bytes.
    Non-intrusive.
    """
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            if port in (80, 8080, 8000, 8888):
                try:
                    s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                except socket.error:
                    pass
            try:
                data = s.recv(1024)
                return data.decode(errors="ignore").strip() if data else None
            except socket.error:
                return None
    except socket.error:
        return None
    return None


def ssl_cert_info(
    ip: str, port: int = 443, timeout: float = 2.0
) -> Tuple[Optional[str], Optional[bool]]:
    """Return (issuer_str, valid_boolean) or (None, None) if handshake failed."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    return None, None
                issuer = cert.get("issuer")
                issuer_text = None
                if isinstance(issuer, tuple):
                    parts = [f"{k}={v}" for item in issuer for k, v in item]  # type: ignore
                    issuer_text = ", ".join(parts)
                else:
                    issuer_text = str(issuer)
                return issuer_text, True
    except (ssl.SSLError, socket.timeout):
        return None, False
    except OSError:
        return None, None


def traceroute_host(ip: str, max_hops: int = 20, timeout: float = 2.0) -> List[str]:
    """
    Best-effort traceroute using scapy or system command.
    """
    hops: List[str] = []
    if scapy:
        try:
            # pylint: disable=no-member
            ans, _ = scapy.traceroute(ip, maxttl=max_hops, timeout=timeout, verbose=0)  # type: ignore
            for _, rcv in ans:
                try:
                    hops.append(rcv.src)
                except AttributeError:
                    pass
            return hops
        except Exception:  # pylint: disable=broad-exception-caught
            pass

    try:
        cmd = ["tracert", "-d", "-h", str(max_hops), ip] if sys.platform.startswith("win") \
            else ["traceroute", "-n", "-m", str(max_hops), ip]
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout * max_hops, check=False
        )
        # Robustly find IPs in the output
        for line in proc.stdout.splitlines():
            found_ips = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", line)
            if found_ips:
                hops.append(found_ips[0])
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return hops


def whois_summary(target: str) -> Optional[str]:
    """Get a brief summary from a WHOIS lookup."""
    if whois is None:
        return "python-whois not installed"
    try:
        data = whois.whois(target)
        if not data:
            return None
        org = data.get("org") or data.get("registrar")
        country = data.get("country")
        return f"org={org}, country={country}"
    except Exception:  # pylint: disable=broad-exception-caught
        return "WHOIS lookup failed"


def shodan_lookup(ip: str, api_key: Optional[str]) -> Optional[str]:
    """Get a brief summary from a Shodan lookup."""
    if not api_key or requests is None:
        return None
    try:
        url = f"https://api.shodan.io/shodan/host/{ip}?key={quote_plus(api_key)}"
        resp = requests.get(url, timeout=6)
        if resp.status_code == 200:
            d = resp.json()
            org, os_name, ports = d.get("org"), d.get("os"), d.get("ports")
            return f"org={org}, os={os_name}, ports={ports}"
    except requests.RequestException:
        pass
    return None


# ========== Scanner Worker (multi-threaded) ==========
class Scanner:
    """
    Coordinates discovery, port scanning, and enrichment tasks in worker threads.
    """

    def __init__(
        self,
        cidr: str,
        ports: Iterable[int],
        threads: int = 200,
        timeout: float = 0.35,
        do_ping_sweep: bool = True,
        do_banner: bool = True,
        do_ssl: bool = True,
        do_traceroute: bool = False,
        do_whois: bool = False,
        shodan_key: Optional[str] = None,
        single_credential_checks: Optional[List[Tuple[str, str]]] = None,
        out_q: Optional[queue.Queue[Any]] = None,
        stop_event: Optional[threading.Event] = None,
    ) -> None:
        self.cidr = cidr
        self.ports = list(ports)
        self.threads = max(4, int(threads))
        self.timeout = float(timeout)
        self.do_ping_sweep = do_ping_sweep
        self.do_banner = do_banner
        self.do_ssl = do_ssl
        self.do_traceroute = do_traceroute
        self.do_whois = do_whois
        self.shodan_key = shodan_key
        self.single_credential_checks = single_credential_checks or []
        self.out_q = out_q or queue.Queue()
        self.stop_event = stop_event or threading.Event()
        self.results: Dict[str, HostResult] = {}
        self.results_lock = threading.Lock()

    def log(self, typ: str, payload: Any) -> None:
        """Emit a message to the UI via queue."""
        if self.out_q:
            self.out_q.put((typ, payload))

    def discover_hosts(self) -> List[str]:
        """
        Discover live hosts using ARP (if local) or a threaded TCP ping.
        """
        try:
            network = ipaddress.ip_network(self.cidr, strict=False)
            hosts = [str(h) for h in network.hosts()]
        except ValueError as e:
            self.log("error", f"Invalid CIDR/target: {e}")
            return []

        found: List[str] = []

        if scapy and network.prefixlen >= 24:
            try:
                self.log("log", "Starting fast ARP sweep (scapy)...")
                # pylint: disable=no-member
                ans, _ = scapy.srp(
                    scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=self.cidr),  # type: ignore[attr-defined]
                    timeout=2,
                    verbose=False
                )
                for _, rcv in ans:
                    found.append(rcv.psrc)
                if found:
                    self.log("log", f"ARP sweep found {len(found)} hosts.")
                    return sorted(found)
            except Exception as e: # pylint: disable=broad-exception-caught
                # --- THIS IS THE KEY IMPROVEMENT ---
                self.log("log", f"Scapy ARP sweep failed: {e}.")
                self.log("log", "This is likely due to missing Npcap/libpcap. See documentation.")
                self.log("log", "Falling back to slower TCP ping sweep...")
                # --- END OF IMPROVEMENT ---


        self.log("log", f"Doing TCP ping-sweep on {len(hosts)} hosts (threads={self.threads})")
        alive_q: queue.Queue[str] = queue.Queue()

        def worker_ping(queue_ips: queue.Queue[str]):
            while not queue_ips.empty() and not self.stop_event.is_set():
                ip = queue_ips.get()
                ok = False
                for p in (80, 443, 22, 53, 3389):
                    try:
                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                            s.settimeout(self.timeout)
                            if s.connect_ex((ip, p)) == 0:
                                ok = True
                                break
                    except socket.error:
                        continue
                if ok:
                    alive_q.put(ip)
                queue_ips.task_done()

        q_ips: queue.Queue[str] = queue.Queue()
        for h in hosts:
            q_ips.put(h)

        threads_list: List[threading.Thread] = []
        for _ in range(min(self.threads, len(hosts))):
            t = threading.Thread(target=worker_ping, args=(q_ips,), daemon=True)
            t.start()
            threads_list.append(t)

        q_ips.join()
        while not alive_q.empty():
            found.append(alive_q.get())

        return sorted(found)

    def _scan_ports_for_host(self, ip: str) -> HostResult:
        """Scan given ports for a single host and collect info."""
        hostname = safe_resolve_host(ip)
        open_ports: List[PortInfo] = []

        for p in self.ports:
            if self.stop_event.is_set():
                break
            try:
                with socket.create_connection((ip, p), timeout=self.timeout):
                    banner, ssl_issuer, ssl_valid = None, None, None
                    if self.do_banner:
                        banner = banner_grab(ip, p, timeout=max(0.6, self.timeout))
                    if self.do_ssl and p in (443, 8443, 993, 995, 465, 587):
                        ssl_issuer, ssl_valid = ssl_cert_info(ip, p, timeout=2.0)
                    open_ports.append(
                        PortInfo(port=p, banner=banner, ssl_issuer=ssl_issuer, ssl_valid=ssl_valid)
                    )
            except socket.error:
                continue
        # OS guess is now part of the result object creation.
        result = HostResult(
            ip=ip, hostname=hostname, mac=None, open_ports=open_ports, last_seen=time.time()
        )
        if self.do_whois:
            result.whois = whois_summary(hostname or ip)
        if self.shodan_key:
            result.shodan = shodan_lookup(ip, self.shodan_key)
        if self.do_traceroute:
            result.traceroute = traceroute_host(ip)

        return result

    def run(self) -> None:
        """Main scanner execution loop."""
        start = time.time()
        try:
            targets = self.discover_hosts() if self.do_ping_sweep else \
                [str(h) for h in ipaddress.ip_network(self.cidr, strict=False).hosts()]

            total = len(targets)
            self.log("start", {"count": total, "cidr": self.cidr})

            with ThreadPoolExecutor(max_workers=self.threads) as exe:
                futures = {exe.submit(self._scan_ports_for_host, ip): ip for ip in targets}
                completed = 0
                for fut in as_completed(futures):
                    if self.stop_event.is_set():
                        break
                    ip = futures[fut]
                    try:
                        res: HostResult = fut.result()
                        with self.results_lock:
                            self.results[ip] = res
                        self.log("host", res)
                    except Exception as e: # pylint: disable=broad-exception-caught
                        self.log("error", f"Host scan error for {ip}: {e}")
                    finally:
                        completed += 1
                        elapsed = time.time() - start
                        eta = (elapsed / completed) * (total - completed) if completed else 0
                        self.log("progress", {"done": completed, "total": total, "eta": eta})

        except Exception as e: # pylint: disable=broad-exception-caught
            self.log("error", str(e))
        finally:
            self.log("done", {"elapsed": time.time() - start})

    def _run_single_credential_checks(self, host_res: HostResult) -> None:
        """VERY LIMITED: only one attempt per credential and per service."""
        for user, pwd in self.single_credential_checks:
            for pinfo in host_res.open_ports:
                if pinfo.port == 21:
                    try:
                        ftp = ftplib.FTP()
                        ftp.connect(host_res.ip, 21, timeout=3)
                        ftp.login(user, pwd)
                        self.log("creds", {"ip": host_res.ip, "port": 21, "user": user, "ok": True})
                        ftp.quit()
                    except ftplib.all_errors:
                        self.log("creds", {"ip": host_res.ip, "port": 21, "user": user, "ok": False})


# ========== UI ToolFrame (Tkinter) ==========
class ToolFrame(BaseToolFrame):
    """The main UI frame for the Network Security Scanner tool."""
    def __init__(self, master: tk.Misc):
        super().__init__(master)
        ensure_results_subfolder(RESULTS_SUBFOLDER)

        self.scanner_thread: Optional[threading.Thread] = None
        self.scanner: Optional[Scanner] = None
        self.out_q: queue.Queue[Any] = queue.Queue()
        self.stop_event = threading.Event()
        self.results: Dict[str, HostResult] = {}
        self.monitoring = False
        self._monitor_timer: Optional[int] = None

        self._build_ui()
        self.after(150, self._pump_queue)

    def _build_ui(self) -> None:
        """Create all the UI widgets for the tool."""
        # Left control panel
        left = tk.Frame(self, bg=PANEL_COLOR, width=360)
        left.pack(side="left", fill="y", padx=6, pady=6)
        style_label(tk.Label(left, text="🔒 Network Security Scanner"))
        style_label(tk.Label(left, text="Target (auto-detected)"))
        self.target_entry = tk.Entry(left)
        style_entry(self.target_entry)
        self.target_entry.pack(fill="x", pady=4)
        self.target_entry.insert(0, get_local_subnet_default())

        style_label(tk.Label(left, text="Ports (e.g. 22,80,443 or 1-1024)"))
        self.ports_entry = tk.Entry(left)
        style_entry(self.ports_entry)
        self.ports_entry.pack(fill="x", pady=4)
        self.ports_entry.insert(0, "20-1024")

        self.threads_var = tk.IntVar(value=200)
        style_label(tk.Label(left, text="Threads"))
        self.threads_spin = tk.Spinbox(left, from_=4, to=1000, textvariable=self.threads_var)
        self.threads_spin.pack(fill="x", pady=4)

        self.timeout_entry = tk.Entry(left)
        style_entry(self.timeout_entry)
        self.timeout_entry.insert(0, "0.35")
        style_label(tk.Label(left, text="Timeout (s)"))
        self.timeout_entry.pack(fill="x", pady=(0, 8))

        self.chk_ping = tk.BooleanVar(value=True)
        self.chk_banner = tk.BooleanVar(value=True)
        self.chk_ssl = tk.BooleanVar(value=True)
        self.chk_tr = tk.BooleanVar(value=False)
        self.chk_whois = tk.BooleanVar(value=False)
        self.chk_shodan = tk.BooleanVar(value=False)
        self.chk_single_creds = tk.BooleanVar(value=False)
        checkboxes = [
            ("Ping sweep (fast discovery)", self.chk_ping),
            ("Banner grab / service detect", self.chk_banner),
            ("SSL cert checks", self.chk_ssl),
            ("Traceroute (best-effort)", self.chk_tr),
            ("WHOIS enrich (optional)", self.chk_whois),
            ("Shodan enrich (requires key)", self.chk_shodan),
            ("Default credential check (single-attempt, opt-in)", self.chk_single_creds),
        ]
        for txt, var in checkboxes:
            cb = tk.Checkbutton(
                left, text=txt, variable=var, bg=PANEL_COLOR, fg=TEXT_COLOR, selectcolor=BG_COLOR
            )
            cb.pack(anchor="w")

        style_label(tk.Label(left, text="Shodan API key (optional)"))
        self.shodan_entry = tk.Entry(left, show="*")
        style_entry(self.shodan_entry)
        self.shodan_entry.pack(fill="x", pady=4)

        style_label(tk.Label(left, text="Credentials (one per line user:pass) — opt-in"))
        self.creds_text = tk.Text(left, height=4)
        style_textbox(self.creds_text)
        self.creds_text.pack(fill="x", pady=(2, 6))

        btn_row = tk.Frame(left, bg=PANEL_COLOR)
        btn_row.pack(fill="x", pady=(6, 4))
        self.start_btn = tk.Button(btn_row, text="▶ Start Scan", command=self.start_scan)
        style_button(self.start_btn)
        self.start_btn.pack(side="left", fill="x", expand=True, padx=(0, 4))
        self.stop_btn = tk.Button(btn_row, text="■ Stop", command=self.stop_scan, state="disabled")
        style_button(self.stop_btn)
        self.stop_btn.pack(side="left", fill="x", expand=True, padx=(4, 0))

        mon_row = tk.Frame(left, bg=PANEL_COLOR)
        mon_row.pack(fill="x", pady=(4, 8))
        style_label(tk.Label(mon_row, text="Continuous monitor (minutes)"))
        self.monitor_interval = tk.IntVar(value=0)
        spin_args = {"from_": 0, "to": 1440, "textvariable": self.monitor_interval}
        self.monitor_spin = tk.Spinbox(mon_row, **spin_args)  # type: ignore
        self.monitor_spin.pack(fill="x", pady=2)

        self.quick_btn = tk.Button(left, text="⚡ Quick Scan My Network", command=self.quick_scan)
        style_button(self.quick_btn)
        self.quick_btn.pack(fill="x", pady=(4, 8))

        ex_row = tk.Frame(left, bg=PANEL_COLOR)
        ex_row.pack(fill="x", pady=(6, 2))
        self.export_csv_btn = tk.Button(ex_row, text="Export CSV", command=self.export_csv)
        style_button(self.export_csv_btn)
        self.export_csv_btn.pack(fill="x", pady=2)
        self.export_json_btn = tk.Button(ex_row, text="Export JSON", command=self.export_json)
        style_button(self.export_json_btn)
        self.export_json_btn.pack(fill="x", pady=2)
        self.save_session_btn = tk.Button(ex_row, text="Save Session", command=self.save_session)
        style_button(self.save_session_btn)
        self.save_session_btn.pack(fill="x", pady=2)
        self.load_session_btn = tk.Button(ex_row, text="Load Session", command=self.load_session)
        style_button(self.load_session_btn)
        self.load_session_btn.pack(fill="x", pady=2)

        style_label(tk.Label(left, text="Progress"))
        self.progress = ttk.Progressbar(left, orient="horizontal", mode="determinate")
        self.progress.pack(fill="x", pady=6)
        self.progress_label = tk.Label(left, text="", bg=PANEL_COLOR, fg=TEXT_COLOR)
        self.progress_label.pack(fill="x")

        # Right panel results
        right = tk.Frame(self, bg=BG_COLOR)
        right.pack(side="right", fill="both", expand=True, padx=6, pady=6)
        self.visualize_btn = tk.Button(right, text="🗺 Visualize", command=self.visualize_graph)
        style_button(self.visualize_btn)
        self.visualize_btn.pack(anchor="nw", pady=2)
        if nx is None:
            self.visualize_btn.config(state="disabled")

        cols = ("ip", "host", "ports", "risk", "whois", "shodan")
        self.tree = ttk.Treeview(right, columns=cols, show="headings")
        for col in cols:
            width = 140 if col in ("ip", "host") else 200
            self.tree.heading(col, text=col.upper())
            self.tree.column(col, width=width, anchor="w")
        self.tree.pack(fill="both", expand=True)

        style_label(tk.Label(right, text="Details / Log"))
        self.logbox = tk.Text(right, height=10)
        style_textbox(self.logbox)
        self.logbox.pack(fill="x", pady=(4, 0))

        self._bind_context_menu()

    def _bind_context_menu(self) -> None:
        """Set up the right-click context menu on the results tree."""
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label="WHOIS", command=self.ctx_whois)
        menu.add_command(label="Traceroute", command=self.ctx_traceroute)
        self.tree.bind("<Button-3>", lambda event: menu.tk_popup(event.x_root, event.y_root))

    def _log(self, text: str) -> None:
        """Add a timestamped message to the log box."""
        ts = datetime.now().strftime("%H:%M:%S")
        self.logbox.insert("end", f"[{ts}] {text}\n")
        self.logbox.see("end")

    def quick_scan(self) -> None:
        """A convenience method to scan the local network with common ports."""
        self.target_entry.delete(0, "end")
        self.target_entry.insert(0, get_local_subnet_default())
        self.start_scan()

    def start_scan(self) -> None:
        """Validate inputs and start the scanner in a new thread."""
        target = self.target_entry.get().strip()
        try:
            ipaddress.ip_network(target, strict=False)
        except ValueError as e:
            messagebox.showerror("Invalid target", f"Target is not a valid IP/CIDR: {e}")
            return

        ports = parse_ports_spec(self.ports_entry.get().strip())
        shodan_key = self.shodan_entry.get().strip() if self.chk_shodan.get() else None
        creds_list = []
        if self.chk_single_creds.get():
            raw = self.creds_text.get("1.0", "end").strip()
            for line in raw.splitlines():
                if ":" in line:
                    user, pword = line.split(":", 1)
                    creds_list.append((user.strip(), pword.strip()))

        self.results.clear()
        for row in self.tree.get_children():
            self.tree.delete(row)
        self.logbox.delete("1.0", "end")
        self._log(f"Starting scan: {target} ports={len(ports)} threads={self.threads_var.get()}")

        self.progress["value"] = 0
        self.progress_label.config(text="Initializing...")
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.stop_event.clear()

        self.scanner = Scanner(
            cidr=target, ports=ports, threads=self.threads_var.get(),
            timeout=float(self.timeout_entry.get().strip() or 0.35),
            do_ping_sweep=self.chk_ping.get(), do_banner=self.chk_banner.get(),
            do_ssl=self.chk_ssl.get(), do_traceroute=self.chk_tr.get(),
            do_whois=self.chk_whois.get(), shodan_key=shodan_key,
            single_credential_checks=creds_list, out_q=self.out_q, stop_event=self.stop_event
        )
        self.scanner_thread = threading.Thread(target=self.scanner.run, daemon=True)
        self.scanner_thread.start()

    def stop_scan(self) -> None:
        """Signal the scanner thread to stop."""
        self._log("Stop requested")
        self.stop_event.set()
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")

    def _pump_queue(self) -> None:
        """Process messages from the scanner thread to update the UI."""
        try:
            while not self.out_q.empty():
                typ, payload = self.out_q.get_nowait()
                if typ == "log":
                    self._log(str(payload))
                elif typ == "start":
                    total = payload.get("count", 0)
                    self.progress.config(mode="determinate", maximum=total)
                    self.progress_label.config(text=f"0 / {total}")
                elif typ == "progress":
                    done, total, eta = payload.get("done", 0), payload.get("total", 0), payload.get("eta")
                    if total > 0:
                        self.progress["value"] = done
                        eta_str = f" • ETA {int(eta)}s" if eta is not None else ""
                        self.progress_label.config(text=f"{done} / {total}{eta_str}")
                elif typ == "host":
                    self._add_result(payload)
                elif typ == "done":
                    self._log(f"Scan finished in {payload.get('elapsed', 0):.2f} seconds.")
                    self.start_btn.config(state="normal")
                    self.stop_btn.config(state="disabled")
                elif typ == "error":
                    self._log(f"ERROR: {payload}")
                elif typ == "creds":
                    self._log(f"Credential check: {payload}")
        finally:
            self.after(150, self._pump_queue)

    def _add_result(self, hr: HostResult) -> None:
        """Add or update a result in the results tree."""
        self.results[hr.ip] = hr
        ports_txt = ", ".join(str(p.port) for p in hr.open_ports) or "-"
        risk = "HIGH" if any(p.port in VULN_PORTS_HINTS for p in hr.open_ports) else "LOW"
        whois_txt = (hr.whois or "")[:120]
        shodan_txt = (hr.shodan or "")[:120]
        values = (hr.ip, hr.hostname or "-", ports_txt, risk, whois_txt, shodan_txt)
        self.tree.insert("", "end", values=values)
        self._log(f"Host {hr.ip} → ports: {ports_txt} risk={risk}")

    def export_csv(self, path: Optional[str] = None) -> None:
        """Export scan results to a CSV file."""
        if not self.results:
            messagebox.showinfo("Export", "No results to export.")
            return
        if not path:
            path = filedialog.asksaveasfilename(
                defaultextension=".csv", filetypes=[("CSV", "*.csv")]
            )
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["ip", "hostname", "ports", "risk", "whois", "shodan", "traceroute"])
            for r in self.results.values():
                ports = ";".join(str(p.port) for p in r.open_ports)
                risk = "HIGH" if any(p.port in VULN_PORTS_HINTS for p in r.open_ports) else "LOW"
                writer.writerow(
                    [r.ip, r.hostname or "", ports, risk, r.whois or "", r.shodan or "",
                     " | ".join(r.traceroute or [])]
                )
        messagebox.showinfo("Export", f"CSV saved to {path}")

    def export_json(self, path: Optional[str] = None) -> None:
        """Export scan results to a JSON file."""
        if not self.results:
            messagebox.showinfo("Export", "No results to export.")
            return
        if not path:
            path = filedialog.asksaveasfilename(
                defaultextension=".json", filetypes=[("JSON", "*.json")]
            )
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            json.dump({ip: asdict(hr) for ip, hr in self.results.items()}, f, indent=2)
        messagebox.showinfo("Export", f"JSON saved to {path}")

    def save_session(self) -> None:
        """Save the current session results to a timestamped JSON file."""
        path = get_save_path(RESULTS_SUBFOLDER, f"session_{int(time.time())}.json")
        self.export_json(path)
        self._log(f"Session saved to {path}")

    def load_session(self) -> None:
        """Load a previous session from a JSON file."""
        path = filedialog.askopenfilename(filetypes=[("JSON", "*.json")])
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.results.clear()
            for row in self.tree.get_children():
                self.tree.delete(row)
            for ip, val in data.items():
                hr = HostResult(**val)
                self.results[ip] = hr
                ports_txt = ", ".join(str(p["port"]) for p in val.get("open_ports", []))
                risk = "HIGH" if any(p["port"] in VULN_PORTS_HINTS for p in val.get("open_ports", [])) else "LOW"
                self.tree.insert(
                    "", "end", values=(ip, hr.hostname or "-", ports_txt, risk, hr.whois or "", hr.shodan or "")
                )
            self._log(f"Loaded session {path}")
        except (json.JSONDecodeError, TypeError) as e:
            messagebox.showerror("Load Error", f"Failed to load session file: {e}")

    def visualize_graph(self) -> None:
        """Generate and save a network graph visualization."""
        if nx is None or plt is None:
            messagebox.showinfo("Unavailable", "Install networkx + matplotlib for visualization.")
            return
        graph: nx.Graph = nx.Graph()
        for ip, hr in self.results.items():
            node_label = f"{ip}\n{hr.hostname or ''}"
            graph.add_node(node_label)
            for p in hr.open_ports:
                graph.add_node(f"{ip}:{p.port}")
                graph.add_edge(node_label, f"{ip}:{p.port}")
        pos = nx.spring_layout(graph, seed=42)
        plt.figure(figsize=(10, 8))
        nx.draw_networkx(graph, pos, with_labels=True, font_size=8, node_size=200)
        fn = get_save_path(RESULTS_SUBFOLDER, f"network_map_{int(time.time())}.png")
        try:
            plt.savefig(fn, dpi=180, bbox_inches="tight")
            plt.close()
            messagebox.showinfo("Saved", f"Network map saved to:\n{fn}")
        except IOError as e:
            messagebox.showerror("Error saving network map", str(e))

    def ctx_whois(self) -> None:
        """Context menu action to show WHOIS info."""
        sel = self.tree.selection()
        if not sel:
            return
        ip = self.tree.item(sel[0])["values"][0]
        hr = self.results.get(ip)
        if hr and hr.whois:
            messagebox.showinfo(f"WHOIS {ip}", hr.whois)
        else:
            self._log("WHOIS not available (enable & install python-whois)")

    def ctx_traceroute(self) -> None:
        """Context menu action to run a traceroute."""
        sel = self.tree.selection()
        if not sel:
            return
        ip = self.tree.item(sel[0])["values"][0]
        self._log(f"Traceroute to {ip} (may take a few seconds)...")
        hops = traceroute_host(ip)
        self._log(" -> ".join(hops or ["(no hops)"]))
        messagebox.showinfo("Traceroute", "\n".join(hops or ["(no hops)"]))