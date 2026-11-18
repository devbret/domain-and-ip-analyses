import socket
import ssl
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional

import httpx
import ipwhois

from .common import USER_AGENT, safe_call
from .models import IPReport, JSONLike


def get_reverse_dns(ip: str) -> JSONLike:
    host, aliases, addrs = socket.gethostbyaddr(ip)
    return {"host": host, "aliases": aliases, "addrs": addrs}


def get_ip_geolocation(ip: str, timeout: int = 10) -> JSONLike:
    with httpx.Client(timeout=timeout, headers={"User-Agent": USER_AGENT}) as client:
        r = client.get(f"https://ipinfo.io/{ip}/json")
        r.raise_for_status()
        return r.json()


def check_port(ip: str, port: int, timeout: float = 1.0) -> Optional[int]:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        if sock.connect_ex((ip, port)) == 0:
            return port
    return None


def scan_open_ports(ip: str, max_port: int = 100, max_threads: int = 50, timeout: float = 1.0) -> List[int]:
    ports = range(1, max_port + 1)
    open_ports: List[int] = []
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(check_port, ip, p, timeout): p for p in ports}
        for future in as_completed(futures):
            res = safe_call(future.result)
            if isinstance(res, int):
                open_ports.append(res)
    open_ports.sort()
    return open_ports


def get_ip_whois_rdap(ip: str) -> JSONLike:
    obj = ipwhois.IPWhois(ip)
    return obj.lookup_rdap(depth=1)


def get_ip_ssl_certificate(ip: str, port: int = 443, timeout: int = 5) -> JSONLike:
    context = ssl.create_default_context()
    with socket.create_connection((ip, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=ip) as ssock:
            return ssock.getpeercert()


def grab_banner(ip: str, port: int, timeout: float = 2.0) -> JSONLike:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect((ip, port))
        data = s.recv(1024)
    try:
        return data.decode(errors="replace").strip()
    except Exception:
        return repr(data)


def ping_latency(ip: str, count: int = 4) -> JSONLike:
    proc = subprocess.run(["ping", "-c", str(count), ip], capture_output=True, text=True)
    return {"returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}


def build_ip_report(
    ip: str,
    banner_port: int = 80,
    scan_max_port: int = 100,
    scan_threads: int = 50,
    scan_timeout: float = 1.0,
) -> IPReport:
    return IPReport(
        ip=ip,
        reverse_dns=safe_call(get_reverse_dns, ip),
        geolocation=safe_call(get_ip_geolocation, ip),
        open_ports=safe_call(scan_open_ports, ip, scan_max_port, scan_threads, scan_timeout),
        whois_rdap=safe_call(get_ip_whois_rdap, ip),
        ssl_certificate=safe_call(get_ip_ssl_certificate, ip),
        banner=safe_call(grab_banner, ip, banner_port),
        ping=safe_call(ping_latency, ip),
    )
