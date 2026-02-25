import argparse
import json
import socket
import ssl
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import dns.exception
import dns.resolver
import httpx
import ipwhois
import requests
import whois

JSONLike = Union[Dict[str, Any], List[Any], str, int, float, bool, None]


@dataclass
class DomainReport:
    domain: str
    whois: JSONLike
    dns_records: Dict[str, JSONLike]
    ssl_certificate: JSONLike
    dnssec: JSONLike
    email_security: Dict[str, JSONLike]
    website_content_preview: JSONLike
    website_performance: JSONLike


@dataclass
class IPReport:
    ip: str
    reverse_dns: JSONLike
    geolocation: JSONLike
    open_ports: JSONLike
    whois_rdap: JSONLike
    ssl_certificate: JSONLike
    banner: JSONLike
    ping: JSONLike


@dataclass
class ReportBundle:
    generated_at: datetime
    domain_report: Optional[DomainReport]
    ip_report: Optional[IPReport]


class EnhancedJSONEncoder(json.JSONEncoder):
    def default(self, obj: Any) -> Any:
        if isinstance(obj, (datetime, date)):
            return obj.isoformat()
        return super().default(obj)


def safe_call(fn, *args, **kwargs) -> JSONLike:
    try:
        return fn(*args, **kwargs)
    except Exception as e:
        return f"{type(e).__name__}: {e}"


def resolve_records(domain: str, record_type: str, resolver: Optional[dns.resolver.Resolver] = None) -> JSONLike:
    r = resolver or dns.resolver.Resolver(configure=True)
    answers = r.resolve(domain, record_type)
    return [str(a) for a in answers]


def get_domain_whois(domain: str) -> JSONLike:
    data = whois.whois(domain)
    try:
        return dict(data)
    except Exception:
        return str(data)


def get_dns_records(domain: str, record_types: Optional[List[str]] = None) -> Dict[str, JSONLike]:
    record_types = record_types or ["A", "MX", "TXT", "NS", "SOA"]
    out: Dict[str, JSONLike] = {}
    for rt in record_types:
        out[rt] = safe_call(resolve_records, domain, rt)
    return out


def get_domain_ssl_certificate(domain: str, port: int = 443, timeout: int = 5) -> JSONLike:
    context = ssl.create_default_context()
    with socket.create_connection((domain, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=domain) as ssock:
            cert = ssock.getpeercert()
    if not isinstance(cert, dict):
        return cert
    return {
        "issuer": cert.get("issuer"),
        "subject": cert.get("subject"),
        "notBefore": cert.get("notBefore"),
        "notAfter": cert.get("notAfter"),
        "serialNumber": cert.get("serialNumber"),
        "version": cert.get("version"),
    }


def make_public_resolver(
    nameservers: Optional[List[str]] = None, timeout: float = 2.0, lifetime: float = 4.0
) -> dns.resolver.Resolver:
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = nameservers or ["1.1.1.1", "8.8.8.8"]
    r.timeout = timeout
    r.lifetime = lifetime
    return r


def check_dnssec(domain: str) -> JSONLike:
    r = make_public_resolver()
    try:
        answers = r.resolve(domain, "DNSKEY", raise_on_no_answer=False)
        if answers.rrset is None:
            return {"status": "unsigned", "detail": "No DNSKEY records returned"}
        keys = [str(a) for a in answers]
        return {"status": "signed", "dnskey_count": len(keys), "dnskeys": keys}
    except dns.resolver.NXDOMAIN:
        return {"status": "error", "detail": "NXDOMAIN"}
    except dns.resolver.NoAnswer:
        return {"status": "unsigned", "detail": "NoAnswer for DNSKEY"}
    except dns.resolver.NoNameservers as e:
        return {"status": "error", "detail": f"NoNameservers: {e}"}
    except dns.exception.Timeout:
        return {"status": "error", "detail": "Timeout querying public resolvers"}
    except Exception as e:
        return {"status": "error", "detail": f"{type(e).__name__}: {e}"}


def extract_spf_from_txt(txt_records: JSONLike) -> JSONLike:
    if not isinstance(txt_records, list):
        return txt_records
    spf = [r for r in txt_records if "v=spf1" in r.lower()]
    return spf if spf else []


def get_email_security_records(domain: str) -> Dict[str, JSONLike]:
    out: Dict[str, JSONLike] = {}
    txt_records = safe_call(resolve_records, domain, "TXT")
    out["SPF"] = extract_spf_from_txt(txt_records)
    out["DMARC"] = safe_call(resolve_records, f"_dmarc.{domain}", "TXT")
    return out


def fetch_website(domain: str, scheme: str = "http", timeout: int = 10) -> requests.Response:
    url = f"{scheme}://{domain}"
    return requests.get(
        url,
        timeout=timeout,
        allow_redirects=True,
        headers={"User-Agent": "net-intel/1.0"},
    )


def check_website_content(domain: str, preview_chars: int = 1000) -> JSONLike:
    resp = fetch_website(domain, "http")
    text = resp.text or ""
    return text[:preview_chars]


def measure_website_performance(domain: str) -> JSONLike:
    resp = fetch_website(domain, "http")
    return {
        "load_time_seconds": resp.elapsed.total_seconds(),
        "status_code": resp.status_code,
        "final_url": resp.url,
    }


def build_domain_report(domain: str, preview_chars: int = 1000) -> DomainReport:
    return DomainReport(
        domain=domain,
        whois=safe_call(get_domain_whois, domain),
        dns_records=get_dns_records(domain),
        ssl_certificate=safe_call(get_domain_ssl_certificate, domain),
        dnssec=safe_call(check_dnssec, domain),
        email_security=safe_call(get_email_security_records, domain),
        website_content_preview=safe_call(check_website_content, domain, preview_chars),
        website_performance=safe_call(measure_website_performance, domain),
    )


def get_reverse_dns(ip: str) -> JSONLike:
    host, aliases, addrs = socket.gethostbyaddr(ip)
    return {"host": host, "aliases": aliases, "addrs": addrs}


def get_ip_geolocation(ip: str, timeout: int = 10) -> JSONLike:
    with httpx.Client(timeout=timeout, headers={"User-Agent": "net-intel/1.0"}) as client:
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


def sanitize_target(s: str) -> str:
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in s).strip("._-")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="net-intel", description="Domain + IP analysis tool")
    p.add_argument("--domain", help="Domain name to analyze (e.g. example.com)")
    p.add_argument("--ip", help="IP address to analyze (e.g. 8.8.8.8)")
    p.add_argument("--banner-port", type=int, default=80)
    p.add_argument("--scan-max-port", type=int, default=100)
    p.add_argument("--scan-threads", type=int, default=50)
    p.add_argument("--scan-timeout", type=float, default=1.0)
    p.add_argument("--preview-chars", type=int, default=1000)
    p.add_argument("--outdir", default="reports")
    p.add_argument("--no-console", action="store_true")
    return p.parse_args()


def to_pretty_json(data: Any) -> str:
    return json.dumps(data, cls=EnhancedJSONEncoder, indent=2, sort_keys=True, ensure_ascii=False)


def write_report(outdir: str, target_hint: str, payload: Any) -> str:
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    safe_target = sanitize_target(target_hint) or "report"
    path = Path(outdir)
    path.mkdir(parents=True, exist_ok=True)
    outfile = path / f"{safe_target}-{ts}.json"
    outfile.write_text(to_pretty_json(payload) + "\n", encoding="utf-8")
    return str(outfile)


def main() -> None:
    args = parse_args()
    if not args.domain and not args.ip:
        raise SystemExit("Provide --domain and/or --ip")

    domain_report = build_domain_report(args.domain, args.preview_chars) if args.domain else None
    ip_report = (
        build_ip_report(args.ip, args.banner_port, args.scan_max_port, args.scan_threads, args.scan_timeout)
        if args.ip
        else None
    )

    bundle = ReportBundle(
        generated_at=datetime.now(),
        domain_report=domain_report,
        ip_report=ip_report,
    )

    payload = asdict(bundle)

    target_hint = args.domain or args.ip or "report"
    outfile = write_report(args.outdir, target_hint, payload)

    if not args.no_console:
        print(to_pretty_json(payload))
        print(f"\nWrote: {outfile}")


if __name__ == "__main__":
    main()