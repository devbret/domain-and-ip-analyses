import socket
import ssl
from typing import Dict

import requests
import whois

from .common import USER_AGENT, safe_call
from .dns_checks import check_dnssec, get_dns_records, get_email_security_records
from .models import DomainReport, JSONLike


def get_domain_whois(domain: str) -> JSONLike:
    data = whois.whois(domain)
    try:
        return dict(data)
    except Exception:
        return str(data)


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


def fetch_website(domain: str, scheme: str = "http", timeout: int = 10) -> requests.Response:
    url = f"{scheme}://{domain}"
    return requests.get(
        url,
        timeout=timeout,
        allow_redirects=True,
        headers={"User-Agent": USER_AGENT},
    )


def summarize_website(domain: str, preview_chars: int = 1000) -> Dict[str, JSONLike]:
    resp = fetch_website(domain, "http")
    text = resp.text or ""
    return {
        "content_preview": text[:preview_chars],
        "performance": {
            "load_time_seconds": resp.elapsed.total_seconds(),
            "status_code": resp.status_code,
            "final_url": resp.url,
        },
    }


def build_domain_report(domain: str, preview_chars: int = 1000) -> DomainReport:
    website = safe_call(summarize_website, domain, preview_chars)
    if isinstance(website, dict):
        content_preview = website["content_preview"]
        performance = website["performance"]
    else:
        content_preview = performance = website

    return DomainReport(
        domain=domain,
        whois=safe_call(get_domain_whois, domain),
        dns_records=get_dns_records(domain),
        ssl_certificate=safe_call(get_domain_ssl_certificate, domain),
        dnssec=safe_call(check_dnssec, domain),
        email_security=safe_call(get_email_security_records, domain),
        website_content_preview=content_preview,
        website_performance=performance,
    )
