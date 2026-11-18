from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Union

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
