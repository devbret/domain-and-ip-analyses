from typing import Dict, List, Optional

import dns.exception
import dns.resolver

from .common import safe_call
from .models import JSONLike


def resolve_records(domain: str, record_type: str, resolver: Optional[dns.resolver.Resolver] = None) -> JSONLike:
    r = resolver or dns.resolver.Resolver(configure=True)
    answers = r.resolve(domain, record_type)
    return [str(a) for a in answers]


def make_public_resolver(
    nameservers: Optional[List[str]] = None, timeout: float = 2.0, lifetime: float = 4.0
) -> dns.resolver.Resolver:
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = nameservers or ["1.1.1.1", "8.8.8.8"]
    r.timeout = timeout
    r.lifetime = lifetime
    return r


def get_dns_records(domain: str, record_types: Optional[List[str]] = None) -> Dict[str, JSONLike]:
    record_types = record_types or ["A", "MX", "TXT", "NS", "SOA"]
    out: Dict[str, JSONLike] = {}
    for rt in record_types:
        out[rt] = safe_call(resolve_records, domain, rt)
    return out


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
