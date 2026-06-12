# resolver.py
# Extra verification layer using multi-resolver + RDAP org lookup

import dns.resolver
import ipaddress
from ipwhois import IPWhois

rdap_cache = {}

RESOLVERS = {
    "Google":     "8.8.8.8",
    "Cloudflare": "1.1.1.1",
    "OpenDNS":    "208.67.222.222",
}


def is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False


def get_ip_org(ip):
    if ip in rdap_cache:
        return rdap_cache[ip]

    if is_private_ip(ip):
        rdap_cache[ip] = "PRIVATE"
        return "PRIVATE"

    try:
        obj = IPWhois(ip)
        result = obj.lookup_rdap(depth=1)
        org = result.get("asn_description", "UNKNOWN").upper()
    except Exception:
        org = "UNKNOWN"

    rdap_cache[ip] = org
    return org


def query_resolver(domain, resolver_ip):
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [resolver_ip]
        resolver.timeout = 3
        resolver.lifetime = 3
        answers = resolver.resolve(domain.rstrip("."), "A")
        return [str(r) for r in answers]
    except Exception as e:
        print(f"  [Resolver {resolver_ip}] Could not reach: {e}")
        return []


def verify_domain(domain):
    print(f"\n  [Verifier] Checking domain: {domain}")
    resolver_results = {}
    all_ips = []

    for name, resolver_ip in RESOLVERS.items():
        ips = query_resolver(domain, resolver_ip)
        resolver_results[name] = ips
        all_ips.extend(ips)
        print(f"  [Verifier] {name} returned: {ips}")

    if not all_ips:
        return {
            "trust_level": "LOW",
            "resolver_results": resolver_results,
            "orgs_seen": [],
            "reason": "No resolver returned any IP. Very suspicious."
        }

    unique_ips = list(set(all_ips))
    for ip in unique_ips:
        if is_private_ip(ip):
            return {
                "trust_level": "LOW",
                "resolver_results": resolver_results,
                "orgs_seen": ["PRIVATE"],
                "reason": f"Private IP found in DNS response: {ip}. Likely spoofing."
            }

    ip_to_org = {}
    for ip in unique_ips:
        org = get_ip_org(ip)
        ip_to_org[ip] = org
        print(f"  [Verifier] {ip} owned by: {org}")

    orgs_seen = list(set(ip_to_org.values()))
    unknown_count = orgs_seen.count("UNKNOWN")
    total_orgs = len(orgs_seen)

    if unknown_count == 0 and total_orgs == 1:
        return {
            "trust_level": "HIGH",
            "resolver_results": resolver_results,
            "orgs_seen": orgs_seen,
            "reason": "All resolvers point to same organization. Fully trusted."
        }

    if unknown_count == 0 and total_orgs > 1:
        return {
            "trust_level": "MEDIUM",
            "resolver_results": resolver_results,
            "orgs_seen": orgs_seen,
            "reason": "Different organizations seen but all are known. Likely CDN."
        }

    if unknown_count < total_orgs:
        return {
            "trust_level": "MEDIUM",
            "resolver_results": resolver_results,
            "orgs_seen": orgs_seen,
            "reason": "Mix of known and unknown orgs. Treat with caution."
        }

    return {
        "trust_level": "LOW",
        "resolver_results": resolver_results,
        "orgs_seen": orgs_seen,
        "reason": "Could not verify ownership of any IP returned. Suspicious."
    }