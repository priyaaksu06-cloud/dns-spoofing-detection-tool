import dns.resolver


def get_trusted_dns_ips(domain):

    trusted_servers = [
        "8.8.8.8",
        "1.1.1.1"
    ]

    trusted_ips = set()

    for server in trusted_servers:

        try:

            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = [server]

            answers = resolver.resolve(
                domain,
                "A"
            )

            for answer in answers:
                trusted_ips.add(
                    answer.to_text()
                )

        except Exception:
            pass

    return list(trusted_ips)


def verify_dns(domain, response_ip):

    trusted_ips = get_trusted_dns_ips(domain)

    return response_ip in trusted_ips