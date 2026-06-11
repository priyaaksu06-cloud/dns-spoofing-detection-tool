import dns.resolver

for server in ["8.8.8.8", "1.1.1.1"]:

    print("\nSERVER:", server)

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [server]

    answers = resolver.resolve(
        "google.com",
        "A"
    )

    for answer in answers:
        print(answer.to_text())