import dns.resolver

def resolve_ip_to_asn(ip):
    # reverse IP
    reversed_ip = '.'.join(reversed(ip.split('.')))
    query = f"{reversed_ip}.origin.asn.cymru.com"
    try:
        answers = dns.resolver.resolve(query, 'TXT')
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            asn = txt.split('|')[0].strip()
            # If multiple ASNs, take the first one
            return int(asn.split()[0])
    except Exception as e:
        print(f"Error: {e}")
        return None

print(resolve_ip_to_asn("1.1.1.1"))
