import dns.resolver

USUAL_SELECTORS = ["default", "google", "selector1", "mail", "spf", "dkim"]

class DKIM:
    def __init__(self, domain, dns_server=None):
        self.domain = domain
        self.dns_server = dns_server
        self.dkim_record = self.get_dkim_record()
        self.version = None
        self.algorithm = None
        self.selector = None
        self.public_key = None


        if self.dkim_record:
            self.version = self.get_dkim_version()
            self.algorithm = self.get_dkim_algorithm()
            self.public_key = self.get_dkim_public_key()

    def get_dkim_record(self):
        """Returns the DKIM record for the domain."""
        try:
            selector, dkim_results = self.find_dkim_selector()
            if selector:
                self.selector = selector
            if dkim_results:
                self.dkim_record = dkim_results[0]
        except Exception:
            return None
        return None
    
    def find_dkim_selector(self):
        """Finds the DKIM selector for the domain."""
        resolver = dns.resolver.Resolver()
        if self.dns_server:
                resolver.nameservers = [self.dns_server]

        for selector in USUAL_SELECTORS:
            query = f"{selector}._domainkey.{self.domain}"
            try:
                answers = resolver.resolve(query, 'TXT')
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer): #, dns.resolver.Timeout):
                continue
            txts = [b"".join(rdata.strings).decode("utf-8") for rdata in answers]
            return selector, txts
                