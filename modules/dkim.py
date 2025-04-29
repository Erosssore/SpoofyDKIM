import dns.resolver
import base64
from cryptography.hazmat.primitives import serialization

USUAL_SELECTORS = ["default", "google", "selector1", "mail", "spf", "dkim"]

class DKIM:
    def __init__(self, domain, dns_server=None):
        self.domain = domain
        self.dns_server = dns_server
        self.dkim_record = self.get_dkim_record()
        self.version = None
        self.algorithm = None
        self.public_key = None
        self.key_length = None


        if self.dkim_record:
            self.version = self.get_dkim_version()
            self.algorithm = self.get_dkim_algorithm()
            self.public_key = self.get_dkim_public_key()
            self.key_length = self.get_key_length()

    def get_dkim_record(self):
        """Returns the DKIM record for the domain."""
        try:
            selector, dkim_results = self.find_dkim_selector()
            if selector:
                self.selector = selector
            if dkim_results:
                return dkim_results[0]
        except Exception:
            return None
        return None
    
    def find_dkim_selector(self):
        """Finds the DKIM selector for the domain."""
        resolver = dns.resolver.Resolver()
        for selector in USUAL_SELECTORS:
            query = f"{selector}._domainkey.{self.domain}"
            try:
                answers = resolver.resolve(query, 'TXT')
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer): #, dns.resolver.Timeout):
                continue
            txts = [b"".join(rdata.strings).decode("utf-8") for rdata in answers]
            return selector, txts
                
    def get_dkim_version(self):
        """Returns the DKIM version from the DKIM record."""
        if "v=" in self.dkim_record:
            return self.dkim_record.split("v=")[1].split(";")[0]
        return None
    
    def get_dkim_algorithm(self):
        """Returns the DKIM algorithm from the DKIM record."""
        if "k=" in self.dkim_record:
            return self.dkim_record.split("k=")[1].split(";")[0]
        return None
    
    def get_dkim_public_key(self):
        """Returns the DKIM public key from the DKIM record."""
        if "p=" in self.dkim_record:
            return self.dkim_record.split("p=")[1].split(";")[0]
        return None
    
    def get_key_length(self):
        """Returns the key size of the DKIM public key."""
        try:
            der = base64.b64decode(self.public_key)
            pub = serialization.load_der_public_key(der)
            key_size = pub.key_size
            return key_size
        except Exception:
            return None