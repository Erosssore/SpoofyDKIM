import dns.resolver
import re


class SPF:
    def __init__(self, domain, dns_server=None):
        self.domain = domain
        self.dns_server = dns_server
        self.spf_record = self.get_spf_record()
        self.all_mechanism = None
        self.spf_dns_query_count = 0
        self.too_many_dns_queries = False

        if self.spf_record:
            self.all_mechanism = self.get_spf_all_string()
            self.spf_dns_query_count = self.get_spf_dns_queries()
            self.too_many_dns_queries = self.spf_dns_query_count > 10

    def get_spf_record(self, domain=None):
        try:
            if not domain:
                domain = self.domain
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [self.dns_server, "1.1.1.1", "8.8.8.8"]
            query_result = resolver.resolve(domain, "TXT")
            for record in query_result:
                if "spf1" in str(record):
                    spf_record = str(record).replace('"', "")
                    return spf_record
            return None
        except Exception:
            return None

    def get_spf_all_string(self):
        spf_record = self.spf_record
        visited_domains = set()

        while spf_record:
            all_matches = re.findall(r"[-~?+]all", spf_record)
            if len(all_matches) == 1:
                return all_matches[0]
            elif len(all_matches) > 1:
                return "2many"

            redirect_match = re.search(r"redirect=([\w.-]+)", spf_record)
            if redirect_match:
                redirect_domain = redirect_match.group(1)
                if redirect_domain in visited_domains:
                    break
                visited_domains.add(redirect_domain)
                spf_record = self.get_spf_record(redirect_domain)
            else:
                break

        return None

    def get_spf_dns_queries(self):
        checked_domains = set()
        domains_to_check = [self.domain]
        count = 0

        while domains_to_check:
            current_domain = domains_to_check.pop()
            if current_domain in checked_domains:
                continue
            checked_domains.add(current_domain)
            try:
                answers = dns.resolver.resolve(current_domain, "TXT")
                for rdata in answers:
                    txt_record = rdata.to_text().strip('"')
                    if txt_record.startswith("v=spf1"):
                        for item in txt_record.split():
                            if item.startswith(("include:", "redirect=")):
                                url = item.split(":", 1)[1] if ":" in item else item.split("=", 1)[1]
                                domains_to_check.append(url)
                                count += 1
                        count += len(re.findall(r"[ ,+]a[ ,:]", txt_record))
                        count += len(re.findall(r"[ ,+]mx[ ,:]", txt_record))
                        count += len(re.findall(r"[ ]ptr[ ]", txt_record))
                        count += len(re.findall(r"exists[:]", txt_record))
            except Exception:
                continue

        return count

    def __str__(self):
        return (
            f"SPF Record: {self.spf_record}\n"
            f"All Mechanism: {self.all_mechanism}\n"
            f"DNS Query Count: {self.spf_dns_query_count}\n"
            f"Too Many DNS Queries: {self.too_many_dns_queries}"
        )
