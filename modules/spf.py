# modules/spf.py

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

    '''
    Changes commited by Erossore.
    Note that the changes here were implemented based on practical testing of Spoofy
    that indicated that the SPF parsing functions were not properly implemented.
    '''
    def get_spf_record(self, domain=None):
        """Fetches the SPF record for the specified domain."""
        try:
            if not domain:
                domain = self.domain

            resolver = dns.resolver.Resolver()

            # Resolvers for Cloudflare, Google, and Quad9 in that order
            #               1.1.1.1     8.8.8.8     9.9.9.9
            fallback_resolvers = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]

            if self.dns_server and self.dns_server not in fallback_resolvers:
                resolver.nameservers = [self.dns_server] + fallback_resolvers
            else:
                resolver.nameservers = fallback_resolvers

            # Query TXT records
            query_result = resolver.resolve(domain, "TXT", lifetime=5)

            for record in query_result:
                # Join TXT strings in the associated format.
                # ambc.com for example
                # v=spf1 ip4:52.146.15.77/32 include:spf.protection.outlook.com -all
                try:
                    txt = "".join(s.decode("utf-8") for s in record.strings)
                except AttributeError:
                    txt = str(record)
                # Ensuring we only accept the single version of spf1
                if "v=spf1" in txt:
                    return txt
            return None

        # Verbose outputs for exceptions
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout) as e:
            print(f"[!] SPF query failed for {domain}: {e}")
            return None
        except Exception as e:
            print(f"[!] Unexpected SPF error for {domain}: {e}")
            return None

    def get_spf_all_string(self):
        """Returns the string value of the 'all' mechanism in the SPF record."""

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
                    break  # Prevent infinite loops in case of circular redirects
                visited_domains.add(redirect_domain)
                spf_record = self.get_spf_record(redirect_domain)
            else:
                break

        return None

    def get_spf_dns_queries(self):
        """Returns the number of dns queries, redirects, and other mechanisms in the SPF record for a given domain."""

        def count_dns_queries(spf_record):
            count = 0
            for item in spf_record.split():
                if item.startswith("include:") or item.startswith("redirect="):
                    if item.startswith("include:"):
                        url = item.replace("include:", "")
                    elif item.startswith("redirect="):
                        url = item.replace("redirect=", "")

                    count += 1
                    try:
                        # Recursively fetch and count dns queries or redirects in the SPF record of the referenced domain
                        answers = dns.resolver.resolve(url, "TXT")
                        for rdata in answers:
                            for txt_string in rdata.strings:
                                txt_record = txt_string.decode("utf-8")
                                if txt_record.startswith("v=spf1"):
                                    count += count_dns_queries(txt_record)
                    except Exception:
                        pass

            # Count occurrences of 'a', 'mx', 'ptr', and 'exists' mechanisms
            count += len(re.findall(r"[ ,+]a[ ,:]", spf_record))
            count += len(re.findall(r"[ ,+]mx[ ,:]", spf_record))
            count += len(re.findall(r"[ ]ptr[ ]", spf_record))
            count += len(re.findall(r"exists[:]", spf_record))

            return count

        return count_dns_queries(self.spf_record)

    def __str__(self):
        return (
            f"SPF Record: {self.spf_record}\n"
            f"All Mechanism: {self.all_mechanism}\n"
            f"DNS Query Count: {self.spf_dns_query_count}\n"
            f"Too Many DNS Queries: {self.too_many_dns_queries}"
        )
