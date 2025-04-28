#! /usr/bin/env python3

import argparse
import threading
from queue import Queue
from modules.dns import DNS
from modules.spf import SPF
from modules.dmarc import DMARC
from modules.bimi import BIMI
from modules.dkim import DKIM
from modules.spoofing import Spoofing
from modules import report
from modules.clean import clean_domains_from_file

print_lock = threading.Lock()


def process_domain(domain):
    dns_info = DNS(domain)
    spf = SPF(domain, dns_info.dns_server)
    dmarc = DMARC(domain, dns_info.dns_server)
    bimi_info = BIMI(domain, dns_info.dns_server)
    dkim_info = DKIM(domain, dns_info.dns_server)

    spoofing_info = Spoofing(
        domain,
        dmarc.dmarc_record,
        dmarc.policy,
        dmarc.aspf,
        spf.spf_record,
        spf.all_mechanism,
        spf.spf_dns_query_count,
        dmarc.sp,
        dmarc.pct,
    )

    return {
        "DOMAIN": domain,
        "DOMAIN_TYPE": spoofing_info.domain_type,
        "DNS_SERVER": dns_info.dns_server,
        "SPF": spf.spf_record,
        "SPF_MULTIPLE_ALLS": spf.all_mechanism,
        "SPF_NUM_DNS_QUERIES": spf.spf_dns_query_count,
        "SPF_TOO_MANY_DNS_QUERIES": spf.too_many_dns_queries,
        "DMARC": dmarc.dmarc_record,
        "DMARC_POLICY": dmarc.policy,
        "DMARC_PCT": dmarc.pct,
        "DMARC_ASPF": dmarc.aspf,
        "DMARC_SP": dmarc.sp,
        "DMARC_FORENSIC_REPORT": dmarc.fo,
        "DMARC_AGGREGATE_REPORT": dmarc.rua,
        "BIMI_RECORD": bimi_info.bimi_record,
        "BIMI_VERSION": bimi_info.version,
        "BIMI_LOCATION": bimi_info.location,
        "BIMI_AUTHORITY": bimi_info.authority,
        "SPOOFING_POSSIBLE": spoofing_info.spoofing_possible,
        "SPOOFING_TYPE": spoofing_info.spoofing_type,
    }


def worker(domain_queue, print_lock, output, results):
    while True:
        domain = domain_queue.get()
        if domain is None:
            break
        result = process_domain(domain)
        with print_lock:
            if output == "stdout":
                report.printer(**result)
            else:
                results.append(result)
        domain_queue.task_done()


def main():
    parser = argparse.ArgumentParser(
        description="Process domains to gather DNS, SPF, DMARC, and BIMI records."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", type=str, help="Single domain to process.")
    group.add_argument("-iL", type=str, help="File containing a list of domains.")
    parser.add_argument(
        "-o", type=str, choices=["stdout", "xls"], default="stdout", help="Output format"
    )
    parser.add_argument("-t", type=int, default=4, help="Number of threads")

    args = parser.parse_args()

    if args.d:
        domains = [args.d]
    elif args.iL:
        temp_path = ".spoofy_autoclean.txt"
        clean_domains_from_file(args.iL, temp_path)
        with open(temp_path, "r") as f:
            domains = [line.strip() for line in f if line.strip()]

    domain_queue = Queue()
    results = []

    for domain in domains:
        domain_queue.put(domain)

    threads = []
    for _ in range(min(args.t, len(domains))):
        thread = threading.Thread(
            target=worker, args=(domain_queue, print_lock, args.o, results)
        )
        thread.start()
        threads.append(thread)

    domain_queue.join()

    if args.o == "xls" and results:
        report.write_to_excel(results)
        print("Results written to output.xlsx")

    for _ in threads:
        domain_queue.put(None)
    for thread in threads:
        thread.join()


if __name__ == "__main__":
    main()
