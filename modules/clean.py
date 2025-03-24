# modules/clean.py
import re
import pandas as pd
from pathlib import Path

def clean_domains_from_file(input_path, output_path):
    path = Path(input_path).resolve()
    if not path.exists():
        raise FileNotFoundError("Input file not found.")

    ext = path.suffix.lower()
    domain_set = set()
    domain_regex = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")

    if ext == ".csv":
        df = pd.read_csv(path)
        for col in df.columns:
            for val in df[col]:
                if isinstance(val, str):
                    matches = domain_regex.findall(val)
                    for domain in matches:
                        domain_set.add(domain.strip())
    else:
        with path.open("r") as f:
            for line in f:
                matches = domain_regex.findall(line)
                for domain in matches:
                    domain_set.add(domain.strip())

    output_file = Path(output_path).resolve()
    with output_file.open("w") as f:
        for domain in sorted(domain_set):
            f.write(domain + "\n")

    print(f"[+] Cleaned domains written to {output_file}")
