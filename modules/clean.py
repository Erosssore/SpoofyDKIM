import re
import pandas as pd
from pathlib import Path

def clean_domains_from_file(input_path, output_path):
    path = Path(input_path).resolve()
    if not path.exists():
        raise FileNotFoundError("Input file not found.")

    # ext will call the extension of the file
    # create a set called domain_set
    ext = path.suffix.lower()
    domain_set = set()

    # Non-recursive regex
    domain_regex = re.compile(
        r"\b(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}\b"
    )

    # If the file extension is .csv
    if ext == ".csv":
        # Read the csv file
        df = pd.read_csv(path, dtype=str)
        # Check if the csv has at least one column
        if df.shape[1] < 1:
            raise ValueError("CSV file has no columns.")

        # Check the first column assuming domain is there
        first_col = df.columns[0]
        # Assume every non-empty entry is a domain
        for val in df[first_col].dropna():
            domain_set.add(val.strip())

    else:
        # Read the file and ignore any errors. For lines in the file add the corresponding regex values
        with path.open("r", encoding='utf-8', errors='ignore') as f:
            for line in f:
                matches = domain_regex.findall(line)
                # Strip whitespace values
                domain_set.update(match.strip() for match in matches)

    # Resolve to absolute path and write the file
    output_file = Path(output_path).resolve()
    with output_file.open("w") as f:
        for domain in sorted(domain_set):
            f.write(domain + "\n")

    # Print statement to the console once this method is completed
    print(f"[+] Cleaned domains written to {output_file}")
