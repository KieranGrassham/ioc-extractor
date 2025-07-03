#!/usr/bin/env python3
"""
ioc_extractor.py

A simple script to extract Indicators of Compromise (IOCs) from text files.
It will find:
  - IPv4 addresses
  - Domain names
  - MD5, SHA1, SHA256 hashes

Usage:
    python ioc_extractor.py input_file.txt

Author: Your Name
"""

import re
import sys

# Regex patterns
IP_PATTERN = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9-]+\.)+(?:[a-zA-Z]{2,})\b"
)
MD5_PATTERN = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_PATTERN = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256_PATTERN = re.compile(r"\b[a-fA-F0-9]{64}\b")


def extract_iocs(text):
    """
    Extracts IOCs from the input text.
    Returns a dictionary of lists.
    """
    iocs = {
        "ips": list(set(IP_PATTERN.findall(text))),
        "domains": list(set(DOMAIN_PATTERN.findall(text))),
        "md5": list(set(MD5_PATTERN.findall(text))),
        "sha1": list(set(SHA1_PATTERN.findall(text))),
        "sha256": list(set(SHA256_PATTERN.findall(text))),
    }
    return iocs


def print_iocs(iocs):
    """
    Nicely prints the extracted IOCs.
    """
    for key, values in iocs.items():
        print(f"\n=== {key.upper()} ===")
        if values:
            for v in values:
                print(v)
        else:
            print("None found.")


def main():
    if len(sys.argv) != 2:
        print("Usage: python ioc_extractor.py <input_file>")
        sys.exit(1)

    input_file = sys.argv[1]

    try:
        with open(input_file, "r") as f:
            content = f.read()
    except Exception as e:
        print(f"Error reading file: {e}")
        sys.exit(1)

    iocs = extract_iocs(content)
    print_iocs(iocs)


if __name__ == "__main__":
    main()
