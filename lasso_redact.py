#!/usr/bin/env python3
"""
EDB Lasso Diagnostic Reduction & Redaction Engine
Proof of Concept (PoC) Tool

Safely strips, masks, and pseudonymizes sensitive credentials, passwords,
tokens, internal IPs, and secrets from EDB Lasso diagnostic bundles before
sharing with external support or community forums.
"""

import os
import re
import sys
import json
import tarfile
import argparse
import hashlib
import shutil
from pathlib import Path
from typing import Dict, List, Tuple, Any

# Regular expression rules for identifying sensitive data in EDB Lasso diagnostic artifacts
DEFAULT_PATTERNS = [
    # Passwords in PostgreSQL connection strings / conninfo
    {
        "id": "CONNINFO_PASSWORD",
        "name": "PostgreSQL Connection String Password",
        "regex": r'(password\s*=\s*)([\'"]?)([^\s\'"]+)\2',
        "replacement": r'\1[REDACTED_PASSWORD]',
        "category": "credentials"
    },
    # Passwords in URI format: postgres://user:password@host:5432/db
    {
        "id": "URI_CREDENTIALS",
        "name": "Database URI User Credentials",
        "regex": r'((?:postgres|postgresql|edb):\/\/[^:\/\s]+:)([^@\s]+)(@)',
        "replacement": r'\1[REDACTED_PASSWORD]\3',
        "category": "credentials"
    },
    # SCRAM-SHA-256 password secrets
    {
        "id": "SCRAM_SECRET",
        "name": "PostgreSQL SCRAM-SHA-256 Hash",
        "regex": r'SCRAM-SHA-256\$[0-9]+:[a-zA-Z0-9+/=]+\$[a-zA-Z0-9+/=]+:[a-zA-Z0-9+/=]+',
        "replacement": 'SCRAM-SHA-256$[REDACTED_SCRAM_SECRET]',
        "category": "credentials"
    },
    # MD5 password hashes in pg_hba or catalogs
    {
        "id": "MD5_PASSWORD",
        "name": "PostgreSQL MD5 Password Hash",
        "regex": r'\bmd5[a-f0-9]{32}\b',
        "replacement": 'md5[REDACTED_MD5_HASH]',
        "category": "credentials"
    },
    # EDB Customer Portal Token
    {
        "id": "EDB_CUSTOMER_TOKEN",
        "name": "EDB Customer / Support Portal Token",
        "regex": r'(EDB_CUSTOMER_TOKEN\s*=\s*|token\s*:\s*[\'"]?)([a-zA-Z0-9_\-]{24,64})',
        "replacement": r'\1[REDACTED_EDB_TOKEN]',
        "category": "api_tokens"
    },
    # Cloud secrets & Generic API keys
    {
        "id": "GENERIC_API_KEY",
        "name": "API Keys and Cloud Access Secrets",
        "regex": r'((?:aws_secret_access_key|api_key|secret_key|auth_token)\s*[:=]\s*[\'"]?)([a-zA-Z0-9\/+=_\-]{16,64})',
        "replacement": r'\1[REDACTED_SECRET_KEY]',
        "category": "api_tokens"
    },
    # Private cryptographic keys
    {
        "id": "PRIVATE_KEY",
        "name": "Private Cryptographic Key Block",
        "regex": r'-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----',
        "replacement": '-----BEGIN PRIVATE KEY-----\n[REDACTED_PRIVATE_KEY_BLOCK]\n-----END PRIVATE KEY-----',
        "category": "certificates"
    },
    # Barman backup SSH & password parameters
    {
        "id": "BARMAN_SECRETS",
        "name": "Barman Backup Password / Auth Strings",
        "regex": r'((?:barman_password|ssh_command\s*=.*?-i\s+)[^\n;]*?password=)([^\s\'"]+)',
        "replacement": r'\1[REDACTED_BARMAN_SECRET]',
        "category": "ecosystem"
    }
]

# IPv4 Regex for deterministic IP pseudonymization
IPV4_REGEX = re.compile(
    r'\b(?!(?:127\.0\.0\.1|0\.0\.0\.0)\b)(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
)


class LassoReductionEngine:
    """Engine responsible for sanitizing and pseudonymizing EDB Lasso bundles."""

    def __init__(self, pseudonymize_ips: bool = True, custom_patterns: List[Dict[str, str]] = None):
        self.pseudonymize_ips = pseudonymize_ips
        self.patterns = DEFAULT_PATTERNS + (custom_patterns or [])
        self.ip_map: Dict[str, str] = {}
        self.ip_counter = 1
        self.audit_records: List[Dict[str, Any]] = []

    def get_pseudo_ip(self, ip: str) -> str:
        """Deterministic IP pseudonymization mapping."""
        if ip not in self.ip_map:
            self.ip_map[ip] = f"PSEUDO_IP_NODE_{self.ip_counter:02d}"
            self.ip_counter += 1
        return self.ip_map[ip]

    def redact_text(self, text: str, source_identifier: str = "stream") -> Tuple[str, List[Dict[str, Any]]]:
        """Redacts sensitive strings from a given text block."""
        redacted_text = text
        matches_found = []

        # 1. Apply rule-based pattern replacements
        for rule in self.patterns:
            pattern = re.compile(rule["regex"], re.IGNORECASE | re.MULTILINE)
            for m in pattern.finditer(redacted_text):
                matches_found.append({
                    "rule_id": rule["id"],
                    "rule_name": rule["name"],
                    "category": rule["category"],
                    "source": source_identifier,
                    "matched_sample": m.group(0)[:40] + ("..." if len(m.group(0)) > 40 else "")
                })
            redacted_text = pattern.sub(rule["replacement"], redacted_text)

        # 2. Deterministic IP Pseudonymization
        if self.pseudonymize_ips:
            def ip_sub(match):
                original_ip = match.group(0)
                pseudo = self.get_pseudo_ip(original_ip)
                matches_found.append({
                    "rule_id": "INTERNAL_IP_MASK",
                    "rule_name": "Internal IP Address Pseudonymization",
                    "category": "network",
                    "source": source_identifier,
                    "matched_sample": f"{original_ip} -> {pseudo}"
                })
                return pseudo

            redacted_text = IPV4_REGEX.sub(ip_sub, redacted_text)

        self.audit_records.extend(matches_found)
        return redacted_text, matches_found

    def redact_file(self, file_path: Path, output_path: Path) -> int:
        """Redacts a single file and writes to destination."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()

            redacted_content, matches = self.redact_text(
                content,
                source_identifier=file_path.name
            )

            output_path.parent.mkdir(parents=True, exist_ok=True)

            with open(output_path, "w", encoding="utf-8") as f:
                f.write(redacted_content)

            return len(matches)

        except Exception:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(file_path, output_path)
            return 0

    def redact_nested_tar_bz2(self, archive_path: Path, output_path: Path):
        """Extract, redact and rebuild nested .tar.bz2 archives."""
        import tempfile

        with tempfile.TemporaryDirectory() as tmp_in, tempfile.TemporaryDirectory() as tmp_out:
            with tarfile.open(archive_path, "r:bz2") as tar:
                tar.extractall(tmp_in)

            self.redact_directory(
                Path(tmp_in),
                Path(tmp_out)
            )

            output_path.parent.mkdir(parents=True, exist_ok=True)

            with tarfile.open(output_path, "w:bz2") as tar:
                tar.add(tmp_out, arcname="")

    def redact_directory(self, input_dir: Path, output_dir: Path) -> Dict[str, Any]:
        """Recursively sanitizes a directory of EDB Lasso outputs."""
        input_dir = Path(input_dir)
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        total_files = 0
        total_redactions = 0

        for root, _, files in os.walk(input_dir):
            for file_name in files:
                rel_path = Path(root).relative_to(input_dir) / file_name
                src_file = input_dir / rel_path
                dest_file = output_dir / rel_path

                if file_name.endswith(".tar.bz2"):
                    print(f"[*] Processing nested archive: {src_file}")

                    self.redact_nested_tar_bz2(
                        src_file,
                        dest_file
                    )

                    total_files += 1
                    continue

                redactions = self.redact_file(src_file, dest_file)
                total_files += 1
                total_redactions += redactions

        manifest = self.generate_manifest(input_dir=str(input_dir), output_dir=str(output_dir))
        with open(output_dir / "lasso_reduction_manifest.json", "w", encoding="utf-8") as mf:
            json.dump(manifest, mf, indent=2)

        return manifest

    def redact_tarball(self, tar_path: Path, output_tar_path: Path) -> Dict[str, Any]:
        """Unpacks, sanitizes, and repacks a Lasso diagnostic .tar.gz bundle."""
        import tempfile
        tar_path = Path(tar_path)
        output_tar_path = Path(output_tar_path)

        with tempfile.TemporaryDirectory() as tmp_in, tempfile.TemporaryDirectory() as tmp_out:
            with tarfile.open(tar_path, "r:*") as tar:
                tar.extractall(path=tmp_in)

            manifest = self.redact_directory(Path(tmp_in), Path(tmp_out))

            output_tar_path.parent.mkdir(parents=True, exist_ok=True)
            mode = "w:bz2" if output_tar_path.name.endswith((".tar.bz2", ".tbz2")) else "w:gz"
            with tarfile.open(output_tar_path, mode) as tar:
                tar.add(tmp_out, arcname="edb_lasso_redacted")

        return manifest

    def generate_manifest(self, input_dir: str = "", output_dir: str = "") -> Dict[str, Any]:
        """Generates an audit manifest detailing all redacted occurrences."""
        summary_by_category: Dict[str, int] = {}
        summary_by_rule: Dict[str, int] = {}

        for record in self.audit_records:
            cat = record["category"]
            rule = record["rule_id"]
            summary_by_category[cat] = summary_by_category.get(cat, 0) + 1
            summary_by_rule[rule] = summary_by_rule.get(rule, 0) + 1

        return {
            "title": "EDB Lasso Reduction Manifest",
            "version": "1.0.0",
            "total_redactions": len(self.audit_records),
            "input_path": input_dir,
            "output_path": output_dir,
            "category_breakdown": summary_by_category,
            "rule_breakdown": summary_by_rule,
            "pseudonymized_ip_count": len(self.ip_map),
            "ip_mapping_sample": {k: v for i, (k, v) in enumerate(self.ip_map.items()) if i < 10},
            "records_sample": self.audit_records[:50]
        }


def create_mock_bundle_tarball(source_dir: Path, output_tar: Path) -> Path:
    """Helper to pack a mock or existing diagnostic directory into a .tar.gz bundle."""
    output_tar.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(output_tar, "w:gz") as tar:
        for item in source_dir.iterdir():
            tar.add(item, arcname=item.name)
    return output_tar


def main():
    parser = argparse.ArgumentParser(description="EDB Lasso Diagnostic Reduction PoC")
    parser.add_argument("-i", "--input", help="Input directory or tar.gz bundle from EDB Lasso")
    parser.add_argument("-o", "--output", help="Output destination for sanitized bundle")
    parser.add_argument("--no-pseudo-ip", action="store_true", help="Disable deterministic IP pseudonymization")
    parser.add_argument("--audit-only", action="store_true", help="Audit mode without writing files")
    parser.add_argument("--create-mock-tarball", help="Create a mock .tar.gz archive from mock_lasso_bundle to test tarball reduction")

    args = parser.parse_args()

    if args.create_mock_tarball:
        src = Path("mock_lasso_bundle")
        dest = Path(args.create_mock_tarball)
        print(f"[*] Packaging mock diagnostic bundle into: {dest}")
        create_mock_bundle_tarball(src, dest)
        print(f"[+] Created mock EDB Lasso tarball successfully: {dest} ({dest.stat().st_size} bytes)")
        return

    if not args.input or not args.output:
        parser.error("-i/--input and -o/--output are required unless --create-mock-tarball is specified.")

    engine = LassoReductionEngine(pseudonymize_ips=not args.no_pseudo_ip)
    input_path = Path(args.input)
    output_path = Path(args.output)

    if not input_path.exists():
        print(f"Error: Input path '{input_path}' does not exist.")
        sys.exit(1)

    print(f"[*] Starting EDB Lasso Reduction on: {input_path}")

    if input_path.is_file() and (
        input_path.name.endswith(".tar.gz") or
        input_path.name.endswith(".tgz") or
        input_path.name.endswith(".tar.bz2")
    ):
        manifest = engine.redact_tarball(input_path, output_path)
    elif input_path.is_dir():
        manifest = engine.redact_directory(input_path, output_path)
    else:
        # Single file
        engine.redact_file(input_path, output_path)
        manifest = engine.generate_manifest(str(input_path), str(output_path))
        with open(output_path.parent / "lasso_reduction_manifest.json", "w", encoding="utf-8") as mf:
            json.dump(manifest, mf, indent=2)

    print("\n[+] Reduction Completed Successfully!")
    print(f"    - Total Redacted Secrets: {manifest['total_redactions']}")
    print(f"    - Redactions by Category: {manifest['category_breakdown']}")
    print(f"    - Pseudonymized IPs: {manifest['pseudonymized_ip_count']}")
    print(f"    - Redacted Output Written To: {output_path}")


if __name__ == "__main__":
    main()
