#!/usr/bin/env python3
"""
Unit and integration tests for EDB Lasso Reduction PoC
"""

import unittest
import tempfile
import shutil
from pathlib import Path
from lasso_redact import LassoReductionEngine, DEFAULT_PATTERNS


class TestLassoReduction(unittest.TestCase):

    def setUp(self):
        self.engine = LassoReductionEngine(pseudonymize_ips=True)

    def test_conninfo_password_redaction(self):
        raw = "primary_conninfo = 'host=10.0.12.45 user=repuser password=MySecret123! port=5432'"
        redacted, matches = self.engine.redact_text(raw)
        self.assertNotIn("MySecret123!", redacted)
        self.assertIn("[REDACTED_PASSWORD]", redacted)
        self.assertIn("PSEUDO_IP_NODE_", redacted)

    def test_database_uri_redaction(self):
        raw = "diagnostic_exporter_uri = postgres://admin:P@ssword123@192.168.1.50:5432/mydb"
        redacted, matches = self.engine.redact_text(raw)
        self.assertNotIn("P@ssword123", redacted)
        self.assertIn("[REDACTED_PASSWORD]", redacted)

    def test_edb_customer_token_redaction(self):
        raw = "EDB_CUSTOMER_TOKEN=edb_prod_cust_tok_982734190843719827419827"
        redacted, matches = self.engine.redact_text(raw)
        self.assertNotIn("edb_prod_cust_tok_982734190843719827419827", redacted)
        self.assertIn("[REDACTED_EDB_TOKEN]", redacted)

    def test_deterministic_ip_pseudonymization(self):
        raw = "Node A is 10.0.12.45 and Node B is 10.0.12.46. Ping 10.0.12.45 again."
        redacted, _ = self.engine.redact_text(raw)
        self.assertNotIn("10.0.12.45", redacted)
        self.assertNotIn("10.0.12.46", redacted)
        # Verify deterministic mapping: 10.0.12.45 appears twice as the same pseudo node
        first_pseudo = self.engine.ip_map["10.0.12.45"]
        self.assertEqual(redacted.count(first_pseudo), 2)

    def test_directory_redaction(self):
        with tempfile.TemporaryDirectory() as tmp_out:
            manifest = self.engine.redact_directory(Path("mock_lasso_bundle"), Path(tmp_out))
            self.assertGreater(manifest["total_redactions"], 0)
            self.assertTrue((Path(tmp_out) / "lasso_reduction_manifest.json").exists())
            self.assertTrue((Path(tmp_out) / "postgresql.conf").exists())

            # Read redacted postgresql.conf
            with open(Path(tmp_out) / "postgresql.conf") as f:
                content = f.read()
                self.assertNotIn("SuperSecretP@ssw0rd!", content)
                self.assertNotIn("BarmanVaultPass987!", content)

    def test_tarball_creation_and_redaction(self):
        from lasso_redact import create_mock_bundle_tarball
        with tempfile.TemporaryDirectory() as tmp_dir:
            raw_tar = Path(tmp_dir) / "raw.tar.gz"
            out_tar = Path(tmp_dir) / "sanitized.tar.gz"

            create_mock_bundle_tarball(Path("mock_lasso_bundle"), raw_tar)
            self.assertTrue(raw_tar.exists())

            manifest = self.engine.redact_tarball(raw_tar, out_tar)
            self.assertTrue(out_tar.exists())
            self.assertGreater(manifest["total_redactions"], 0)


if __name__ == "__main__":
    unittest.main()
