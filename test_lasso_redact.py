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

    def test_nested_tar_bz2_redaction(self):
        import tarfile
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            nested_src = tmp_path / "nested_src"
            nested_src.mkdir()
            sample_conf = nested_src / "postgresql.conf"
            sample_conf.write_text("password = 'NestedSecretPassword123!'\nhost = 192.168.1.99")

            # Create a nested .tar.bz2
            bundle_dir = tmp_path / "bundle"
            bundle_dir.mkdir()
            nested_bz2 = bundle_dir / "edb-lasso-nested.tar.bz2"
            with tarfile.open(nested_bz2, "w:bz2") as tar:
                tar.add(sample_conf, arcname="postgresql.conf")

            # Run reduction on the bundle containing the nested archive
            out_bundle = tmp_path / "sanitized_bundle"
            manifest = self.engine.redact_directory(bundle_dir, out_bundle)

            # Verify that the nested .tar.bz2 was recreated
            sanitized_bz2 = out_bundle / "edb-lasso-nested.tar.bz2"
            self.assertTrue(sanitized_bz2.exists())
            self.assertGreater(manifest["total_redactions"], 0)

            # Unpack the sanitized nested archive and inspect contents
            extracted_check = tmp_path / "extracted_check"
            with tarfile.open(sanitized_bz2, "r:bz2") as tar:
                tar.extractall(extracted_check)

            redacted_text = (extracted_check / "postgresql.conf").read_text()
            self.assertNotIn("NestedSecretPassword123!", redacted_text)
            self.assertIn("[REDACTED_PASSWORD]", redacted_text)
            self.assertIn("PSEUDO_IP_NODE_", redacted_text)

    def test_fallback_copy_on_read_failure(self):
        import unittest.mock
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            sample_file = tmp_path / "sample.bin"
            sample_data = b"\x00\x01\x02\xff\xfe\xfd"
            sample_file.write_bytes(sample_data)

            out_file = tmp_path / "out" / "sample.bin"
            with unittest.mock.patch.object(self.engine, "redact_text", side_effect=Exception("Failed to parse")):
                redactions = self.engine.redact_file(sample_file, out_file)
                self.assertEqual(redactions, 0)
                self.assertTrue(out_file.exists())
                self.assertEqual(out_file.read_bytes(), sample_data)

    def test_dual_manifests_when_zipped_in_output(self):
        """Verify that when a tarball is reduced, 2 manifest files are created in the output destination:
        1. lasso_reduction_manifest_security_donotshare.json
        2. lasso_reduction_manifest_support.json
        And verify that the support manifest contains ZERO credentials, while the security manifest preserves internal audit data.
        """
        import tarfile
        import json
        from lasso_redact import create_mock_bundle_tarball

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            raw_tar = tmp_path / "raw.tar.gz"
            out_dir = tmp_path / "output_bundle"
            out_dir.mkdir()
            out_tar = out_dir / "sanitized.tar.gz"

            create_mock_bundle_tarball(Path("mock_lasso_bundle"), raw_tar)
            self.engine.redact_tarball(raw_tar, out_tar)

            self.assertTrue(out_tar.exists())

            # 1. Verify both manifest files exist in output directory
            sec_manifest_path = out_dir / "lasso_reduction_manifest_security_donotshare.json"
            sup_manifest_path = out_dir / "lasso_reduction_manifest_support.json"
            self.assertTrue(sec_manifest_path.exists(), "Security manifest must exist in output")
            self.assertTrue(sup_manifest_path.exists(), "Support manifest must exist in output")

            # 2. Inspect support manifest: must NOT contain credentials
            with open(sup_manifest_path) as f:
                sup_data = json.load(f)

            sup_str = json.dumps(sup_data)
            self.assertNotIn("SuperSecretP@ssw0rd!", sup_str)
            self.assertNotIn("BarmanVaultPass987!", sup_str)
            self.assertNotIn("10.0.12.45", sup_str)
            self.assertEqual(sup_data["manifest_type"], "support")
            self.assertIn("pseudonymized_nodes", sup_data)

            # 3. Inspect security manifest: contains internal audit trail and IP mapping
            with open(sec_manifest_path) as f:
                sec_data = json.load(f)

            self.assertEqual(sec_data["manifest_type"], "security_donotshare")
            self.assertIn("CONFIDENTIAL", sec_data["confidentiality"])
            self.assertIn("10.0.12.45", sec_data["ip_mapping"])

            # 4. Inspect tarball contents: security manifest must NOT be inside the archive sent to support!
            with tarfile.open(out_tar, "r:gz") as tar:
                names = tar.getnames()
                self.assertTrue(any("lasso_reduction_manifest_support.json" in n for n in names))
                self.assertFalse(any("security_donotshare" in n for n in names))


if __name__ == "__main__":
    unittest.main()
