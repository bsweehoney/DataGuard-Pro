"""
Unit tests for DataGuard-Pro's Azure Function core logic.

Run locally:
    cd azurefunc
    pip install pytest
    pytest tests/ -v

These tests import function_app.py directly (mocking azure.functions since
it's not needed for the pure logic being tested), so they run without any
Azure connection or deployed resources.
"""

import sys
import os
import io
import types
import importlib.util
from pathlib import Path

import pytest
import pandas as pd

# ── Mock azure.functions so function_app.py can be imported standalone ────────
def _install_fake_azure_functions():
    fake_func = types.ModuleType("azure.functions")

    class FakeFunctionApp:
        def __init__(self, **kw): pass
        def blob_trigger(self, **kw):
            def deco(f): return f
            return deco
        def route(self, **kw):
            def deco(f): return f
            return deco

    class FakeAuthLevel:
        ANONYMOUS = "anonymous"

    fake_func.FunctionApp = FakeFunctionApp
    fake_func.AuthLevel = FakeAuthLevel
    fake_func.InputStream = object
    fake_func.HttpRequest = object
    fake_func.HttpResponse = object

    sys.modules['azure.functions'] = fake_func
    if 'azure' not in sys.modules:
        sys.modules['azure'] = types.ModuleType("azure")
    sys.modules['azure'].functions = fake_func


@pytest.fixture(scope="session")
def mod():
    """Loads function_app.py as a module for direct testing."""
    _install_fake_azure_functions()
    here = Path(__file__).parent.parent
    spec = importlib.util.spec_from_file_location("function_app", here / "function_app.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


@pytest.fixture
def sample_df():
    return pd.DataFrame({
        "customer_id": [1, 2, 3, None],
        "name": ["Alice", "Bob", "Carol", "Dave"],
        "email": ["alice@test.com", "bad-email", "carol@test.com", "dave@test.com"],
        "age": [25, -3, 34, 150],
        "revenue": [100, 200, -50, 300],
        "serial_number": ["372-88-3412", "SN-002", "SN-003", "SN-004"],
        "notes": [
            "SSN: 372-88-3412",
            "Call 415-555-0199",
            "Regular customer",
            "DOB: 03/15/1985",
        ],
    })


# ── PII Detection Tests ─────────────────────────────────────────────────────

class TestPIIDetection:

    def test_detects_ssn_in_notes_as_high_risk(self, mod, sample_df):
        findings = mod.scan_pii(sample_df, sensitivity="high")
        ssn_findings = [f for f in findings if f["pii_type"] == "SSN" and f["column"] == "notes"]
        assert len(ssn_findings) == 1
        assert ssn_findings[0]["risk"] == "HIGH"

    def test_downgrades_ssn_pattern_in_safe_column_to_low(self, mod, sample_df):
        """Core false-positive reduction test — the whole point of context scoring."""
        findings = mod.scan_pii(sample_df, sensitivity="high")
        serial_findings = [f for f in findings if f["column"] == "serial_number"]
        assert len(serial_findings) >= 1
        assert all(f["risk"] == "LOW" for f in serial_findings)
        assert all(f["confidence"] < 0.40 for f in serial_findings)

    def test_low_sensitivity_excludes_phone_and_dob(self, mod, sample_df):
        findings = mod.scan_pii(sample_df, sensitivity="low")
        types_found = {f["pii_type"] for f in findings}
        assert "PHONE" not in types_found
        assert "DATE_OF_BIRTH" not in types_found

    def test_high_sensitivity_includes_all_pii_types(self, mod, sample_df):
        findings = mod.scan_pii(sample_df, sensitivity="high")
        types_found = {f["pii_type"] for f in findings}
        assert "SSN" in types_found
        assert "PHONE" in types_found
        assert "DATE_OF_BIRTH" in types_found

    def test_email_column_does_not_flag_own_email(self, mod, sample_df):
        findings = mod.scan_pii(sample_df, sensitivity="high")
        email_col_findings = [f for f in findings if f["column"] == "email"]
        assert len(email_col_findings) == 0

    def test_masked_values_never_contain_raw_pii(self, mod, sample_df):
        findings = mod.scan_pii(sample_df, sensitivity="high")
        for f in findings:
            if f["pii_type"] == "SSN":
                assert f["raw_value"] not in f["masked"]
                assert f["masked"].startswith("XXX-XX-")


# ── Data Quality Tests ───────────────────────────────────────────────────────

class TestDataQuality:

    def test_detects_null_id_column(self, mod, sample_df):
        result = mod.check_quality(sample_df)
        id_check = next(r for r in result["results"] if r["column"] == "customer_id")
        assert id_check["passed"] is False
        assert "1 null" in id_check["detail"]

    def test_detects_invalid_email_format(self, mod, sample_df):
        result = mod.check_quality(sample_df)
        email_check = next(r for r in result["results"] if r["column"] == "email")
        assert email_check["passed"] is False

    def test_detects_out_of_range_age(self, mod, sample_df):
        result = mod.check_quality(sample_df)
        age_check = next(r for r in result["results"] if r["column"] == "age")
        assert age_check["passed"] is False
        assert "2 out-of-range" in age_check["detail"]

    def test_detects_negative_revenue(self, mod, sample_df):
        result = mod.check_quality(sample_df)
        revenue_check = next(r for r in result["results"] if r["column"] == "revenue")
        assert revenue_check["passed"] is False


# ── Duplicate Detection Tests ────────────────────────────────────────────────

class TestDuplicateDetection:

    def test_no_duplicates_in_clean_data(self, mod, sample_df):
        result = mod.check_duplicates(sample_df)
        assert result["exact_duplicates"] == 0

    def test_detects_exact_duplicate_row(self, mod, sample_df):
        df_with_dupe = pd.concat([sample_df, sample_df.iloc[[0]]], ignore_index=True)
        result = mod.check_duplicates(df_with_dupe)
        assert result["exact_duplicates"] == 1
        assert result["duplicate_pct"] > 0


# ── Scoring Tests ─────────────────────────────────────────────────────────────

class TestScoring:

    def test_perfect_dataset_scores_high(self, mod):
        df = pd.DataFrame({"id": [1, 2, 3], "value": [10, 20, 30]})
        pii = mod.scan_pii(df, sensitivity="high")
        quality = mod.check_quality(df)
        dupes = mod.check_duplicates(df)
        scores = mod.calculate_score(pii, quality, dupes, len(df))
        assert scores["overall"] >= 85
        assert scores["grade"].startswith("A")

    def test_dirty_dataset_scores_low(self, mod, sample_df):
        pii = mod.scan_pii(sample_df, sensitivity="high")
        quality = mod.check_quality(sample_df)
        dupes = mod.check_duplicates(sample_df)
        scores = mod.calculate_score(pii, quality, dupes, len(sample_df))
        assert scores["overall"] < 70

    def test_score_grade_boundaries(self, mod):
        assert mod.calculate_score([], {"passed":1,"total":1,"failed":0}, {"duplicate_pct":0}, 10)["grade"].startswith("A")


# ── Remediation Engine Tests ─────────────────────────────────────────────────

class TestRemediation:

    def test_masking_removes_raw_pii_from_output(self, mod, sample_df):
        findings = mod.scan_pii(sample_df, sensitivity="high")
        clean = mod.remediate(sample_df, findings, mask=True, dedup=False)
        for f in findings:
            if f["risk"] in ("HIGH", "MEDIUM"):
                col_value = str(clean.iloc[f["row"]][f["column"]])
                assert f["raw_value"] not in col_value

    def test_dedup_removes_duplicate_rows(self, mod, sample_df):
        df_with_dupe = pd.concat([sample_df, sample_df.iloc[[0]]], ignore_index=True)
        findings = mod.scan_pii(df_with_dupe, sensitivity="high")
        clean = mod.remediate(df_with_dupe, findings, mask=False, dedup=True)
        assert len(clean) == len(sample_df)

    def test_low_risk_findings_are_never_masked(self, mod, sample_df):
        """LOW confidence findings (false positives) should be left untouched."""
        findings = mod.scan_pii(sample_df, sensitivity="high")
        clean = mod.remediate(sample_df, findings, mask=True, dedup=False)
        low_findings = [f for f in findings if f["risk"] == "LOW"]
        for f in low_findings:
            col_value = str(clean.iloc[f["row"]][f["column"]])
            assert f["raw_value"] in col_value


# ── Format Conversion Tests ──────────────────────────────────────────────────

class TestFormatConversion:

    def test_detect_format_from_extension(self, mod):
        assert mod.detect_format("data.csv") == "csv"
        assert mod.detect_format("data.parquet") == "parquet"
        assert mod.detect_format("data.json") == "json"
        assert mod.detect_format("data.xlsx") == "excel"
        assert mod.detect_format("data.unknown") == "csv"  # defaults to csv

    def test_csv_round_trip_preserves_data(self, mod):
        df = pd.DataFrame({"a": [1, 2, 3], "b": ["x", "y", "z"]})
        raw = mod.write_any_format(df, "csv")
        result_df, fmt = mod.read_any_format(raw, "test.csv")
        assert fmt == "csv"
        assert list(result_df["a"]) == [1, 2, 3]

    def test_parquet_round_trip_preserves_data(self, mod):
        df = pd.DataFrame({"a": [1, 2, 3], "b": ["x", "y", "z"]})
        raw = mod.write_any_format(df, "parquet")
        result_df, fmt = mod.read_any_format(raw, "test.parquet")
        assert fmt == "parquet"
        assert list(result_df["a"]) == [1, 2, 3]

    def test_cross_format_conversion_csv_to_parquet(self, mod):
        """The core promise: upload any format, download any format."""
        df = pd.DataFrame({"a": [1, 2, 3]})
        csv_bytes = mod.write_any_format(df, "csv")
        df_from_csv, _ = mod.read_any_format(csv_bytes, "input.csv")
        parquet_bytes = mod.write_any_format(df_from_csv, "parquet")
        df_from_parquet, fmt = mod.read_any_format(parquet_bytes, "output.parquet")
        assert fmt == "parquet"
        assert list(df_from_parquet["a"]) == [1, 2, 3]

    def test_output_extension_mapping(self, mod):
        assert mod.output_extension("parquet") == "parquet"
        assert mod.output_extension("csv") == "csv"
        assert mod.output_extension("excel") == "xlsx"


# ── Encryption Engine Tests ──────────────────────────────────────────────────

class TestEncryption:

    def test_encrypted_value_is_recoverable(self, mod, monkeypatch):
        from cryptography.fernet import Fernet
        test_key = Fernet.generate_key().decode()
        monkeypatch.setenv("PII_ENCRYPTION_KEY", test_key)

        cipher = mod.get_cipher()
        original = "372-88-3412"
        encrypted = mod.encrypt_value_full(cipher, original)
        decrypted = mod.decrypt_value(cipher, encrypted)

        assert decrypted == original
        assert encrypted != original  # actually encrypted, not passthrough

    def test_missing_key_raises_clear_error(self, mod, monkeypatch):
        monkeypatch.delenv("PII_ENCRYPTION_KEY", raising=False)
        with pytest.raises(ValueError, match="PII_ENCRYPTION_KEY"):
            mod.get_cipher()

    def test_remediate_encrypts_only_high_risk_when_enabled(self, mod, sample_df, monkeypatch):
        from cryptography.fernet import Fernet
        test_key = Fernet.generate_key().decode()
        monkeypatch.setenv("PII_ENCRYPTION_KEY", test_key)

        findings = mod.scan_pii(sample_df, sensitivity="high")
        clean = mod.remediate(sample_df, findings, mask=True, dedup=False, encrypt_high_risk=True)

        high_findings = [f for f in findings if f["risk"] == "HIGH"]
        for f in high_findings:
            col_value = str(clean.iloc[f["row"]][f["column"]])
            # Encrypted values are long base64 tokens, not the short mask
            assert f["masked"] not in col_value
            assert f["raw_value"] not in col_value
