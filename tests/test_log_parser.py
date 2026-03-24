import os
import tempfile
import unittest

from trivyincident.log_parser import (
    extract_first_log_timestamp_from_file,
    extract_workflow_name_from_file,
    parse_log_for_finding,
    set_indicator_sets,
)
from trivyincident.models import RunInfo


class LogParserTests(unittest.TestCase):
    def _write_temp_log(self, content: str) -> str:
        tmp = tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8")
        tmp.write(content)
        tmp.flush()
        tmp.close()
        self.addCleanup(lambda: os.path.exists(tmp.name) and os.unlink(tmp.name))
        return tmp.name

    def test_extract_timestamp_from_file(self) -> None:
        path = self._write_temp_log("line\n2026-03-21T11:22:33Z runner\n")
        self.assertEqual(extract_first_log_timestamp_from_file(path), "2026-03-21T11:22:33Z")

    def test_extract_workflow_name_prefers_complete_job_name(self) -> None:
        content = "===== 1_build.txt =====\nComplete job name: nightly security scan\n"
        path = self._write_temp_log(content)
        self.assertEqual(extract_workflow_name_from_file(path), "nightly security scan")

    def test_extract_workflow_name_uses_section_header_fallback(self) -> None:
        path = self._write_temp_log("===== 2_release-check.txt =====\nother line\n")
        self.assertEqual(extract_workflow_name_from_file(path), "release-check")

    def test_parse_log_marks_malicious_version_critical(self) -> None:
        set_indicator_sets(set(), set(), set())
        for ver in ("0.69.4", "0.69.5", "0.69.6"):
            content = f"2026-03-21T11:22:33Z run\napt-get install -y trivy={ver}\n"
            path = self._write_temp_log(content)
            run = RunInfo(
                repo="org/repo",
                run_id=123,
                run_number=1,
                created_at="",
                workflow_name="wf",
                conclusion="success",
                status="completed",
            )

            finding = parse_log_for_finding(run, path)
            self.assertIsNotNone(finding, f"No finding for version {ver}")
            self.assertEqual(finding.usage_type, "apt")
            self.assertEqual(finding.severity, "CRITICAL", f"Version {ver} should be CRITICAL")
            self.assertIn(f"malicious-version:{ver}", finding.ioc_match)

    def test_parse_log_marks_ioc_hit_critical(self) -> None:
        malicious_sha = "a" * 40
        set_indicator_sets({malicious_sha}, set(), set())
        content = (
            "2026-03-21T11:22:33Z run\n"
            "Download action repository 'aquasecurity/trivy-action@0.35.0' (SHA:"
            + malicious_sha
            + ")\n"
        )
        path = self._write_temp_log(content)
        run = RunInfo(
            repo="org/repo",
            run_id=999,
            run_number=1,
            created_at="",
            workflow_name="wf",
            conclusion="success",
            status="completed",
        )

        finding = parse_log_for_finding(run, path)
        self.assertIsNotNone(finding)
        self.assertEqual(finding.severity, "CRITICAL")
        self.assertEqual(finding.severity_trigger, "ioc-hit")
        self.assertIn("workflow-sha:aquasecurity/trivy-action", finding.ioc_match)

    def test_action_ref_high_only_inside_exposure_window(self) -> None:
        """trivy-action with mutable tag should be HIGH only inside exposure window."""
        set_indicator_sets(set(), set(), set())

        # Inside trivy-action exposure window (2026-03-19 17:43 – 2026-03-20 05:40 UTC)
        content_in = (
            "2026-03-19T20:00:00Z run\n"
            "Download action repository 'aquasecurity/trivy-action@0.28.0' (SHA:" + "b" * 40 + ")\n"
        )
        path_in = self._write_temp_log(content_in)
        run_in = RunInfo(
            repo="org/repo", run_id=100, run_number=1,
            created_at="2026-03-19T20:00:00Z", workflow_name="ci",
            conclusion="success", status="completed",
        )
        finding_in = parse_log_for_finding(run_in, path_in)
        self.assertIsNotNone(finding_in)
        self.assertEqual(finding_in.severity, "HIGH")
        self.assertIn("action-ref-risk:", finding_in.severity_trigger)

    def test_action_ref_downgraded_outside_exposure_window(self) -> None:
        """trivy-action with mutable tag should be MEDIUM outside exposure window."""
        set_indicator_sets(set(), set(), set())

        # Outside exposure window (2026-03-19 10:00 — hours before compromise)
        content_out = (
            "2026-03-19T10:00:00Z run\n"
            "Download action repository 'aquasecurity/trivy-action@0.28.0' (SHA:" + "c" * 40 + ")\n"
        )
        path_out = self._write_temp_log(content_out)
        run_out = RunInfo(
            repo="org/repo", run_id=101, run_number=1,
            created_at="2026-03-19T10:00:00Z", workflow_name="ci",
            conclusion="success", status="completed",
        )
        finding_out = parse_log_for_finding(run_out, path_out)
        self.assertIsNotNone(finding_out)
        self.assertEqual(finding_out.severity, "MEDIUM")
        self.assertIn("outside-exposure-window", finding_out.severity_trigger)

    def test_setup_trivy_high_inside_window_medium_outside(self) -> None:
        """setup-trivy with any tag: HIGH inside window, MEDIUM outside."""
        set_indicator_sets(set(), set(), set())

        # Inside setup-trivy window (2026-03-19 17:43 – 21:44 UTC)
        content_in = (
            "2026-03-19T19:00:00Z run\n"
            "Download action repository 'aquasecurity/setup-trivy@v0.2.0' (SHA:" + "d" * 40 + ")\n"
        )
        path_in = self._write_temp_log(content_in)
        run_in = RunInfo(
            repo="org/repo", run_id=200, run_number=1,
            created_at="2026-03-19T19:00:00Z", workflow_name="ci",
            conclusion="success", status="completed",
        )
        finding_in = parse_log_for_finding(run_in, path_in)
        self.assertIsNotNone(finding_in)
        self.assertEqual(finding_in.severity, "HIGH")

        # Outside window (2026-03-19 10:00 UTC)
        content_out = (
            "2026-03-19T10:00:00Z run\n"
            "Download action repository 'aquasecurity/setup-trivy@v0.2.0' (SHA:" + "e" * 40 + ")\n"
        )
        path_out = self._write_temp_log(content_out)
        run_out = RunInfo(
            repo="org/repo", run_id=201, run_number=1,
            created_at="2026-03-19T10:00:00Z", workflow_name="ci",
            conclusion="success", status="completed",
        )
        finding_out = parse_log_for_finding(run_out, path_out)
        self.assertIsNotNone(finding_out)
        self.assertEqual(finding_out.severity, "MEDIUM")


if __name__ == "__main__":
    unittest.main()
