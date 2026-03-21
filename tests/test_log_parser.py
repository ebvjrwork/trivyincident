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

    def test_parse_log_marks_apt_0694_high(self) -> None:
        set_indicator_sets(set(), set(), set())
        content = "2026-03-21T11:22:33Z run\napt-get install -y trivy=0.69.4\n"
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
        self.assertIsNotNone(finding)
        self.assertEqual(finding.usage_type, "apt")
        self.assertEqual(finding.severity, "HIGH")
        self.assertEqual(finding.severity_trigger, "apt-0.69.4")

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


if __name__ == "__main__":
    unittest.main()
