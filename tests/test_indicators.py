import os
import tempfile
import unittest

from trivyincident.indicators import load_indicator_db_file, load_indicator_sets


class IndicatorLoadingTests(unittest.TestCase):
    def test_load_indicator_db_file_ignores_comments_and_normalizes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "workflow-sha.db")
            with open(path, "w", encoding="utf-8") as f:
                f.write("# comment\n")
                f.write("\n")
                f.write("ABCDEF1234\n")

            values = load_indicator_db_file(path)
            self.assertEqual(values, {"abcdef1234"})

    def test_load_indicator_sets_supports_fallback_filenames(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "workflow_shas.db"), "w", encoding="utf-8") as f:
                f.write("deadbeef\n")
            with open(os.path.join(tmp, "binary_sha256.db"), "w", encoding="utf-8") as f:
                f.write("cafebabe\n")
            with open(os.path.join(tmp, "network_iocs.db"), "w", encoding="utf-8") as f:
                f.write("evil.example\n")

            workflow, binary, network = load_indicator_sets(tmp)
            self.assertEqual(workflow, {"deadbeef"})
            self.assertEqual(binary, {"cafebabe"})
            self.assertEqual(network, {"evil.example"})


if __name__ == "__main__":
    unittest.main()
