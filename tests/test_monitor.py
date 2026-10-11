"""Tests for the file integrity monitor."""

import hashlib
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from unittest.mock import patch

import monitor


class MonitorTests(unittest.TestCase):
    """Exercise hashing, baseline generation, and change detection."""

    def setUp(self):
        self.original_directory = os.getcwd()
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.addCleanup(os.chdir, self.original_directory)
        os.chdir(self.temporary_directory.name)
        self.target_directory = os.path.join(self.temporary_directory.name, "target")
        os.makedirs(self.target_directory)

    def _target_file(self, name):
        """Return a normalized path for a file inside the monitored tree."""
        return os.path.join(self.target_directory, name).replace("\\", "/")

    def test_calculate_sha256_returns_known_digest(self):
        file_path = os.path.join(self.target_directory, "sample.txt")
        with open(file_path, "wb") as sample:
            sample.write(b"abc")

        self.assertEqual(
            monitor.calculate_sha256(file_path),
            hashlib.sha256(b"abc").hexdigest(),
        )

    def test_calculate_sha256_returns_none_for_missing_file(self):
        missing_path = os.path.join(self.target_directory, "missing.txt")

        self.assertIsNone(monitor.calculate_sha256(missing_path))

    def test_log_event_prints_and_appends_alert(self):
        output = StringIO()
        with redirect_stdout(output):
            monitor.log_event("MODIFIED", "target/sample.txt", "changed")

        log_path = os.path.join(os.getcwd(), monitor.LOG_FILE)
        with open(log_path, encoding="utf-8") as log_file:
            entry = log_file.read()

        self.assertIn("[MODIFIED] target/sample.txt changed", output.getvalue())
        self.assertEqual(entry, output.getvalue())

    def test_generate_baseline_includes_nested_files(self):
        nested_directory = os.path.join(self.target_directory, "nested")
        os.makedirs(nested_directory)
        contents = {
            self._target_file("root.txt"): b"root",
            os.path.join(nested_directory, "nested.txt").replace("\\", "/"): b"nested",
        }
        for file_path, data in contents.items():
            with open(file_path, "wb") as sample:
                sample.write(data)

        with redirect_stdout(StringIO()):
            monitor.generate_baseline(self.target_directory)

        with open(monitor.BASELINE_FILE, encoding="utf-8") as baseline_file:
            baseline = json.load(baseline_file)

        self.assertEqual(
            baseline,
            {
                path: hashlib.sha256(data).hexdigest()
                for path, data in contents.items()
            },
        )

    def test_generate_baseline_exits_for_missing_directory(self):
        output = StringIO()
        with redirect_stdout(output):
            with self.assertRaises(SystemExit) as error:
                monitor.generate_baseline(os.path.join(self.target_directory, "absent"))

        self.assertEqual(error.exception.code, 1)
        self.assertIn("does not exist", output.getvalue())

    def test_monitor_directory_requires_baseline(self):
        with self.assertRaises(SystemExit) as error:
            monitor.monitor_directory(self.target_directory)

        self.assertEqual(error.exception.code, 1)

    def test_monitor_reports_new_modified_and_deleted_files_once(self):
        modified_file = self._target_file("modified.txt")
        deleted_file = self._target_file("deleted.txt")
        new_file = self._target_file("new.txt")
        for file_path in (modified_file, deleted_file):
            with open(file_path, "w", encoding="utf-8") as sample:
                sample.write("original")

        with redirect_stdout(StringIO()):
            monitor.generate_baseline(self.target_directory)

        with open(modified_file, "w", encoding="utf-8") as sample:
            sample.write("changed")
        os.remove(deleted_file)
        with open(new_file, "w", encoding="utf-8") as sample:
            sample.write("new")

        output = StringIO()
        with redirect_stdout(output):
            with patch.object(monitor.time, "sleep", side_effect=[None, KeyboardInterrupt]):
                monitor.monitor_directory(self.target_directory, interval=0)

        log_path = os.path.join(os.getcwd(), monitor.LOG_FILE)
        with open(log_path, encoding="utf-8") as log_file:
            log_entries = log_file.readlines()

        self.assertEqual(len(log_entries), 3)
        self.assertEqual(
            {entry.split("] [", 1)[1].split("]", 1)[0] for entry in log_entries},
            {"NEW_FILE", "MODIFIED", "DELETED"},
        )
        self.assertIn(modified_file, output.getvalue())
        self.assertIn(deleted_file, output.getvalue())
        self.assertIn(new_file, output.getvalue())
        self.assertIn("Monitoring stopped by user", output.getvalue())


if __name__ == "__main__":
    unittest.main()
