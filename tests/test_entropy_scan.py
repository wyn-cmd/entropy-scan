import os
import random
import subprocess
import sys
import tempfile
import unittest
import zlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from entropy_scan import identify, iter_windows, scan_bytes, shannon_entropy

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(PROJECT_ROOT, "entropy_scan.py")

# Deterministic filler so the tests never depend on luck
RNG = random.Random(20261110)
RANDOM_BLOB = bytes(RNG.randrange(256) for _ in range(4096))
PLAIN_TEXT = b"The quick brown fox jumps over the lazy dog. " * 200


class EntropyMathTests(unittest.TestCase):
    def test_empty_chunk_is_zero(self):
        self.assertEqual(shannon_entropy(b""), 0.0)

    def test_constant_bytes_are_zero(self):
        self.assertEqual(shannon_entropy(b"A" * 1024), 0.0)

    def test_full_byte_alphabet_is_eight_bits(self):
        self.assertAlmostEqual(shannon_entropy(bytes(range(256))), 8.0, places=6)

    def test_text_sits_far_below_random_data(self):
        self.assertLess(shannon_entropy(PLAIN_TEXT), 5.0)
        self.assertGreater(shannon_entropy(RANDOM_BLOB), 7.9)

    def test_window_iterator_covers_the_tail(self):
        data = b"x" * 1000
        windows = list(iter_windows(data, 256, 32))
        last_offset, last_chunk = windows[-1]
        self.assertEqual(last_offset + len(last_chunk), len(data))
        self.assertEqual(windows[0][0], 0)


class ScanTests(unittest.TestCase):
    def test_plain_text_has_no_regions(self):
        self.assertEqual(scan_bytes(PLAIN_TEXT), [])

    def test_embedded_blob_is_found_once(self):
        payload = b"\x00" * 2048 + RANDOM_BLOB + b"\x00" * 2048
        regions = scan_bytes(payload)
        self.assertEqual(len(regions), 1)
        region = regions[0]
        self.assertLessEqual(region["offset"], 2048)
        self.assertGreaterEqual(region["offset"] + region["length"], 2048 + len(RANDOM_BLOB))
        self.assertGreater(region["peak_entropy"], 7.5)

    def test_small_region_is_dropped_by_min_region(self):
        payload = b"\x00" * 2048 + RANDOM_BLOB + b"\x00" * 2048
        self.assertEqual(scan_bytes(payload, min_region=8192), [])
        self.assertEqual(len(scan_bytes(payload)), 1)

    def test_zlib_stream_is_named(self):
        compressed = zlib.compress(RANDOM_BLOB, 9)
        tail = bytes(RNG.randrange(256) for _ in range(256))
        payload = b"\x00" * 1024 + compressed + tail + b"\x00" * 1024
        regions = scan_bytes(payload)
        self.assertEqual(len(regions), 1)
        self.assertEqual(regions[0]["format"], "zlib")

    def test_identify_unknown_data(self):
        self.assertIsNone(identify(RANDOM_BLOB))

    def test_threshold_controls_sensitivity(self):
        self.assertEqual(scan_bytes(PLAIN_TEXT, threshold=7.9), [])
        self.assertEqual(len(scan_bytes(RANDOM_BLOB)), 1)
        # A 4096 byte random buffer peaks near 7.83, so a 7.85 cut misses it
        self.assertEqual(scan_bytes(RANDOM_BLOB, threshold=7.85), [])


class CommandLineTests(unittest.TestCase):
    def test_json_report_and_exit_code(self):
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as handle:
            handle.write(b"\x00" * 1024 + RANDOM_BLOB + b"\x00" * 1024)
            path = handle.name
        try:
            result = subprocess.run(
                [sys.executable, SCRIPT, path, "--json", "--fail-on-hit"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 3, result.stderr)
            self.assertIn('"regions"', result.stdout)
            self.assertIn('"size": 6144', result.stdout)
        finally:
            os.unlink(path)

    def test_clean_file_exits_zero(self):
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as handle:
            handle.write(PLAIN_TEXT)
            path = handle.name
        try:
            result = subprocess.run(
                [sys.executable, SCRIPT, path, "--fail-on-hit"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("no high-entropy regions", result.stdout)
        finally:
            os.unlink(path)

    def test_missing_file_reports_error(self):
        result = subprocess.run(
            [sys.executable, SCRIPT, "/definitely/not/here.bin"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("entropy_scan:", result.stderr)


if __name__ == "__main__":
    unittest.main()
