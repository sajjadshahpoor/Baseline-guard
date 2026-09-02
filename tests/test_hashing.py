import hashlib
import tempfile
import unittest
from pathlib import Path

from baselineguard.hashing import canonical_json_bytes, hash_bytes, hash_file


class HashFileTests(unittest.TestCase):
    def test_matches_hashlib_directly(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.txt"
            path.write_bytes(b"the quick brown fox")
            expected = hashlib.sha256(b"the quick brown fox").hexdigest()
            self.assertEqual(hash_file(path), expected)

    def test_large_file_chunked_matches_single_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "big.bin"
            data = b"x" * (3 * 1024 * 1024 + 17)  # spans multiple chunks
            path.write_bytes(data)
            self.assertEqual(hash_file(path), hashlib.sha256(data).hexdigest())

    def test_different_content_different_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            a = Path(tmp) / "a.txt"
            b = Path(tmp) / "b.txt"
            a.write_bytes(b"one")
            b.write_bytes(b"two")
            self.assertNotEqual(hash_file(a), hash_file(b))


class HashBytesTests(unittest.TestCase):
    def test_matches_hashlib(self):
        data = b"ssh-ed25519 AAAA... user@host"
        self.assertEqual(hash_bytes(data), hashlib.sha256(data).hexdigest())


class CanonicalJsonTests(unittest.TestCase):
    def test_key_order_does_not_matter(self):
        a = {"b": 1, "a": 2}
        b = {"a": 2, "b": 1}
        self.assertEqual(canonical_json_bytes(a), canonical_json_bytes(b))

    def test_different_values_differ(self):
        self.assertNotEqual(canonical_json_bytes({"a": 1}), canonical_json_bytes({"a": 2}))


if __name__ == "__main__":
    unittest.main()
