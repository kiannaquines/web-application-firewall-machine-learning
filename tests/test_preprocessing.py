import unittest

from waf_ml.preprocessing import normalize_payload, repeated_base64_decode


class PreprocessingTests(unittest.TestCase):
    def test_url_encoded_traversal_is_decoded(self):
        normalized = normalize_payload("file=%2E%2E/%2E%2E/etc/passwd")
        self.assertIn("../..", normalized.normalized)
        self.assertIn("/etc/passwd", normalized.normalized)

    def test_base64_decode_is_bounded(self):
        once = "YWRtaW4nLS0="
        self.assertEqual(repeated_base64_decode(once, max_depth=2), "admin'--")

    def test_invalid_base64_does_not_crash(self):
        normalized = normalize_payload("payload=%%%notbase64%%%")
        self.assertEqual(normalized.normalized, "payload=%%%notbase64%%%")

    def test_raw_and_normalized_are_both_kept(self):
        normalized = normalize_payload("username=Admin&payload=%2Fetc%2Fpasswd")
        self.assertIn("__raw__", normalized.combined)
        self.assertIn("__normalized__", normalized.combined)


if __name__ == "__main__":
    unittest.main()
