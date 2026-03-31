import unittest

from validate_traffic import sample_to_request


class ValidateTrafficTests(unittest.TestCase):
    def test_explicit_json_sample_is_preserved(self):
        prepared = sample_to_request(
            {
                "name": "json attack",
                "method": "POST",
                "path": "/submit",
                "json": {"input": "<script>alert(1)</script>"},
                "headers": {"Content-Type": "application/json"},
                "label": "xss",
            }
        )
        self.assertEqual(prepared["json"], {"input": "<script>alert(1)</script>"})
        self.assertEqual(prepared["headers"]["Content-Type"], "application/json")
        self.assertEqual(prepared["name"], "json attack")

    def test_explicit_query_params_are_preserved(self):
        prepared = sample_to_request(
            {
                "method": "GET",
                "path": "/search",
                "params": {"q": "admin' OR 1=1 --", "page": "1"},
                "label": "sqli",
            }
        )
        self.assertEqual(prepared["params"]["page"], "1")
        self.assertEqual(prepared["params"]["q"], "admin' OR 1=1 --")

    def test_legacy_payload_shape_still_defaults_by_method(self):
        prepared = sample_to_request(
            {
                "method": "POST",
                "path": "/submit",
                "payload": "hello",
                "label": "valid",
            }
        )
        self.assertEqual(prepared["json"], {"input": "hello"})
        self.assertIsNone(prepared["data"])


if __name__ == "__main__":
    unittest.main()
