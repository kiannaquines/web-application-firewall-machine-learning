import unittest

from waf_ml.runtime import canonicalize_request


class RuntimeCanonicalizationTests(unittest.TestCase):
    def test_query_only_request_is_canonicalized(self):
        payload = canonicalize_request(
            method="GET",
            path="/search",
            query={"q": "hello", "page": "1"},
            headers={"User-Agent": "tester"},
        )
        self.assertIn('"method":"GET"', payload)
        self.assertIn('"path":"/search"', payload)
        self.assertIn('"query":{"page":"1","q":"hello"}', payload)
        self.assertIn('"headers":{"user-agent":"tester"}', payload)

    def test_form_request_keeps_fields(self):
        payload = canonicalize_request(
            method="POST",
            path="/submit",
            form={"username": "alice", "note": "hi"},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        self.assertIn('"form":{"note":"hi","username":"alice"}', payload)
        self.assertIn('"content-type":"application/x-www-form-urlencoded"', payload)

    def test_json_request_is_stable(self):
        payload = canonicalize_request(
            method="POST",
            path="/submit",
            json_body={"note": "hello", "meta": {"b": 2, "a": 1}},
        )
        self.assertIn('"json":{"meta":{"a":"1","b":"2"},"note":"hello"}', payload)

    def test_sensitive_values_can_be_redacted(self):
        payload = canonicalize_request(
            method="POST",
            path="/submit",
            form={"password": "super-secret", "username": "alice"},
            redact_sensitive=True,
        )
        self.assertIn('"password":"<redacted>"', payload)
        self.assertIn('"username":"alice"', payload)


if __name__ == "__main__":
    unittest.main()
