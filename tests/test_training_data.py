import unittest

from waf_ml.data import Record, build_dataset_bundle, record_to_runtime_request


class TrainingDataTests(unittest.TestCase):
    def test_sqli_record_is_wrapped_as_runtime_search_request(self):
        record = Record(pattern="admin' OR 1=1 --", label="sqli", source="test")
        runtime_record = record_to_runtime_request(record)
        self.assertIn('"path":"/search"', runtime_record.pattern)
        self.assertIn('"q":"admin\' or 1=1 --"', runtime_record.pattern.lower())

    def test_xss_record_is_wrapped_as_runtime_submit_request(self):
        record = Record(pattern="<script>alert(1)</script>", label="xss", source="test")
        runtime_record = record_to_runtime_request(record)
        self.assertIn('"path":"/submit"', runtime_record.pattern)
        self.assertIn('"content-type":"application/json"', runtime_record.pattern.lower())

    def test_invalid_representation_raises(self):
        with self.assertRaises(ValueError):
            build_dataset_bundle(representation="unknown")


if __name__ == "__main__":
    unittest.main()
