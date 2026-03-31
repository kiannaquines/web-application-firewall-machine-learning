import unittest

from waf_ml.data import Record, deduplicate_records, expand_realistic_valid_samples


class DataPipelineTests(unittest.TestCase):
    def test_deduplicate_records_drops_exact_duplicates(self):
        records = [
            Record(pattern="/api/status", label="valid", source="a"),
            Record(pattern="/api/status", label="valid", source="b"),
            Record(pattern="admin'--", label="sqli", source="c"),
        ]
        deduped = deduplicate_records(records)
        self.assertEqual(len(deduped), 2)

    def test_conflicting_labels_are_removed(self):
        records = [
            Record(pattern="same", label="valid", source="a"),
            Record(pattern="same", label="sqli", source="b"),
        ]
        self.assertEqual(deduplicate_records(records), [])

    def test_valid_routes_are_expanded(self):
        records = [Record(pattern="/api/orders", label="valid", source="seed")]
        expanded = expand_realistic_valid_samples(records, per_route_limit=1)
        self.assertTrue(expanded)
        self.assertTrue(all(record.label == "valid" for record in expanded))


if __name__ == "__main__":
    unittest.main()
