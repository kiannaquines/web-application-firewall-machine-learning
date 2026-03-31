import tempfile
import unittest
from pathlib import Path

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer

from waf_ml.detector import WAFDetector, WAFModelArtifact
from waf_ml.preprocessing import combine_raw_and_normalized


class DetectorTests(unittest.TestCase):
    def test_detector_returns_rich_results(self):
        pipeline = Pipeline(
            steps=[
                ("normalize", FunctionTransformer(combine_raw_and_normalized, validate=False)),
                ("tfidf", TfidfVectorizer(analyzer="char", ngram_range=(1, 2))),
                ("classifier", LogisticRegression(max_iter=500)),
            ]
        )
        X = [
            "username=alice&note=hello",
            "username=admin' OR 1=1 --",
            "<script>alert(1)</script>",
            "file=../../etc/passwd",
        ]
        y = ["valid", "sqli", "xss", "path-traversal"]
        pipeline.fit(X, y)
        artifact = WAFModelArtifact(
            pipeline=pipeline,
            classes=list(pipeline.named_steps["classifier"].classes_),
            block_threshold=0.55,
            allow_threshold=0.55,
            metadata={"selected_model": "test"},
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            artifact_path = Path(tmpdir) / "artifact.joblib"
            joblib.dump(artifact, artifact_path)
            detector = WAFDetector(str(artifact_path))
            result = detector.predict("username=admin' OR 1=1 --")[0]

        self.assertIn("normalized_payload", result)
        self.assertIn("predicted_class", result)
        self.assertIn("confidence", result)
        self.assertIn(result["action"], {"allow", "block", "review"})


if __name__ == "__main__":
    unittest.main()
