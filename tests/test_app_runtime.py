import os
import tempfile
import unittest
from pathlib import Path

import numpy as np
import joblib

from app import create_app
from waf_ml.detector import WAFModelArtifact


class KeywordPipeline:
    classes_ = np.array(["path-traversal", "sqli", "valid", "xss"])

    def fit(self, X, y):
        return self

    def predict(self, X):
        return np.array([self._label(value) for value in X])

    def predict_proba(self, X):
        rows = []
        for value in X:
            label = self._label(value)
            if label == "valid":
                rows.append([0.03, 0.03, 0.91, 0.03])
            elif label == "sqli":
                rows.append([0.03, 0.91, 0.03, 0.03])
            elif label == "xss":
                rows.append([0.03, 0.03, 0.03, 0.91])
            else:
                rows.append([0.91, 0.03, 0.03, 0.03])
        return np.array(rows)

    def _label(self, value):
        lowered = value.lower()
        if "../" in lowered or "/etc/passwd" in lowered:
            return "path-traversal"
        if "script" in lowered:
            return "xss"
        if " or " in lowered or "union" in lowered or "drop table" in lowered:
            return "sqli"
        return "valid"


def make_test_artifact(artifact_path: Path) -> None:
    pipeline = KeywordPipeline()
    artifact = WAFModelArtifact(
        pipeline=pipeline,
        classes=list(pipeline.classes_),
        block_threshold=0.45,
        allow_threshold=0.45,
        metadata={"selected_model": "test"},
    )
    joblib.dump(artifact, artifact_path)


class AppRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.artifact_path = Path(self.tmpdir.name) / "artifact.joblib"
        make_test_artifact(self.artifact_path)
        os.environ["MODEL_ARTIFACT_PATH"] = str(self.artifact_path)
        os.environ["WAF_BLOCK_THRESHOLD"] = "0.45"
        os.environ["WAF_ALLOW_THRESHOLD"] = "0.45"
        self.app = create_app()
        self.client = self.app.test_client()

    def tearDown(self) -> None:
        self.tmpdir.cleanup()
        os.environ.pop("MODEL_ARTIFACT_PATH", None)
        os.environ.pop("WAF_BLOCK_THRESHOLD", None)
        os.environ.pop("WAF_ALLOW_THRESHOLD", None)

    def test_healthz_reports_loaded_model(self):
        response = self.client.get("/healthz")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["model_loaded"])

    def test_benign_query_is_allowed(self):
        response = self.client.get("/search?q=hello")
        body = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(body["status"], "accepted")
        self.assertIn(body["waf"]["action"], {"allow", "review"})

    def test_malicious_body_is_blocked_by_app_layer(self):
        response = self.client.post("/submit", json={"input": "admin' OR 1=1 --"})
        body = response.get_json()
        self.assertEqual(response.status_code, 403)
        self.assertEqual(body["error"], "request_blocked")
        self.assertEqual(body["stage"], "application")

    def test_auth_endpoint_blocks_malicious_query(self):
        response = self.client.get(
            "/__waf__/authorize",
            headers={
                "X-WAF-Auth-Request": "1",
                "X-Original-Method": "GET",
                "X-Original-URI": "/search?q=admin%27%20OR%201%3D1%20--",
                "X-Edge-User-Agent": "pytest",
            },
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.headers["X-WAF-Action"], "block")

    def test_auth_endpoint_requires_internal_header(self):
        response = self.client.get("/__waf__/authorize")
        self.assertEqual(response.status_code, 403)


if __name__ == "__main__":
    unittest.main()
