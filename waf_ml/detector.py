from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Sequence

import joblib
import numpy as np

from .preprocessing import normalize_payload


@dataclass
class WAFModelArtifact:
    pipeline: Any
    classes: Sequence[str]
    block_threshold: float = 0.70
    allow_threshold: float = 0.80
    metadata: Dict[str, Any] = field(default_factory=dict)


class WAFDetector:
    def __init__(self, artifact_path: str = "./artifacts/request_predictor_v2.joblib"):
        self.artifact: WAFModelArtifact = joblib.load(artifact_path)
        self.pipeline = self.artifact.pipeline
        self.classes = list(self.artifact.classes)
        self.block_threshold = self.artifact.block_threshold
        self.allow_threshold = self.artifact.allow_threshold
        self.metadata = dict(self.artifact.metadata)

    def parse_payload(self, payload: Any) -> List[str]:
        if isinstance(payload, str):
            return [payload]
        if isinstance(payload, list):
            return [str(item) for item in payload]
        raise ValueError("Payload must be a string or a list of strings.")

    def _predict_proba(self, payloads: Iterable[str]) -> np.ndarray:
        if hasattr(self.pipeline, "predict_proba"):
            return self.pipeline.predict_proba(payloads)
        raise ValueError("The loaded pipeline does not support probability output.")

    def _action_for(self, label: str, confidence: float) -> str:
        if label == "valid":
            return "allow" if confidence >= self.allow_threshold else "review"
        return "block" if confidence >= self.block_threshold else "review"

    def predict(self, payload: Any) -> List[Dict[str, Any]]:
        entries = self.parse_payload(payload)
        probabilities = self._predict_proba(entries)
        predictions = self.pipeline.predict(entries)

        results: List[Dict[str, Any]] = []
        for raw, prediction, row in zip(entries, predictions, probabilities):
            normalized = normalize_payload(raw)
            confidence = float(np.max(row))
            class_scores = {
                class_name: float(score) for class_name, score in zip(self.classes, row)
            }
            results.append(
                {
                    "raw_payload": normalized.raw,
                    "normalized_payload": normalized.normalized,
                    "model_input": normalized.combined,
                    "predicted_class": str(prediction),
                    "confidence": confidence,
                    "action": self._action_for(str(prediction), confidence),
                    "scores": class_scores,
                }
            )
        return results
