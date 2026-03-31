#!/usr/bin/env python3

import argparse
import json
from typing import Any, Dict, Iterable, List, Optional

import torch

from pytorch_waf.artifact import TorchWAFArtifact
from pytorch_waf.data import encode_text
from pytorch_waf.model import CharCNNClassifier, CharCNNConfig, predict_probabilities
from pytorch_waf.train import select_device
from waf_ml.preprocessing import normalize_payload


class TorchWAFDetector:
    def __init__(self, artifact_path: str, *, device: Optional[str] = None):
        self.artifact: TorchWAFArtifact = torch.load(artifact_path, map_location="cpu")
        config = CharCNNConfig(**self.artifact.config)
        self.model = CharCNNClassifier(config)
        self.model.load_state_dict(self.artifact.model_state)
        self.model.eval()
        self.classes = list(self.artifact.classes)
        self.vocabulary = dict(self.artifact.vocabulary)
        self.block_threshold = self.artifact.block_threshold
        self.allow_threshold = self.artifact.allow_threshold
        self.device = torch.device(device) if device else select_device()
        self.model.to(self.device)
        self.max_length = int(self.artifact.config.get("max_length", 512))

    def _action_for(self, label: str, confidence: float) -> str:
        if label == "valid":
            return "allow" if confidence >= self.allow_threshold else "review"
        return "block" if confidence >= self.block_threshold else "review"

    def predict(self, payloads: Iterable[str]) -> List[Dict[str, Any]]:
        rows = list(payloads)
        encoded = [
            encode_text(row, self.vocabulary, self.max_length)
            for row in rows
        ]
        tensor = torch.tensor(encoded, dtype=torch.long, device=self.device)
        with torch.no_grad():
            probs = predict_probabilities(self.model, tensor).cpu()
        predictions = probs.argmax(dim=1).tolist()
        results: List[Dict[str, Any]] = []
        for raw, index, prob_row in zip(rows, predictions, probs.tolist()):
            normalized = normalize_payload(raw)
            predicted_class = self.classes[index]
            confidence = float(max(prob_row))
            scores = {
                label: float(score) for label, score in zip(self.classes, prob_row)
            }
            results.append(
                {
                    "raw_payload": normalized.raw,
                    "normalized_payload": normalized.normalized,
                    "predicted_class": predicted_class,
                    "confidence": confidence,
                    "action": self._action_for(predicted_class, confidence),
                    "scores": scores,
                }
            )
        return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Run predictions with a torch WAF model.")
    parser.add_argument("artifact")
    parser.add_argument("payload", nargs="+")
    args = parser.parse_args()
    detector = TorchWAFDetector(args.artifact)
    print(json.dumps(detector.predict(args.payload), indent=2))


if __name__ == "__main__":
    main()
