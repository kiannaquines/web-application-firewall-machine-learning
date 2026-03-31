import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Sequence, Tuple

import joblib
import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    recall_score,
)
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.preprocessing import FunctionTransformer
from sklearn.svm import LinearSVC

from .data import DatasetBundle, LABELS, Record
from .detector import WAFModelArtifact
from .features import SuspiciousPatternFeatures
from .preprocessing import combine_raw_and_normalized


@dataclass(frozen=True)
class CandidateModel:
    name: str
    pipeline: Pipeline
    classifier_step: str


def candidate_models(random_state: int = 42) -> List[CandidateModel]:
    text_preprocessor = FunctionTransformer(combine_raw_and_normalized, validate=False)
    return [
        CandidateModel(
            name="linear_svc_char_12",
            classifier_step="classifier",
            pipeline=Pipeline(
                steps=[
                    ("text", text_preprocessor),
                    (
                        "tfidf",
                        TfidfVectorizer(
                            analyzer="char", ngram_range=(1, 2), max_features=4096
                        ),
                    ),
                    (
                        "classifier",
                        CalibratedClassifierCV(
                            estimator=LinearSVC(
                                C=1.0,
                                class_weight="balanced",
                                random_state=random_state,
                            ),
                            method="sigmoid",
                            cv=3,
                        ),
                    ),
                ]
            ),
        ),
        CandidateModel(
            name="linear_svc_char_14",
            classifier_step="classifier",
            pipeline=Pipeline(
                steps=[
                    ("text", text_preprocessor),
                    (
                        "tfidf",
                        TfidfVectorizer(
                            analyzer="char", ngram_range=(1, 4), max_features=4096
                        ),
                    ),
                    (
                        "classifier",
                        CalibratedClassifierCV(
                            estimator=LinearSVC(
                                C=1.0,
                                class_weight="balanced",
                                random_state=random_state,
                            ),
                            method="sigmoid",
                            cv=3,
                        ),
                    ),
                ]
            ),
        ),
        CandidateModel(
            name="logistic_char_wb_35",
            classifier_step="classifier",
            pipeline=Pipeline(
                steps=[
                    ("text", text_preprocessor),
                    (
                        "tfidf",
                        TfidfVectorizer(
                            analyzer="char_wb", ngram_range=(3, 5), max_features=4096
                        ),
                    ),
                    (
                        "classifier",
                        LogisticRegression(
                            max_iter=2500,
                            class_weight="balanced",
                            random_state=random_state,
                        ),
                    ),
                ]
            ),
        ),
        CandidateModel(
            name="feature_fusion_logistic",
            classifier_step="classifier",
            pipeline=Pipeline(
                steps=[
                    (
                        "features",
                        FeatureUnion(
                            transformer_list=[
                                (
                                    "text",
                                    Pipeline(
                                        steps=[
                                            ("normalize", text_preprocessor),
                                            (
                                                "tfidf",
                                                TfidfVectorizer(
                                                    analyzer="char",
                                                    ngram_range=(1, 4),
                                                    max_features=8192,
                                                ),
                                            ),
                                        ]
                                    ),
                                ),
                                ("signals", SuspiciousPatternFeatures()),
                            ]
                        ),
                    ),
                    (
                        "classifier",
                        LogisticRegression(
                            max_iter=2500,
                            class_weight="balanced",
                            random_state=random_state,
                        ),
                    ),
                ]
            ),
        ),
    ]


def _split_fields(
    records: Sequence[Record],
) -> Tuple[List[str], List[str], List[float], List[str]]:
    return (
        [record.pattern for record in records],
        [record.label for record in records],
        [record.weight for record in records],
        [record.family for record in records],
    )


def _fit_pipeline(
    candidate: CandidateModel, X: List[str], y: List[str], sample_weight: List[float]
):
    fit_kwargs = {f"{candidate.classifier_step}__sample_weight": sample_weight}
    candidate.pipeline.fit(X, y, **fit_kwargs)
    return candidate.pipeline


def _valid_false_positive_rate(y_true: Sequence[str], y_pred: Sequence[str]) -> float:
    valid_total = sum(1 for label in y_true if label == "valid")
    if not valid_total:
        return 0.0
    false_positive = sum(
        1
        for actual, predicted in zip(y_true, y_pred)
        if actual == "valid" and predicted != "valid"
    )
    return false_positive / valid_total


def _challenge_macro_recall(pipeline: Pipeline, records: Sequence[Record]) -> float:
    if not records:
        return 0.0
    X = [record.pattern for record in records]
    y_true = [record.label for record in records]
    y_pred = pipeline.predict(X)
    return recall_score(y_true, y_pred, average="macro", zero_division=0)


def _classification_report(pipeline: Pipeline, records: Sequence[Record]) -> Dict[str, object]:
    if not records:
        return {}
    X = [record.pattern for record in records]
    y_true = [record.label for record in records]
    y_pred = pipeline.predict(X)
    return classification_report(
        y_true, y_pred, labels=list(LABELS), output_dict=True, zero_division=0
    )


def evaluate_candidate(
    candidate: CandidateModel,
    bundle: DatasetBundle,
    random_state: int = 42,
    verbose: bool = False,
) -> Dict[str, object]:
    X_dev, y_dev, weights_dev, groups_dev = _split_fields(bundle.development)
    cv = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=random_state)
    cv_scores = []
    if verbose:
        print(
            f"[candidate:{candidate.name}] starting cross-validation on {len(X_dev)} development rows",
            flush=True,
        )
    for train_idx, validation_idx in cv.split(X_dev, y_dev, groups_dev):
        fold_number = len(cv_scores) + 1
        train_X = [X_dev[index] for index in train_idx]
        train_y = [y_dev[index] for index in train_idx]
        train_weights = [weights_dev[index] for index in train_idx]
        validation_X = [X_dev[index] for index in validation_idx]
        validation_y = [y_dev[index] for index in validation_idx]
        if verbose:
            print(
                f"[candidate:{candidate.name}] fold {fold_number}/5 train={len(train_X)} validation={len(validation_X)}",
                flush=True,
            )
        pipeline = _fit_pipeline(candidate, train_X, train_y, train_weights)
        predictions = pipeline.predict(validation_X)
        fold_score = f1_score(validation_y, predictions, average="macro")
        cv_scores.append(fold_score)
        if verbose:
            print(
                f"[candidate:{candidate.name}] fold {fold_number}/5 macro_f1={fold_score:.4f}",
                flush=True,
            )

    if verbose:
        print(
            f"[candidate:{candidate.name}] fitting on full development split",
            flush=True,
        )
    pipeline = _fit_pipeline(candidate, X_dev, y_dev, weights_dev)
    X_test, y_test, _, _ = _split_fields(bundle.final_test)
    y_pred = pipeline.predict(X_test)
    report = classification_report(
        y_test, y_pred, labels=list(LABELS), output_dict=True, zero_division=0
    )
    metrics = {
        "name": candidate.name,
        "cv_macro_f1_mean": float(np.mean(cv_scores)),
        "cv_macro_f1_std": float(np.std(cv_scores)),
        "test_macro_f1": float(f1_score(y_test, y_pred, average="macro")),
        "valid_false_positive_rate": _valid_false_positive_rate(y_test, y_pred),
        "challenge_macro_recall": _challenge_macro_recall(pipeline, bundle.challenge),
        "runtime_challenge_macro_recall": _challenge_macro_recall(
            pipeline, bundle.runtime_challenge
        ),
        "classification_report": report,
        "runtime_challenge_report": _classification_report(
            pipeline, bundle.runtime_challenge
        ),
        "confusion_matrix": confusion_matrix(
            y_test, y_pred, labels=list(LABELS)
        ).tolist(),
        "pipeline": pipeline,
    }
    if verbose:
        print(
            "[candidate:{name}] test_macro_f1={f1:.4f} valid_fpr={fpr:.4f} challenge_macro_recall={challenge:.4f} runtime_challenge_macro_recall={runtime:.4f}".format(
                name=candidate.name,
                f1=metrics["test_macro_f1"],
                fpr=metrics["valid_false_positive_rate"],
                challenge=metrics["challenge_macro_recall"],
                runtime=metrics["runtime_challenge_macro_recall"],
            ),
            flush=True,
        )
    return metrics


def choose_best_model(results: Sequence[Dict[str, object]]) -> Dict[str, object]:
    return max(
        results,
        key=lambda item: (
            item["runtime_challenge_macro_recall"],
            item["challenge_macro_recall"],
            item["test_macro_f1"],
            -item["valid_false_positive_rate"],
            item["cv_macro_f1_mean"],
        ),
    )


def _class_order(pipeline: Pipeline) -> List[str]:
    classifier = pipeline.named_steps["classifier"]
    if hasattr(classifier, "classes_"):
        return list(classifier.classes_)
    if (
        hasattr(classifier, "calibrated_classifiers_")
        and classifier.calibrated_classifiers_
    ):
        return list(classifier.calibrated_classifiers_[0].estimator.classes_)
    return list(LABELS)


def train_and_save(
    bundle: DatasetBundle, artifact_path: Path, report_path: Path, verbose: bool = False
) -> Dict[str, object]:
    if verbose:
        print("[train] evaluating candidate models", flush=True)
    results = [
        evaluate_candidate(candidate, bundle, verbose=verbose)
        for candidate in candidate_models()
    ]
    best = choose_best_model(results)
    if verbose:
        print(f"[train] selected model: {best['name']}", flush=True)

    all_train_records = list(bundle.development) + list(bundle.final_test)
    X_all, y_all, weights_all, _ = _split_fields(all_train_records)
    best_pipeline = best["pipeline"]
    if verbose:
        print(
            f"[train] refitting selected model on {len(all_train_records)} rows before serialization",
            flush=True,
        )
    best_pipeline.fit(X_all, y_all, classifier__sample_weight=weights_all)

    artifact = WAFModelArtifact(
        pipeline=best_pipeline,
        classes=_class_order(best_pipeline),
        block_threshold=0.70,
        allow_threshold=0.80,
        metadata={
            "selected_model": best["name"],
            "dataset_summary": bundle.summary,
            "preprocessing": (
                "http_runtime_canonical_request_pipeline"
                if bundle.summary.get("representation") == "http"
                else "shared_raw_plus_normalized_payload_pipeline"
            ),
        },
    )
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(artifact, artifact_path)

    serializable_results = []
    for item in results:
        copy = dict(item)
        copy.pop("pipeline")
        serializable_results.append(copy)
    report = {
        "selected_model": best["name"],
        "dataset_summary": bundle.summary,
        "results": serializable_results,
    }
    report_path.write_text(json.dumps(report, indent=2))
    if verbose:
        print(f"[train] wrote artifact to {artifact_path}", flush=True)
        print(f"[train] wrote report to {report_path}", flush=True)
    return report
