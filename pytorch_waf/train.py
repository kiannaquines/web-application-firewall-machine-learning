#!/usr/bin/env python3

import argparse
import json
import math
from pathlib import Path
from typing import Dict, List

import torch
from sklearn.metrics import classification_report, f1_score, recall_score
from torch import nn
from torch.optim import AdamW
from torch.utils.data import DataLoader

from .artifact import TorchWAFArtifact
from .data import HTTPRequestDataset, TorchDatasetBundle, build_torch_bundle
from .model import CharCNNClassifier, CharCNNConfig, predict_probabilities


def select_device(force_cpu: bool = False) -> torch.device:
    if force_cpu:
        return torch.device("cpu")
    if hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
        return torch.device("mps")
    if torch.cuda.is_available():
        return torch.device("cuda")
    return torch.device("cpu")


def evaluate_model(
    model: nn.Module,
    dataloader: DataLoader,
    *,
    classes: List[str],
    device: torch.device,
) -> Dict[str, object]:
    model.eval()
    all_labels: List[int] = []
    all_predictions: List[int] = []
    with torch.no_grad():
        for batch in dataloader:
            input_ids = batch["input_ids"].to(device)
            labels = batch["label"].to(device)
            probs = predict_probabilities(model, input_ids)
            predictions = probs.argmax(dim=1)
            all_labels.extend(labels.cpu().tolist())
            all_predictions.extend(predictions.cpu().tolist())
    return {
        "macro_f1": float(f1_score(all_labels, all_predictions, average="macro")),
        "macro_recall": float(
            recall_score(all_labels, all_predictions, average="macro", zero_division=0)
        ),
        "classification_report": classification_report(
            all_labels,
            all_predictions,
            labels=list(range(len(classes))),
            target_names=classes,
            output_dict=True,
            zero_division=0,
        ),
    }


def train_one_epoch(
    model: nn.Module,
    dataloader: DataLoader,
    *,
    optimizer: AdamW,
    loss_fn: nn.Module,
    device: torch.device,
    epoch: int,
    total_epochs: int,
    log_every: int,
    quiet: bool,
) -> float:
    model.train()
    running_loss = 0.0
    sample_count = 0
    total_batches = max(len(dataloader), 1)
    for batch_index, batch in enumerate(dataloader, start=1):
        input_ids = batch["input_ids"].to(device)
        labels = batch["label"].to(device)
        weights = batch["weight"].to(device)

        optimizer.zero_grad()
        logits = model(input_ids)
        loss = loss_fn(logits, labels)
        weighted_loss = (loss * weights).mean()
        weighted_loss.backward()
        optimizer.step()

        batch_size = labels.size(0)
        running_loss += float(weighted_loss.item()) * batch_size
        sample_count += batch_size
        if not quiet and (
            batch_index == 1
            or batch_index == total_batches
            or batch_index % max(log_every, 1) == 0
        ):
            avg_loss = running_loss / max(sample_count, 1)
            print(
                "[epoch {epoch}/{total_epochs}] batch {batch}/{total_batches} avg_loss={avg_loss:.6f}".format(
                    epoch=epoch,
                    total_epochs=total_epochs,
                    batch=batch_index,
                    total_batches=total_batches,
                    avg_loss=avg_loss,
                ),
                flush=True,
            )
    return running_loss / max(sample_count, 1)


def build_loaders(
    bundle: TorchDatasetBundle,
    *,
    max_length: int,
    batch_size: int,
) -> Dict[str, DataLoader]:
    common = {
        "vocabulary": bundle.vocabulary,
        "classes": bundle.classes,
        "max_length": max_length,
    }
    development = HTTPRequestDataset(bundle.development, **common)
    final_test = HTTPRequestDataset(bundle.final_test, **common)
    runtime_challenge = HTTPRequestDataset(bundle.runtime_challenge, **common)
    return {
        "development": DataLoader(development, batch_size=batch_size, shuffle=True),
        "final_test": DataLoader(final_test, batch_size=batch_size, shuffle=False),
        "runtime_challenge": DataLoader(
            runtime_challenge, batch_size=batch_size, shuffle=False
        ),
    }


def train_model(args: argparse.Namespace) -> Dict[str, object]:
    device = select_device(force_cpu=args.cpu)
    if not args.quiet:
        print(f"[startup] selected device: {device}", flush=True)
        print(
            f"[startup] loading dataset representation={args.representation}",
            flush=True,
        )
    bundle = build_torch_bundle(
        representation=args.representation,
        max_vocab_size=args.max_vocab_size,
        min_frequency=args.min_frequency,
    )
    if not args.quiet:
        print(
            "[startup] dataset summary development={development} test={test} runtime_challenge={runtime} classes={classes} vocab_size={vocab}".format(
                development=len(bundle.development),
                test=len(bundle.final_test),
                runtime=len(bundle.runtime_challenge),
                classes=len(bundle.classes),
                vocab=len(bundle.vocabulary),
            ),
            flush=True,
        )
        print(
            f"[startup] building dataloaders batch_size={args.batch_size} max_length={args.max_length}",
            flush=True,
        )
    loaders = build_loaders(bundle, max_length=args.max_length, batch_size=args.batch_size)
    if not args.quiet:
        print(
            "[startup] dataloader batches development={development} test={test} runtime_challenge={runtime}".format(
                development=len(loaders["development"]),
                test=len(loaders["final_test"]),
                runtime=len(loaders["runtime_challenge"]),
            ),
            flush=True,
        )

    config = CharCNNConfig(
        vocab_size=len(bundle.vocabulary),
        num_classes=len(bundle.classes),
        embedding_dim=args.embedding_dim,
        channels=args.channels,
        kernel_sizes=tuple(args.kernel_sizes),
        dropout=args.dropout,
    )
    model = CharCNNClassifier(config).to(device)
    optimizer = AdamW(model.parameters(), lr=args.learning_rate, weight_decay=args.weight_decay)
    loss_fn = nn.CrossEntropyLoss(reduction="none")
    log_every = max(1, math.ceil(len(loaders["development"]) / max(args.progress_updates, 1)))
    if not args.quiet:
        print(
            "[startup] model ready embedding_dim={embedding} channels={channels} kernels={kernels} log_every={log_every}".format(
                embedding=args.embedding_dim,
                channels=args.channels,
                kernels=list(args.kernel_sizes),
                log_every=log_every,
            ),
            flush=True,
        )

    history: List[Dict[str, object]] = []
    for epoch in range(1, args.epochs + 1):
        if not args.quiet:
            print(f"[epoch {epoch}/{args.epochs}] training", flush=True)
        train_loss = train_one_epoch(
            model,
            loaders["development"],
            optimizer=optimizer,
            loss_fn=loss_fn,
            device=device,
            epoch=epoch,
            total_epochs=args.epochs,
            log_every=log_every,
            quiet=args.quiet,
        )
        if not args.quiet:
            print(f"[epoch {epoch}/{args.epochs}] evaluating final test", flush=True)
        test_metrics = evaluate_model(
            model, loaders["final_test"], classes=bundle.classes, device=device
        )
        if not args.quiet:
            print(f"[epoch {epoch}/{args.epochs}] evaluating runtime challenge", flush=True)
        runtime_metrics = evaluate_model(
            model, loaders["runtime_challenge"], classes=bundle.classes, device=device
        )
        epoch_metrics = {
            "epoch": epoch,
            "train_loss": train_loss,
            "test_macro_f1": test_metrics["macro_f1"],
            "runtime_challenge_macro_recall": runtime_metrics["macro_recall"],
        }
        history.append(epoch_metrics)
        if not args.quiet:
            print(json.dumps(epoch_metrics), flush=True)

    final_test = evaluate_model(
        model, loaders["final_test"], classes=bundle.classes, device=device
    )
    runtime_challenge = evaluate_model(
        model, loaders["runtime_challenge"], classes=bundle.classes, device=device
    )

    artifact = TorchWAFArtifact(
        model_state=model.state_dict(),
        vocabulary=bundle.vocabulary,
        classes=bundle.classes,
        config=config.to_dict(),
        block_threshold=args.block_threshold,
        allow_threshold=args.allow_threshold,
        metadata={
            "representation": args.representation,
            "device": str(device),
            "dataset_summary": bundle.summary,
            "history": history,
        },
    )
    artifact_path = Path(args.artifact)
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    torch.save(artifact, artifact_path)

    report = {
        "artifact": str(artifact_path),
        "representation": args.representation,
        "dataset_summary": bundle.summary,
        "history": history,
        "final_test": final_test,
        "runtime_challenge": runtime_challenge,
    }
    report_path = Path(args.report)
    report_path.write_text(json.dumps(report, indent=2))
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Train a PyTorch char-CNN WAF model on HTTP request strings."
    )
    parser.add_argument(
        "--artifact",
        default="artifacts/request_predictor_torch.pt",
        help="Path to write the trained torch artifact.",
    )
    parser.add_argument(
        "--report",
        default="artifacts/benchmark_report_torch.json",
        help="Path to write the training report.",
    )
    parser.add_argument("--representation", choices=("http", "payload"), default="http")
    parser.add_argument("--epochs", type=int, default=5)
    parser.add_argument("--batch-size", type=int, default=256)
    parser.add_argument("--max-length", type=int, default=512)
    parser.add_argument("--max-vocab-size", type=int, default=256)
    parser.add_argument("--min-frequency", type=int, default=1)
    parser.add_argument("--embedding-dim", type=int, default=64)
    parser.add_argument("--channels", type=int, default=128)
    parser.add_argument("--kernel-sizes", nargs="+", type=int, default=[3, 5, 7])
    parser.add_argument("--dropout", type=float, default=0.2)
    parser.add_argument("--learning-rate", type=float, default=3e-4)
    parser.add_argument("--weight-decay", type=float, default=1e-4)
    parser.add_argument("--block-threshold", type=float, default=0.70)
    parser.add_argument("--allow-threshold", type=float, default=0.80)
    parser.add_argument("--cpu", action="store_true", help="Force CPU even if CUDA exists.")
    parser.add_argument(
        "--progress-updates",
        type=int,
        default=10,
        help="How many progress updates to print during each training epoch.",
    )
    parser.add_argument("--quiet", action="store_true")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    report = train_model(args)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
