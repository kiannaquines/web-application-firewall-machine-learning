#!/usr/bin/env python3

import argparse
import json
from pathlib import Path

from waf_ml.data import build_dataset_bundle
from waf_ml.modeling import train_and_save


def main() -> None:
    parser = argparse.ArgumentParser(description="Train and benchmark the WAF model.")
    parser.add_argument(
        "--artifact",
        default="artifacts/request_predictor_http.joblib",
        help="Output path for the trained model artifact.",
    )
    parser.add_argument(
        "--report",
        default="artifacts/benchmark_report_http.json",
        help="Output path for the benchmark report JSON.",
    )
    parser.add_argument(
        "--representation",
        default="http",
        choices=("http", "payload"),
        help="Training representation to use for model inputs.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress debug messages and only print the final report.",
    )
    args = parser.parse_args()

    verbose = not args.quiet
    if verbose:
        print("[train] building dataset bundle", flush=True)
    bundle = build_dataset_bundle(representation=args.representation)
    if verbose:
        print(
            "[train] development={development_rows} final_test={final_test_rows} challenge={challenge_rows}".format(
                **bundle.summary
            ),
            flush=True,
        )
        print(
            f"[train] development class counts: {bundle.summary['development_class_counts']}",
            flush=True,
        )
        print(
            f"[train] final test class counts: {bundle.summary['final_test_class_counts']}",
            flush=True,
        )
    report = train_and_save(
        bundle, Path(args.artifact), Path(args.report), verbose=verbose
    )
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
