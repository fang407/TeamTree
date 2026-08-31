#!/usr/bin/env python3
"""Train the local secret-confidence logistic model from CredData.

The script deliberately never prints, writes, or exports labelled credential
values. Its only output is aggregate metrics and the numeric model parameters
that can be embedded in safety-middleware.ts.
"""

from __future__ import annotations

import argparse
import binascii
import csv
import hashlib
import json
import math
import os
import re
import zlib
from collections import Counter
from pathlib import Path


FEATURES = (
    "entropy",
    "length",
    "mixed_classes",
    "known_secret_prefix",
    "uuid",
    "hex_digest",
    "ordinary_base64",
)
HIGH_ENTROPY_CANDIDATE = re.compile(r"^[A-Za-z0-9_+/=-]{20,160}$")


def entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    return -sum((count / len(value)) * math.log2(count / len(value)) for count in counts.values())


def is_uuid(value: str) -> bool:
    parts = value.lower().split("-")
    return (
        len(parts) == 5
        and [len(part) for part in parts] == [8, 4, 4, 4, 12]
        and all(all(char in "0123456789abcdef" for char in part) for part in parts)
        and parts[2][:1] in {"1", "2", "3", "4", "5"}
        and parts[3][:1] in {"8", "9", "a", "b"}
    )


def is_hex_digest(value: str) -> bool:
    return len(value) in {32, 40, 64} and all(char in "0123456789abcdefABCDEF" for char in value)


def is_ordinary_base64(value: str) -> bool:
    if len(value) < 24 or len(value) % 4 != 0:
        return False
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
    return all(char in alphabet for char in value) and value.rstrip("=").find("=") == -1


def feature_vector(value: str) -> list[float]:
    compact = "".join(char for char in value if not char.isspace() and char != "-")
    return [
        min(entropy(compact), 6.0) / 6.0,
        min(len(compact), 128) / 128.0,
        float(any(char.islower() for char in compact) and any(char.isupper() for char in compact) and any(char.isdigit() for char in compact)),
        float(compact.lower().startswith(("sk", "ghp", "github_pat", "akia", "xoxb", "xoxa", "xoxp", "xoxr", "xoxs"))),
        float(is_uuid(value)),
        float(is_hex_digest(compact)),
        float(is_ordinary_base64(compact)),
    ]


def sigmoid(value: float) -> float:
    value = max(-35.0, min(35.0, value))
    return 1.0 / (1.0 + math.exp(-value))


def split_for_validation(identifier: str) -> bool:
    return int(hashlib.sha256(identifier.encode()).hexdigest()[:8], 16) % 5 == 0


def examples(creddata_dir: Path, checkout_dir: Path | None):
    sources: dict[str, dict[str, Path]] = {}
    if checkout_dir:
        snapshot = json.loads((creddata_dir / "snapshot.json").read_text(encoding="utf-8"))
        for repo_id in snapshot:
            raw_repo = checkout_dir / repo_id
            if not raw_repo.is_dir():
                continue
            meta_id = f"{zlib.crc32(binascii.unhexlify(repo_id)) & 0xffffffff:08x}"
            source_by_file_id: dict[str, Path] = {}
            for root, directories, filenames in os.walk(raw_repo):
                if ".git" in directories:
                    directories.remove(".git")
                for filename in filenames:
                    source = Path(root) / filename
                    relative = source.relative_to(raw_repo).as_posix()
                    file_id = hashlib.sha256(relative.encode()).hexdigest()[:8]
                    source_by_file_id[file_id] = source
            sources[meta_id] = source_by_file_id

    for meta_path in sorted((creddata_dir / "meta").glob("*.csv")):
        with meta_path.open(newline="", encoding="utf-8") as handle:
            for row in csv.DictReader(handle):
                try:
                    line_start = int(row["LineStart"])
                    line_end = int(row["LineEnd"])
                    value_start = int(row["ValueStart"])
                    value_end = int(row["ValueEnd"])
                except (KeyError, TypeError, ValueError):
                    continue
                if line_start != line_end or value_start < 0 or value_end <= value_start:
                    continue
                if checkout_dir:
                    source = sources.get(meta_path.stem, {}).get(row["FileID"])
                    if source is None:
                        continue
                else:
                    source = creddata_dir / row["FilePath"]
                try:
                    with source.open("r", encoding="utf-8", errors="replace") as data_file:
                        for current_line, line in enumerate(data_file, start=1):
                            if current_line == line_start:
                                value = line[value_start:value_end].strip()
                                break
                        else:
                            continue
                except OSError:
                    continue
                if not HIGH_ENTROPY_CANDIDATE.fullmatch(value):
                    continue
                label = 1 if row.get("GroundTruth") == "T" else 0
                yield row["Id"], feature_vector(value), label


def train(train_rows: list[tuple[list[float], int]], epochs: int, learning_rate: float, l2: float):
    positives = sum(label for _, label in train_rows)
    negatives = len(train_rows) - positives
    if not positives or not negatives:
        raise RuntimeError("training data must contain both positive and negative labels")

    positive_weight = len(train_rows) / (2 * positives)
    negative_weight = len(train_rows) / (2 * negatives)
    weights = [0.0] * len(FEATURES)
    bias = 0.0
    for epoch in range(epochs):
        gradient = [0.0] * len(FEATURES)
        bias_gradient = 0.0
        for vector, label in train_rows:
            prediction = sigmoid(bias + sum(weight * feature for weight, feature in zip(weights, vector)))
            error = prediction - label
            sample_weight = positive_weight if label else negative_weight
            for index, feature in enumerate(vector):
                gradient[index] += sample_weight * error * feature
            bias_gradient += sample_weight * error
        step = learning_rate / len(train_rows)
        for index in range(len(weights)):
            weights[index] -= step * (gradient[index] + l2 * weights[index])
        bias -= step * bias_gradient
        learning_rate *= 0.985
    return bias, weights


def metrics(rows: list[tuple[list[float], int]], bias: float, weights: list[float]):
    true_positive = false_positive = false_negative = 0
    for vector, label in rows:
        prediction = sigmoid(bias + sum(weight * feature for weight, feature in zip(weights, vector))) >= 0.5
        if prediction and label:
            true_positive += 1
        elif prediction:
            false_positive += 1
        elif label:
            false_negative += 1
    precision = true_positive / max(1, true_positive + false_positive)
    recall = true_positive / max(1, true_positive + false_negative)
    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(2 * precision * recall / max(1e-12, precision + recall), 4),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--creddata-dir", type=Path, required=True)
    parser.add_argument(
        "--checkout-dir",
        type=Path,
        help="Optional CredData tmp directory; trains from successfully downloaded repositories.",
    )
    parser.add_argument("--epochs", type=int, default=180)
    parser.add_argument("--learning-rate", type=float, default=0.8)
    parser.add_argument("--l2", type=float, default=0.01)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    rows = list(examples(args.creddata_dir, args.checkout_dir))
    train_rows = [(vector, label) for identifier, vector, label in rows if not split_for_validation(identifier)]
    validation_rows = [(vector, label) for identifier, vector, label in rows if split_for_validation(identifier)]
    bias, weights = train(train_rows, args.epochs, args.learning_rate, args.l2)
    report = {
        "dataset": "CredData",
        "features": FEATURES,
        "bias": round(bias, 8),
        "weights": {name: round(weight, 8) for name, weight in zip(FEATURES, weights)},
        "samples": {"train": len(train_rows), "validation": len(validation_rows)},
        "source": "partial CredData checkouts" if args.checkout_dir else "CredData data directory",
        "validation": metrics(validation_rows, bias, weights),
    }
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: report[key] for key in ("samples", "validation")}, indent=2))


if __name__ == "__main__":
    main()
