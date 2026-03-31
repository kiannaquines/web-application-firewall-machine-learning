from dataclasses import dataclass
from typing import Dict, Iterable, List, Sequence

import torch
from torch.utils.data import Dataset

from waf_ml.data import DatasetBundle, Record, build_dataset_bundle


PAD_TOKEN = "<pad>"
UNK_TOKEN = "<unk>"


@dataclass(frozen=True)
class TorchDatasetBundle:
    development: List[Record]
    final_test: List[Record]
    runtime_challenge: List[Record]
    classes: List[str]
    vocabulary: Dict[str, int]
    summary: Dict[str, object]


def build_char_vocabulary(
    records: Sequence[Record], min_frequency: int = 1, max_size: int = 256
) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for record in records:
        for char in record.pattern:
            counts[char] = counts.get(char, 0) + 1

    ordered = sorted(
        (item for item in counts.items() if item[1] >= min_frequency),
        key=lambda item: (-item[1], item[0]),
    )
    vocabulary = {PAD_TOKEN: 0, UNK_TOKEN: 1}
    for char, _ in ordered:
        if len(vocabulary) >= max_size:
            break
        vocabulary[char] = len(vocabulary)
    return vocabulary


def encode_text(text: str, vocabulary: Dict[str, int], max_length: int) -> List[int]:
    tokens = [vocabulary.get(char, vocabulary[UNK_TOKEN]) for char in text[:max_length]]
    if len(tokens) < max_length:
        tokens.extend([vocabulary[PAD_TOKEN]] * (max_length - len(tokens)))
    return tokens


class HTTPRequestDataset(Dataset):
    def __init__(
        self,
        records: Sequence[Record],
        *,
        vocabulary: Dict[str, int],
        classes: Sequence[str],
        max_length: int,
    ):
        self.records = list(records)
        self.vocabulary = vocabulary
        self.class_to_index = {label: index for index, label in enumerate(classes)}
        self.max_length = max_length

    def __len__(self) -> int:
        return len(self.records)

    def __getitem__(self, index: int) -> Dict[str, torch.Tensor]:
        record = self.records[index]
        encoded = encode_text(record.pattern, self.vocabulary, self.max_length)
        return {
            "input_ids": torch.tensor(encoded, dtype=torch.long),
            "label": torch.tensor(self.class_to_index[record.label], dtype=torch.long),
            "weight": torch.tensor(record.weight, dtype=torch.float32),
        }


def build_torch_bundle(
    *,
    representation: str = "http",
    max_vocab_size: int = 256,
    min_frequency: int = 1,
) -> TorchDatasetBundle:
    bundle: DatasetBundle = build_dataset_bundle(representation=representation)
    classes = sorted({record.label for record in bundle.development + bundle.final_test})
    vocabulary = build_char_vocabulary(
        list(bundle.development) + list(bundle.final_test),
        min_frequency=min_frequency,
        max_size=max_vocab_size,
    )
    return TorchDatasetBundle(
        development=bundle.development,
        final_test=bundle.final_test,
        runtime_challenge=bundle.runtime_challenge,
        classes=classes,
        vocabulary=vocabulary,
        summary=dict(bundle.summary),
    )
