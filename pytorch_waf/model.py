from dataclasses import asdict, dataclass
from typing import Dict, Iterable, List

import torch
from torch import nn


@dataclass(frozen=True)
class CharCNNConfig:
    vocab_size: int
    num_classes: int
    embedding_dim: int = 64
    channels: int = 128
    kernel_sizes: tuple = (3, 5, 7)
    dropout: float = 0.2
    padding_idx: int = 0

    def to_dict(self) -> Dict[str, object]:
        data = asdict(self)
        data["kernel_sizes"] = list(self.kernel_sizes)
        return data


class CharCNNClassifier(nn.Module):
    def __init__(self, config: CharCNNConfig):
        super().__init__()
        self.config = config
        self.embedding = nn.Embedding(
            config.vocab_size,
            config.embedding_dim,
            padding_idx=config.padding_idx,
        )
        self.convs = nn.ModuleList(
            [
                nn.Conv1d(
                    in_channels=config.embedding_dim,
                    out_channels=config.channels,
                    kernel_size=kernel_size,
                )
                for kernel_size in config.kernel_sizes
            ]
        )
        self.dropout = nn.Dropout(config.dropout)
        self.classifier = nn.Linear(
            config.channels * len(config.kernel_sizes), config.num_classes
        )

    def forward(self, input_ids: torch.Tensor) -> torch.Tensor:
        embedded = self.embedding(input_ids).transpose(1, 2)
        pooled: List[torch.Tensor] = []
        for conv in self.convs:
            activations = torch.relu(conv(embedded))
            pooled.append(torch.max(activations, dim=2).values)
        merged = torch.cat(pooled, dim=1)
        return self.classifier(self.dropout(merged))


def predict_probabilities(model: nn.Module, input_ids: torch.Tensor) -> torch.Tensor:
    logits = model(input_ids)
    return torch.softmax(logits, dim=1)
