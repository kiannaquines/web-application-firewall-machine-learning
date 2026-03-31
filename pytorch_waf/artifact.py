from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class TorchWAFArtifact:
    model_state: Dict[str, object]
    vocabulary: Dict[str, int]
    classes: List[str]
    config: Dict[str, object]
    block_threshold: float = 0.70
    allow_threshold: float = 0.80
    metadata: Dict[str, object] = field(default_factory=dict)
