# PyTorch WAF

This folder contains a separate PyTorch implementation for the WAF model.
It does not replace or modify the existing sklearn pipeline in `waf_ml/`.

## What is included

- `data.py`: builds a char-level dataset from the existing `waf_ml.data` HTTP representation
- `model.py`: char-CNN classifier for request text
- `train.py`: training entrypoint for CPU or GPU
- `predict.py`: local prediction helper for `.pt` artifacts
- `artifact.py`: serialized artifact container

## Install

Use a separate requirements file so the existing setup stays untouched.

```bash
pip install -r requirements-pytorch.txt
```

## Train locally or in Colab

```bash
python -m pytorch_waf.train \
  --artifact artifacts/request_predictor_torch.pt \
  --report artifacts/benchmark_report_torch.json \
  --representation http \
  --epochs 5 \
  --progress-updates 10
```

Device priority is:

1. `mps` on macOS / Apple Silicon
2. `cuda`
3. `cpu`

Use `--cpu` to force CPU.
Use `--progress-updates` to control how many batch progress lines are printed per epoch.

## Predict

```bash
python -m pytorch_waf.predict \
  artifacts/request_predictor_torch.pt \
  '{"method":"GET","path":"/search","query":{"q":"admin'\'' OR 1=1 --"}}'
```

## Colab quick start

```python
%cd /content/web-application-firewall-machine-learning
!pip install -r requirements-pytorch.txt
!python -m pytorch_waf.train --artifact artifacts/request_predictor_torch.pt --report artifacts/benchmark_report_torch.json --representation http --epochs 5
```
