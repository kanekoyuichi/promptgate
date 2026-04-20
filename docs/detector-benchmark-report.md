# Detector Benchmark Report

**Date:** 2026-04-06  
**Branch:** feature/classifier-v1  
**Benchmark:** 200-case evaluation dataset (A:50 / B:50 / C:50 / D:50)

---

## Dataset Structure

| Category | Description | Count | Expected |
|---|---|---|---|
| A | Direct attacks (known keywords, injection phrases) | 50 | attack |
| B | Paraphrase attacks (roleplay, obfuscation, indirect) | 50 | attack |
| C | Safe inputs (normal user queries) | 50 | safe |
| D | FP inducers (benign text with attack-like words) | 50 | safe |

Languages: English and Japanese (25 each per category).

---

## Overall Results

| Detector | Detection (A+B) | Specificity (C+D) | Accuracy | Precision | F1 | Latency |
|---|---|---|---|---|---|---|
| **ClassifierDetector** | **76.0%** | **99.0%** | **87.5%** | **98.7%** | **0.859** | 165 ms |
| e5-large (embedding) | 55.0% | 100.0% | 77.5% | 100.0% | 0.710 | 878 ms |
| mpnet-base-v2 (embedding) | 37.0% | 100.0% | 68.5% | 100.0% | 0.540 | 236 ms |
| MiniLM-L12-v2 (embedding) | 33.0% | 100.0% | 66.5% | 100.0% | 0.497 | 75 ms |
| rule only (baseline) | 20.0% | 100.0% | 60.0% | 100.0% | 0.333 | < 1 ms |

---

## Per-Category Breakdown

### TP/FP by Category

| Detector | Cat A TP/50 | Cat B TP/50 | Cat C FP/50 | Cat D FP/50 |
|---|---|---|---|---|
| **ClassifierDetector** | **46 (92%)** | **30 (60%)** | **0 (0%)** | **1 (2%)** |
| e5-large | 40 (80%) | 15 (30%) | 0 (0%) | 0 (0%) |
| mpnet-base-v2 | 28 (56%) | 9 (18%) | 0 (0%) | 0 (0%) |
| MiniLM-L12-v2 | 27 (54%) | 6 (12%) | 0 (0%) | 0 (0%) |
| rule only | ~20 (40%) | ~0 (0%) | 0 (0%) | 0 (0%) |

The single FP from ClassifierDetector (Cat D) was:
> 「依存性注入フレームワークにおける「インジェクション」を説明してください。」  
> risk_score=0.668 (the word "インジェクション" triggered a borderline score)

---

## Key Findings

### 1. ClassifierDetector is the best overall detector

- Detection rate +21 pp above e5-large (the previous best)
- F1 improvement: 0.859 vs 0.710 (+0.149)
- 5x faster than e5-large (165 ms vs 878 ms)
- Only 1 false positive across 100 safe inputs

### 2. Category B (paraphrase) remains the hardest

All embedding models perform poorly on paraphrase attacks. ClassifierDetector is the only one that generalizes reasonably (60%), which reflects the fine-tuning on a diverse attack dataset containing roleplay, obfuscation, and indirect injection patterns.

| Model | Cat B recall |
|---|---|
| ClassifierDetector | **60%** |
| e5-large | 30% |
| mpnet-base-v2 | 18% |
| MiniLM-L12-v2 | 12% |

### 3. Specificity trade-off is minimal

The single FP (「インジェクション」 in a benign context) represents a 1% FP rate on Cat D. In production, combining ClassifierDetector with a whitelist rule for known benign "injection" usages (e.g., dependency injection) would eliminate this.

### 4. Latency is competitive

At 165 ms (CPU, Raspberry Pi 4), ClassifierDetector is 5x faster than e5-large while delivering significantly better recall. On more capable hardware, latency will be lower.

---

## Model Details

**Model:** `promptgate-classifier-v1`  
**Backbone:** `distilbert-base-multilingual-cased` (66M parameters, EN+JA)  
**Training data:** `data/dataset_v1.csv` (4,000 cases, attack:1,868 / safe:2,132)  
**Training strategy:** Phase 1 only (backbone frozen, classifier head trained, LR=1e-3, 2 epochs)  
**Hardware:** Raspberry Pi 4 (8GB RAM) — Phase 2 full fine-tune was OOM-killed  
**Path:** `models/promptgate-classifier-v1/`

Phase 2 (full fine-tune, backbone LR=2e-5) was not completed due to memory constraints (~2.8GB available). Running Phase 2 on a machine with 16GB+ RAM is expected to push Cat B recall above 70% and overall F1 above 0.90.

---

## Recommendation

For production use in PromptGate:

1. **Use ClassifierDetector as the primary detector** — highest recall, acceptable FP rate, reasonable latency.
2. **Keep rule-based as the pre-filter** — zero latency for obvious patterns.
3. **Avoid embedding-only detectors** — even the best (e5-large) misses 45% of attacks and is 5x slower.
4. **Consider Phase 2 fine-tuning** on a higher-memory machine to push Cat B recall further.

Suggested configuration:
```python
gate = PromptGate(detectors=["rule", "classifier"])
```
