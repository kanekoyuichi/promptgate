"""Fine-tune a binary prompt-injection classifier.

Example:
    .venv/bin/python scripts/train_classifier.py \
        --data data/dataset_v2.csv \
        --output-dir models/promptgate-classifier-v2
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from sklearn.model_selection import train_test_split
from torch.utils.data import DataLoader

ROOT = Path(__file__).parent.parent


def log(message: str) -> None:
    print(f"[train] {message}", flush=True)


@dataclass(frozen=True)
class TrainConfig:
    data: Path
    output_dir: Path
    base_model: str
    max_length: int
    seed: int
    validation_size: float
    phase1_epochs: int
    phase2_epochs: int
    phase1_lr: float
    phase2_lr_backbone: float
    phase2_lr_head: float
    phase1_batch: int
    phase2_batch: int
    phase2_grad_accum: int
    eval_batch: int
    attack_weight: float
    resume_phase1: bool
    weight_decay: float
    clip_grad_max_norm: float


def parse_args() -> TrainConfig:
    parser = argparse.ArgumentParser(description="Train PromptGate classifier")
    parser.add_argument("--data", default="data/dataset_v2.csv")
    parser.add_argument("--output-dir", default="models/promptgate-classifier-v2")
    parser.add_argument("--base-model", default="distilbert-base-multilingual-cased")
    parser.add_argument("--max-length", type=int, default=128)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--validation-size", type=float, default=0.2)
    parser.add_argument("--phase1-epochs", type=int, default=2)
    parser.add_argument("--phase2-epochs", type=int, default=3)
    parser.add_argument("--phase1-lr", type=float, default=1e-3)
    parser.add_argument("--phase2-lr-backbone", type=float, default=2e-5)
    parser.add_argument("--phase2-lr-head", type=float, default=1e-4)
    parser.add_argument("--phase1-batch", type=int, default=16)
    parser.add_argument("--phase2-batch", type=int, default=2)
    parser.add_argument("--phase2-grad-accum", type=int, default=8)
    parser.add_argument("--eval-batch", type=int, default=4)
    parser.add_argument("--attack-weight", type=float, default=1.0)
    parser.add_argument("--no-resume-phase1", action="store_true")
    parser.add_argument("--weight-decay", type=float, default=0.01)
    parser.add_argument("--clip-grad-max-norm", type=float, default=1.0)
    args = parser.parse_args()

    return TrainConfig(
        data=(ROOT / args.data).resolve() if not Path(args.data).is_absolute() else Path(args.data),
        output_dir=(
            (ROOT / args.output_dir).resolve()
            if not Path(args.output_dir).is_absolute()
            else Path(args.output_dir)
        ),
        base_model=args.base_model,
        max_length=args.max_length,
        seed=args.seed,
        validation_size=args.validation_size,
        phase1_epochs=args.phase1_epochs,
        phase2_epochs=args.phase2_epochs,
        phase1_lr=args.phase1_lr,
        phase2_lr_backbone=args.phase2_lr_backbone,
        phase2_lr_head=args.phase2_lr_head,
        phase1_batch=args.phase1_batch,
        phase2_batch=args.phase2_batch,
        phase2_grad_accum=args.phase2_grad_accum,
        eval_batch=args.eval_batch,
        attack_weight=args.attack_weight,
        resume_phase1=not args.no_resume_phase1,
        weight_decay=args.weight_decay,
        clip_grad_max_norm=args.clip_grad_max_norm,
    )


def set_seed(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)


def load_data(config: TrainConfig) -> tuple[pd.DataFrame, pd.DataFrame]:
    if not config.data.exists():
        raise SystemExit(f"dataset not found: {config.data}")

    df = pd.read_csv(config.data)
    missing = {"text", "label"} - set(df.columns)
    if missing:
        raise SystemExit(f"dataset missing columns: {sorted(missing)}")

    df = df[["text", "label"]].dropna()
    df["label"] = df["label"].astype(int)
    log(
        "data total={} attack={} safe={}".format(
            len(df),
            int((df["label"] == 1).sum()),
            int((df["label"] == 0).sum()),
        )
    )

    train_df, val_df = train_test_split(
        df,
        test_size=config.validation_size,
        random_state=config.seed,
        stratify=df["label"],
    )
    log(f"split train={len(train_df)} val={len(val_df)}")
    return train_df, val_df


def build_datasets(
    train_df: pd.DataFrame,
    val_df: pd.DataFrame,
    tokenizer: object,
    config: TrainConfig,
) -> tuple[object, object]:
    from datasets import Dataset  # type: ignore

    def tokenize(batch: dict[str, list[str]]) -> object:
        return tokenizer(
            batch["text"],
            truncation=True,
            max_length=config.max_length,
            padding="max_length",
        )

    train_ds = Dataset.from_pandas(train_df.reset_index(drop=True))
    val_ds = Dataset.from_pandas(val_df.reset_index(drop=True))

    log("tokenizing")
    train_ds = train_ds.map(tokenize, batched=True, batch_size=256)
    val_ds = val_ds.map(tokenize, batched=True, batch_size=256)

    train_ds = train_ds.rename_column("label", "labels")
    val_ds = val_ds.rename_column("label", "labels")
    train_ds.set_format("torch", columns=["input_ids", "attention_mask", "labels"])
    val_ds.set_format("torch", columns=["input_ids", "attention_mask", "labels"])
    return train_ds, val_ds


def compute_metrics(logits: np.ndarray, labels: np.ndarray) -> dict[str, float | int]:
    preds = np.argmax(logits, axis=1)
    tp = int(((preds == 1) & (labels == 1)).sum())
    fp = int(((preds == 1) & (labels == 0)).sum())
    tn = int(((preds == 0) & (labels == 0)).sum())
    fn = int(((preds == 0) & (labels == 1)).sum())
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    specificity = tn / (tn + fp) if (tn + fp) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    accuracy = (tp + tn) / len(labels) if len(labels) else 0.0
    return {
        "accuracy": round(accuracy, 4),
        "f1": round(f1, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "specificity": round(specificity, 4),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
    }


def evaluate(model: nn.Module, val_ds: object, batch_size: int) -> dict[str, float | int]:
    model.eval()
    loader = DataLoader(val_ds, batch_size=batch_size)
    all_logits: list[np.ndarray] = []
    all_labels: list[np.ndarray] = []
    with torch.no_grad():
        for batch in loader:
            out = model(
                input_ids=batch["input_ids"],
                attention_mask=batch["attention_mask"],
            )
            all_logits.append(out.logits.cpu().numpy())
            all_labels.append(batch["labels"].cpu().numpy())
    return compute_metrics(np.concatenate(all_logits), np.concatenate(all_labels))


def fix_layernorm_naming(model: nn.Module) -> None:
    """Rename DistilBERT embedding LayerNorm beta/gamma to weight/bias if present."""
    ln = model.distilbert.embeddings.LayerNorm
    params = dict(ln._parameters)
    renamed = False
    if "gamma" in params:
        data = params.pop("gamma").data.clone()
        ln._parameters.pop("gamma", None)
        ln.register_parameter("weight", nn.Parameter(data))
        renamed = True
    if "beta" in params:
        data = params.pop("beta").data.clone()
        ln._parameters.pop("beta", None)
        ln.register_parameter("bias", nn.Parameter(data))
        renamed = True
    if renamed:
        log("fixed embedding LayerNorm: beta/gamma -> weight/bias")


def weighted_loss(logits: torch.Tensor, labels: torch.Tensor, attack_weight: float) -> torch.Tensor:
    weights = torch.tensor([1.0, attack_weight], dtype=logits.dtype, device=logits.device)
    return torch.nn.functional.cross_entropy(logits, labels, weight=weights)


def train_phase1(
    model: nn.Module,
    train_ds: object,
    val_ds: object,
    config: TrainConfig,
) -> None:
    log(f"phase1 head-only epochs={config.phase1_epochs} lr={config.phase1_lr}")
    for param in model.distilbert.parameters():
        param.requires_grad = False

    optimizer = torch.optim.AdamW(
        [p for p in model.parameters() if p.requires_grad],
        lr=config.phase1_lr,
        weight_decay=config.weight_decay,
    )
    loader = DataLoader(train_ds, batch_size=config.phase1_batch, shuffle=True)
    steps_per_epoch = len(loader)

    for epoch in range(1, config.phase1_epochs + 1):
        model.train()
        total_loss = 0.0
        for step, batch in enumerate(loader, 1):
            optimizer.zero_grad()
            out = model(input_ids=batch["input_ids"], attention_mask=batch["attention_mask"])
            loss = weighted_loss(out.logits, batch["labels"], config.attack_weight)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=config.clip_grad_max_norm)
            optimizer.step()
            total_loss += float(loss.item())
            if step % 50 == 0 or step == steps_per_epoch:
                log(f"phase1 epoch={epoch} step={step}/{steps_per_epoch} loss={total_loss/step:.4f}")

        metrics = evaluate(model, val_ds, config.eval_batch)
        log(f"phase1 epoch={epoch} val={metrics}")

    for param in model.distilbert.parameters():
        param.requires_grad = True


def train_phase2(
    model: nn.Module,
    train_ds: object,
    val_ds: object,
    config: TrainConfig,
) -> dict[str, float | int]:
    log(
        "phase2 full fine-tune epochs={} backbone_lr={} head_lr={} batch={} grad_accum={}".format(
            config.phase2_epochs,
            config.phase2_lr_backbone,
            config.phase2_lr_head,
            config.phase2_batch,
            config.phase2_grad_accum,
        )
    )
    model.gradient_checkpointing_enable()

    head_params = [
        p
        for name, p in model.named_parameters()
        if "classifier" in name or "pre_classifier" in name
    ]
    backbone_params = [
        p
        for name, p in model.named_parameters()
        if "classifier" not in name and "pre_classifier" not in name
    ]
    optimizer = torch.optim.AdamW(
        [
            {"params": backbone_params, "lr": config.phase2_lr_backbone},
            {"params": head_params, "lr": config.phase2_lr_head},
        ],
        weight_decay=config.weight_decay,
    )

    loader = DataLoader(train_ds, batch_size=config.phase2_batch, shuffle=True)
    steps_per_epoch = len(loader)
    total_steps = config.phase2_epochs * steps_per_epoch
    scheduler = torch.optim.lr_scheduler.LinearLR(
        optimizer,
        start_factor=1.0,
        end_factor=0.0,
        total_iters=total_steps,
    )

    best_f1 = -1.0
    best_specificity = -1.0
    best_state: dict[str, torch.Tensor] | None = None
    best_metrics: dict[str, float | int] = {}

    for epoch in range(1, config.phase2_epochs + 1):
        model.train()
        total_loss = 0.0
        optimizer.zero_grad()
        for step, batch in enumerate(loader, 1):
            out = model(input_ids=batch["input_ids"], attention_mask=batch["attention_mask"])
            loss = weighted_loss(out.logits, batch["labels"], config.attack_weight)
            (loss / config.phase2_grad_accum).backward()
            total_loss += float(loss.item())

            if step % config.phase2_grad_accum == 0 or step == steps_per_epoch:
                torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=config.clip_grad_max_norm)
                optimizer.step()
                scheduler.step()
                optimizer.zero_grad()

            if step % 50 == 0 or step == steps_per_epoch:
                log(f"phase2 epoch={epoch} step={step}/{steps_per_epoch} loss={total_loss/step:.4f}")

        metrics = evaluate(model, val_ds, config.eval_batch)
        log(f"phase2 epoch={epoch} val={metrics}")
        f1 = float(metrics["f1"])
        specificity = float(metrics["specificity"])
        if f1 > best_f1 or (f1 == best_f1 and specificity > best_specificity):
            best_f1 = f1
            best_specificity = specificity
            best_metrics = metrics
            best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}
            log(f"new best f1={best_f1:.4f} specificity={best_specificity:.4f}")

    if best_state is not None:
        model.load_state_dict(best_state)
    return best_metrics


def main() -> None:
    from transformers import AutoModelForSequenceClassification, AutoTokenizer  # type: ignore

    config = parse_args()
    config.output_dir.mkdir(parents=True, exist_ok=True)
    phase1_ckpt = config.output_dir / "phase1_checkpoint"

    log("start")
    log(f"data={config.data}")
    log(f"output_dir={config.output_dir}")
    log(f"base_model={config.base_model}")
    log(f"attack_weight={config.attack_weight}")
    set_seed(config.seed)

    train_df, val_df = load_data(config)
    tokenizer = AutoTokenizer.from_pretrained(config.base_model)

    if config.resume_phase1 and phase1_ckpt.exists():
        log(f"loading phase1 checkpoint: {phase1_ckpt}")
        model = AutoModelForSequenceClassification.from_pretrained(str(phase1_ckpt), num_labels=2)
        fix_layernorm_naming(model)
    else:
        model = AutoModelForSequenceClassification.from_pretrained(config.base_model, num_labels=2)
        fix_layernorm_naming(model)

    train_ds, val_ds = build_datasets(train_df, val_df, tokenizer, config)

    if not (config.resume_phase1 and phase1_ckpt.exists()):
        train_phase1(model, train_ds, val_ds, config)
        log(f"saving phase1 checkpoint: {phase1_ckpt}")
        model.save_pretrained(str(phase1_ckpt))
        tokenizer.save_pretrained(str(phase1_ckpt))

    best_metrics = train_phase2(model, train_ds, val_ds, config)
    final_metrics = evaluate(model, val_ds, config.eval_batch)

    model.save_pretrained(str(config.output_dir))
    tokenizer.save_pretrained(str(config.output_dir))

    report = {
        "config": {
            "data": str(config.data.relative_to(ROOT) if config.data.is_relative_to(ROOT) else config.data),
            "output_dir": str(
                config.output_dir.relative_to(ROOT)
                if config.output_dir.is_relative_to(ROOT)
                else config.output_dir
            ),
            "base_model": config.base_model,
            "max_length": config.max_length,
            "seed": config.seed,
            "validation_size": config.validation_size,
            "phase1_epochs": config.phase1_epochs,
            "phase2_epochs": config.phase2_epochs,
            "attack_weight": config.attack_weight,
        },
        "best_metrics": best_metrics,
        "final_metrics": final_metrics,
    }
    metrics_path = config.output_dir / "train_metrics.json"
    metrics_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    log(f"saved model: {config.output_dir}")
    log(f"saved metrics: {metrics_path}")
    log(f"final={final_metrics}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
