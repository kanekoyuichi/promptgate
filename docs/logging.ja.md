# ログ

PromptGate のログは2種類あります。

- **監査ログ**: スキャン結果を記録する。本番運用での追跡・監視に使用する
- **内部警告ログ**: パターン読み込みや LLM API のエラーを記録する

どちらも Python 標準の `logging` モジュールを使用しており、既存のログ設定に統合できます。

---

## 監査ログ

### 出力タイミングとログレベル

| 条件 | ログレベル |
|---|---|
| `is_safe=False`（ブロック） | `WARNING` |
| `is_safe=True` かつ `log_all=True` | `INFO` |
| `is_safe=True` かつ信頼済みユーザー | `INFO` |
| 上記以外（通過・通常ユーザー） | 出力しない |

デフォルトでは**ブロック時のみ**ログが出ます。

### メッセージ形式

```
promptgate.scan verdict=BLOCKED trace_id=abc123 scan_type=input input_hash=d4d10baf risk_score=0.9500 threats=['direct_injection']
```

### extra フィールド

`logging.Handler` の `LogRecord` に付加される構造化データです。
JSON ハンドラや外部ログサービスと組み合わせることで機械可読な監査証跡として利用できます。

| フィールド | 型 | 内容 |
|---|---|---|
| `trace_id` | `str` | リクエスト追跡 ID（未指定時は自動生成 UUID） |
| `tenant_id` | `str \| None` | `PromptGate(tenant_id=...)` で設定したテナント識別子 |
| `scan_type` | `str` | `"input"` または `"output"` |
| `input_hash` | `str` | 入力テキストの SHA-256 先頭16桁（本文は含まない） |
| `input_length` | `int` | 入力文字数 |
| `user_id` | `str \| None` | `scan(text, user_id=...)` で渡したユーザー ID |
| `is_trusted` | `bool` | 信頼済みユーザーフラグ |
| `is_safe` | `bool` | 最終判定 |
| `risk_score` | `float` | 最終スコア（0.0〜1.0） |
| `threats` | `list[str]` | 検出された脅威カテゴリのリスト |
| `detector_scores` | `dict[str, float]` | スキャナー別スコア（例: `{"rule": 0.9}`） |
| `rule_hits` | `list[str]` | ルールスキャナーがヒットした脅威タイプ |
| `latency_ms` | `float` | スキャン全体の処理時間（ms） |
| `input_text` | `str` | 入力テキスト原文（`log_input=True` 時のみ付与） |

### 設定オプション

```python
gate = PromptGate(
    log_all=True,       # 通過判定もすべてログに記録（デフォルト: False）
    log_input=True,     # 入力テキスト原文を extra に含める（デフォルト: False）
    tenant_id="app-1",  # テナント識別子を全ログに付与
)
```

> **`log_input=True` について**: 入力テキスト原文がそのままログに記録されます。
> 個人情報や機密情報を含む入力が流れる環境では、ログの保管・アクセス制御を適切に設定してください。

### trace_id の指定

`scan()` / `scan_async()` に `trace_id` を渡すと、アプリケーション側のリクエスト ID と紐付けられます。

```python
result = gate.scan(user_input, trace_id=request.headers.get("X-Request-ID"))
```

### 構造化ログへの接続

`extra` フィールドは `LogRecord` の属性として渡されるため、カスタムハンドラで参照できます。

```python
import logging
import json

class JsonHandler(logging.StreamHandler):
    FIELDS = [
        "trace_id", "tenant_id", "scan_type", "input_hash",
        "is_safe", "risk_score", "threats", "latency_ms",
    ]

    def emit(self, record):
        data = {"level": record.levelname, "message": record.getMessage()}
        for field in self.FIELDS:
            if hasattr(record, field):
                data[field] = getattr(record, field)
        print(json.dumps(data, ensure_ascii=False))

logging.getLogger("promptgate.core").addHandler(JsonHandler())
```

出力例:

```json
{
  "level": "WARNING",
  "message": "promptgate.scan verdict=BLOCKED ...",
  "trace_id": "abc123",
  "scan_type": "input",
  "is_safe": false,
  "risk_score": 0.95,
  "threats": ["direct_injection", "data_exfiltration"],
  "latency_ms": 0.41
}
```

---

## 内部警告ログ

ライブラリの動作上の問題を `WARNING` で出力します。監査ログとは別の用途です。

| ロガー名 | 発生条件 |
|---|---|
| `promptgate.detectors.rule_based` | YAML パターンのコンパイル失敗、空文字列マッチパターンの拒否、`add_rule()` でのバリデーション失敗 |
| `promptgate.detectors.llm_judge` | LLM API エラー（`llm_on_error` の設定に従い処理を継続） |

これらのログが出た場合、設定ミスや外部サービスの障害を示している可能性があります。

---

## ロガー名の一覧

| ロガー名 | 用途 |
|---|---|
| `promptgate.core` | 監査ログ |
| `promptgate.detectors.rule_based` | ルールスキャナーの内部警告 |
| `promptgate.detectors.llm_judge` | LLM スキャナーの内部警告 |

特定のロガーだけを有効にしたい場合:

```python
import logging

# 監査ログのみ WARNING 以上を出力
logging.getLogger("promptgate.core").setLevel(logging.WARNING)

# 内部警告ログを無効化
logging.getLogger("promptgate.detectors").setLevel(logging.ERROR)
```
