# Contributing to PromptGate

PromptGate へのコントリビューションを歓迎します。

---

## 開発環境のセットアップ

```bash
git clone https://github.com/kanekoyuichi/promptgate.git
cd promptgate
pip install -e ".[dev]"
```

---

## 開発の流れ

1. Issue を作成して変更内容を議論する
2. `main` から feature ブランチを作成する
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. コードを変更し、テストを追加する
4. 以下のチェックをすべてパスさせる
5. Pull Request を作成する

---

## チェック項目

```bash
# テスト
pytest tests/

# 型チェック
mypy promptgate/

# リント
ruff check promptgate/
```

PR を出す前にこれらが全てパスしていることを確認してください。

---

## コーディング規約

- 型ヒントを全ての関数・メソッドに付ける
- 独自例外 (`PromptGateError` のサブクラス) を使う
- 新しい検出パターンは `promptgate/patterns/ja.yaml` または `en.yaml` に追加する
- ゼロ依存の原則を守る（ルールベース検出に外部ライブラリを使わない）

---

## 攻撃パターンの追加

`promptgate/patterns/ja.yaml` または `en.yaml` に追記するだけで新しいパターンを追加できます。

```yaml
threat_type:
  - "新しいパターン"
```

対応するテストを `tests/test_rule_based.py` に追加してください。

---

## Pull Request

- タイトルは変更内容を簡潔に説明する（日本語・英語どちらでも可）
- 既存のテストが全てパスすること
- 新機能には必ずテストを追加すること

---

## ライセンス

コントリビューションは [MIT License](LICENSE) に同意したものとみなします。
