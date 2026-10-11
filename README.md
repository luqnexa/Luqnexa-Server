# Luqnexa-Server

辞書配信・新語収集の開発用リポジトリです。現在の実装は公開文章からの学習用データ収集スクリプトだけです。Rust/Tokio/AxumのAPIサーバー、PostgreSQL、Redis Streams、R2、認証・レート制限・監査ログ、Ed25519署名更新は**未実装**です。運用サーバーとして起動・公開できる状態ではありません。

実装済みの青空文庫収集は、公式メタデータによる対象選択、順次ダウンロード、サイズ制限、前処理、重複除去、著者単位の評価分割、SQLite再開管理、SHA-256、原子的なローカル学習成果物の保存です。メタデータ条件に合わない作品や失敗作品を、成功した学習として扱いません。端末の入力履歴を収集しません。処理結果を稼働中IMEへ自動適用しません。

```sh
git clone --recurse-submodules https://github.com/Luqnexa/Luqnexa-Server.git
cd Luqnexa-Server
python scripts/test-auto-train-aozora.py
# 明示的に公開文章を取得する場合だけ実行:
python scripts/auto-train-aozora.py --download
```

学習処理と再現用データは固定版の `modules/Luqnexa-AI` にあります。成果物・取得キャッシュはその `.cache` 内へ保存され、Gitへ追加しません。全対象の学習完了を保証するリポジトリではありません。

今後のAPI案: `/api/v1/manifest`、`/dictionaries`、`/updates`、`/words/submit`、`/releases`。ユーザー登録語の送信は明示許可された語だけを対象とします。文章全文・パスワード・会話履歴を自動送信しません。

ソースはAGPL-3.0-only。公開鍵以外の署名鍵・クラウド認証情報・DBデータ・個人辞書はこのリポジトリに含めません。
