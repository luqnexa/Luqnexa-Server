# Luqnexa-Server

辞書配信・公開文章収集のRust/Axum開発用プロトタイプです。

実装済み: Ed25519署名付きManifest、SHA-256検証、辞書ストリーム配信、差分更新、原子的切り替え、rollback、同意付き新語投稿、Bearer認証、入力上限、レート制限、監査ログ。投稿は審査待ちへ保存し自動公開しません。


```sh
git clone --recurse-submodules https://github.com/Luqnexa/Luqnexa-Server.git
cd Luqnexa-Server
cargo test --workspace --locked
cargo bench -p luqnexa-server --bench services --locked
```


loopback HTTP限定。公開HTTPS、PostgreSQL、Redis Streams、R2、OS鍵保管、クラッシュ後の自動復旧、IME接続は未実装です。差分生成64MiB・挿入16MiBの上限があります。[実装と制約](docs/phase4-5.md)を参照してください。

青空文庫の収集スクリプトも保持しています。作品のライセンス・取得失敗を区別し、全対象の学習完了を保証しません。入力履歴は収集しません。

GNU AGPL-3.0-only。鍵、トークン、会話履歴、ダウンロードしたコーパス、未採用モデルは公開しません。

AIと学習機能は削除しました。辞書配信と更新機能を保持しています。
