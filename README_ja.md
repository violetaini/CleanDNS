<div align="center">

<img src="assets/avatar.webp" alt="CleanDNS" width="120" />

# **CleanDNS**

[![Version](https://img.shields.io/badge/Version-0.1.0-f97316?style=for-the-badge)](VERSION)
[![Runtime](https://img.shields.io/badge/Runtime-Node.js%2022%2B-22c55e?style=for-the-badge)](package.json)
[![Native Transport](https://img.shields.io/badge/Native%20Transport-Go%201.26%2B-00add8?style=for-the-badge)](go.mod)
[![Frontend](https://img.shields.io/badge/Frontend-HTML%20%2B%20JavaScript-42b883?style=for-the-badge)](panel.html)
[![Configuration](https://img.shields.io/badge/Configuration-JSON-2563eb?style=for-the-badge)](config.example.json)

</div>

<p align="center">
  <a href="README.md">English</a> |
  <a href="README_zh.md">简体中文</a> |
  <a href="README_zh-TW.md">繁體中文</a> |
  <a href="README_ja.md">日本語</a>
</p>

<p align="center">
  <a href="docs/configuration.md">Configuration</a> |
  <a href="docs/deployment.md">Deployment</a> |
  <a href="docs/native-doq.md">Native DoQ</a>
</p>

CleanDNS は、レスポンシブな管理画面を備えたセルフホスト型 DNS フィルタリングサービスです。Node.js がフィルタリング、書き換え、キャッシュ、クライアント、問い合わせ統計を処理し、オプションの Go トランスポートが DNS-over-QUIC を提供します。

## クイックスタート

Node.js 22 以降を推奨します。Node サービスは標準モジュールを使用し、外部 npm ランタイム依存関係はありません。ネイティブ DoQ のビルドには Go 1.26 以降が必要です。

```bash
git clone https://github.com/violetaini/CleanDNS.git
cd CleanDNS
cp config.example.json config.json
npm start
```

**http://127.0.0.1:8055/admin/** を開きます。サンプルはループバックのみをリッスンし、内部 UDP ポートは `8053` です。リモートから利用する場合は SSH トンネルか Nginx を設定してください。

初期ユーザー名は `admin` です。初回起動時にランダムな一時パスワードを生成してコンソールに表示し、ソルト付きハッシュを `data/admin-password` に保存します。共通の初期パスワードはありません。ログイン後に管理画面から変更できます。

公開の通常 DNS、DHCP、DoQ は初期設定で無効です。有効化する前に証明書とアクセス規則を設定してください。[デプロイ手順](docs/deployment.md)と[設定ガイド](docs/configuration.md)を参照してください。

## 機能

- DoH、オプションの UDP/TCP DNS、メインサービスが管理するネイティブ DoQ。
- UDP、TCP、DoT、DoH、DoQ の上流、Bootstrap DNS、フォールバック、クライアント別ポリシー。
- ブロックリスト、許可リスト、購読、DNS 書き換え、応答フィルタリング。
- サービス別ブロックのカタログ更新、スケジュール、セーフサーチ、保護機能。
- TTL、楽観的キャッシュ、ECS、DNSSEC リクエスト処理、IPv6 設定。
- 問い合わせログ、保持期間、IP 匿名化、統計、クライアント検出。
- オプションの Linux DHCP、インターフェース検証、リース管理。
- ライト/ダークテーマ、モバイル画面、ローカル管理者ログイン。このソースは Chitanda SSO に未対応です。

## ネイティブ DoQ

```bash
bash build-cleandns-dns
```

非公開の `config.json` で DoQ、ホスト名、UDP ポート、証明書と秘密鍵を設定します。サンプルの非特権ポートは `8853` です。Go 子プロセスは PROXY v2 で Node.js の共通エンジンに問い合わせを渡します。独立した DoQ サービスは不要です。[設計の詳細](docs/native-doq.md)。

## 開発とテスト

```bash
npm ci
npm test
go test ./cmd/cleandns-dns
```

`npm run audit:local` は追加の分離された統合チェックです。GitHub Actions が JavaScript、Shell 構文、Go テストとビルドを検証します。`cmd/audit-panel.mjs` は任意のブラウザー監査ツールで、CI は本番サイトに接続しません。

## ディレクトリ

- `server.js` とルートの JS：DNS ポリシー、認証、API。
- `panel.html`：Web 管理画面。
- `cmd/cleandns-dns/`：Go DoQ と上流ブリッジ。
- `config.example.json`：認証情報を含まないサンプル。
- `nginx/`、`systemd/`、`docs/`：デプロイ用テンプレートと説明。

本番設定、パスワード、セッション、問い合わせ履歴、秘密鍵、バイナリ、バックアップは含まれません。

## 上流プロジェクトとライセンス

QUIC は [quic-go](https://github.com/quic-go/quic-go)、サービスカタログは [AdGuard HostlistsRegistry](https://github.com/AdguardTeam/HostlistsRegistry) を使用します。プロジェクト全体のライセンスは未指定です。外部コンポーネントにはそれぞれのライセンスが適用されます。
