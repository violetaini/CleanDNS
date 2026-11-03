<div align="center">

<img src="assets/avatar.webp" alt="CleanDNS" width="120" />

# **CleanDNS**

[![Version](https://img.shields.io/badge/Version-0.2.1-f97316?style=for-the-badge)](VERSION)
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

### ワンコマンドインストール · Linux x86_64 / arm64

```bash
curl -fsSL https://raw.githubusercontent.com/violetaini/CleanDNS/main/install.sh | sudo bash
```

Node.js 24 とネイティブ DoQ を同梱しており、サーバー上でのビルドは不要です。初回セットアップ画面でリッスン先、管理者アカウント、上流 DNS を設定し、ポートを確認します。セットアップは **127.0.0.1:3000** で待ち受けます。トークン付きリンクとリモート用 SSH トンネルの手順を表示します。更新時は既存の設定とデータを保持します。

[Installation guide / 安裝指引](docs/first-run.md) · [Releases](https://github.com/violetaini/CleanDNS/releases/latest)

### ソースから起動

```bash
git clone https://github.com/violetaini/CleanDNS.git
cd CleanDNS
npm start
```

Node.js 22+ が必要です。設定ファイルがなければ初回設定リンクを表示します。完了後に指定した管理画面（既定 **http://127.0.0.1:8055/admin/**）へアクセスしてください。既存の config.json があれば直接起動します。Node コアに外部 npm ランタイム依存関係はなく、DoQ のソースビルドにのみ Go 1.26+ が必要です。

## 機能

- DoH、オプションの UDP/TCP DNS、メインサービスが管理するネイティブ DoQ。
- UDP、TCP、DoT、DoH、DoQ の上流、Bootstrap DNS、フォールバック、クライアント別ポリシー。
- ブロックリスト、許可リスト、購読、DNS 書き換え、応答フィルタリング。
- サービス別ブロックのカタログ更新、スケジュール、セーフサーチ、保護機能。
- TTL、楽観的キャッシュ、ECS、DNSSEC リクエスト処理、IPv6 設定。
- 問い合わせログ、保持期間、IP 匿名化、統計、クライアント検出。
- オプションの Linux DHCP、インターフェース検証、リース管理。
- ライト/ダークテーマ、モバイル画面、ローカル管理者ログイン、および任意の [Chitanda SSO 管理画面認証](docs/sso.md)。DNS プロトコルは既存のアクセス方針を使用します。

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
