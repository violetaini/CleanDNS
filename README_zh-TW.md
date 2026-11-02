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

CleanDNS 是可自行部署的 DNS 過濾服務，提供響應式網頁管理介面。Node.js 核心統一處理過濾、重寫、快取、用戶端與查詢統計，可選的原生 Go 傳輸層負責 DNS-over-QUIC。

## 快速開始

建議使用 Node.js 22 或更新版本。Node 服務僅使用內建模組，沒有外部 npm 執行期依賴；編譯原生 DoQ 需要 Go 1.26 或更新版本。

```bash
git clone https://github.com/violetaini/CleanDNS.git
cd CleanDNS
cp config.example.json config.json
npm start
```

開啟 **http://127.0.0.1:8055/admin/**。範例僅監聽本機回環位址，內部 UDP 連接埠為 `8053`。遠端使用請設定 SSH 通道或 Nginx 反向代理。

初始帳號為 `admin`。首次啟動會隨機產生臨時密碼並顯示在伺服器終端，於 `data/admin-password` 儲存加鹽雜湊。請使用自己實例產生的密碼；專案沒有共用預設密碼，登入後可於面板變更。

範例預設關閉公開的一般 DNS、DHCP 與 DoQ。啟用前請設定憑證及存取規則。詳見[部署說明](docs/deployment.md)與[設定說明](docs/configuration.md)。

## 功能

- DoH、可選 UDP/TCP 一般 DNS，以及主服務管理的原生 DoQ。
- UDP、TCP、DoT、DoH、DoQ 上游，Bootstrap DNS、備援及個別用戶端策略。
- 黑白名單、規則訂閱、DNS 重寫、回應過濾與個別用戶端設定。
- 服務封鎖目錄自動更新、排程、安全搜尋、安全瀏覽及家長控制選項。
- TTL 與樂觀快取、ECS、DNSSEC 請求處理及 IPv6 控制。
- 查詢記錄、保留期限、IP 匿名化、統計圖表及執行期用戶端探索。
- 可選 Linux DHCP、網路介面檢查、租約與靜態租約管理。
- 明暗主題、行動版配置、獨立管理員登入，以及可選的 [Chitanda SSO 管理端登入](docs/sso.md)。DNS 協定入口沿用原有存取規則。

## 原生 DoQ

```bash
bash build-cleandns-dns
```

請在私有 `config.json` 設定開關、網域、UDP 連接埠及憑證/私鑰。範例使用非特權連接埠 `8853`，預設關閉 DoQ。Go 子程序透過 PROXY v2 將查詢交回同一 Node.js 策略核心，不需要獨立的 DoQ 系統服務。詳見[傳輸文件](docs/native-doq.md)。

## 開發與驗證

```bash
npm ci
npm test
go test ./cmd/cleandns-dns
```

`npm run audit:local` 可執行額外的隔離整合檢查。GitHub Actions 執行 JavaScript 回歸、Shell 語法、Go 測試與編譯。`cmd/audit-panel.mjs` 是選用的瀏覽器檢查工具，CI 不會存取正式站點。

## 專案內容

- `server.js`、根目錄模組：DNS 核心、驗證和 API。
- `panel.html`：網頁管理介面。
- `cmd/cleandns-dns/`：Go DoQ 與上游橋接。
- `config.example.json`：不含部署憑據的通用設定。
- `nginx/`、`systemd/`、`docs/`：部署範例及文件。

原始碼倉庫不包含正式設定、密碼、工作階段、查詢歷史、私鑰、編譯產物或部署備份。

## 上游與授權

原生傳輸使用 [quic-go](https://github.com/quic-go/quic-go)，服務封鎖目錄來自 [AdGuard HostlistsRegistry](https://github.com/AdguardTeam/HostlistsRegistry)。目前尚未指定專案層級授權，第三方元件沿用各自條款。
