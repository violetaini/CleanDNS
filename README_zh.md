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

CleanDNS 是一个自部署 DNS 过滤服务，提供响应式网页管理面板。Node.js 核心统一处理过滤、重写、缓存、客户端与查询统计，可选的原生 Go 传输层负责 DNS-over-QUIC。

## 快速开始

### 一键安装 · Linux x86_64 / arm64

```bash
curl -fsSL https://raw.githubusercontent.com/violetaini/CleanDNS/main/install.sh | sudo bash
```

安装包自带 Node.js 24 和原生 DoQ，无需在服务器编译。首次安装通过网页向导设置监听地址、管理员账号和上游 DNS，并自动检查端口。向导默认 **127.0.0.1:3000**，安装命令会给出带令牌的链接和远程 SSH 转发方法。升级保留已有配置和数据。

[Installation guide / 安裝指引](docs/first-run.md) · [Releases](https://github.com/violetaini/CleanDNS/releases/latest)

### 从源码启动

```bash
git clone https://github.com/violetaini/CleanDNS.git
cd CleanDNS
npm start
```

源码运行需要 Node.js 22+。没有配置文件时，终端会给出首次安装链接；向导完成后访问你选择的管理地址，默认为 **http://127.0.0.1:8055/admin/**。已有 config.json 会直接启动服务。Node 核心无外部 npm 运行时依赖，仅自行编译原生 DoQ 时需要 Go 1.26+。

## 功能

- DoH、可选 UDP/TCP 普通 DNS，以及主服务管理的原生 DoQ。
- UDP、TCP、DoT、DoH、DoQ 上游，Bootstrap DNS、回退上游与客户端独立解析策略。
- 黑白名单、规则订阅、DNS 重写、响应过滤及客户端独立设置。
- 服务屏蔽目录自动更新、时间表、安全搜索、安全浏览与家长控制选项。
- TTL 与乐观缓存、ECS、DNSSEC 请求处理和 IPv6 控制。
- 查询日志、留存周期、IP 匿名化、统计图表及运行时客户端发现。
- 可选 Linux DHCP、网卡检查、租约与静态租约管理。
- 明暗主题、移动端布局、独立管理员登录，以及可选的 [Chitanda SSO 管理端登录](docs/sso.md)。DNS 协议入口继续使用原有访问策略。

## 架构与原生 DoQ

Node.js 主进程管理 Go DoQ 子进程的启停、端口、证书重载与退出。Go 子进程通过 PROXY v2 转交原始客户端信息，过滤、缓存和上游策略仍由同一个核心处理。参见[原生 DoQ 文档](docs/native-doq.md)。

```bash
bash build-cleandns-dns
```

在私有 `config.json` 中设置 DoQ 开关、域名、UDP 端口及证书/私钥路径。示例使用非特权端口 `8853`，默认关闭 DoQ。仓库不附带编译二进制或生产证书。

## 开发与验证

```bash
npm ci
npm test
go test ./cmd/cleandns-dns
```

`npm run audit:local` 提供额外的隔离集成检查。GitHub Actions 执行 JavaScript 回归、Shell 语法、Go 测试与构建。`cmd/audit-panel.mjs` 是按需使用的浏览器检查工具，不会在 CI 中访问生产站点。

## 项目目录

| 目录/文件 | 用途 |
| --- | --- |
| `server.js`、根目录 JS | DNS 核心、会话和 API |
| `panel.html` | 网页管理面板 |
| `cmd/cleandns-dns/` | Go DoQ 服务端和上游桥接 |
| `cmd/test-*.mjs` | JavaScript 回归 |
| `config.example.json` | 通用配置示例 |
| `nginx/`、`systemd/`、`docs/` | 部署模板与文档 |

仓库不包含生产配置、密码、会话、查询历史、私钥、编译产物或部署备份。

## 上游与许可

原生传输使用 [quic-go](https://github.com/quic-go/quic-go)，服务屏蔽目录来自 [AdGuard HostlistsRegistry](https://github.com/AdguardTeam/HostlistsRegistry)。当前尚未指定项目级软件许可证，第三方组件沿用各自许可。
