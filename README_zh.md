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

CleanDNS 是一个自部署 DNS 过滤服务，提供响应式网页管理面板。Node.js 核心统一处理过滤、重写、缓存、客户端与查询统计，可选的原生 Go 传输层负责 DNS-over-QUIC。

## 快速开始

推荐使用 Node.js 22 或更新版本。Node 服务只使用内置模块，没有外部 npm 运行时依赖；构建原生 DoQ 需要 Go 1.26 或更新版本。

```bash
git clone https://github.com/violetaini/CleanDNS.git
cd CleanDNS
cp config.example.json config.json
npm start
```

打开 **http://127.0.0.1:8055/admin/**。示例只监听本机回环，内部 UDP 端口为 `8053`。远程访问请使用 SSH 隧道或配置 Nginx 反向代理。

初始账号为 `admin`。首次启动会随机生成临时密码并打印到服务器终端，在 `data/admin-password` 保存加盐哈希。请使用你自己实例生成的密码；项目没有通用默认密码，登录后可在面板修改。

示例默认关闭公网普通 DNS、DHCP 和 DoQ。启用前请配置证书与访问策略。详细步骤见[部署说明](docs/deployment.md)和[配置说明](docs/configuration.md)。

## 功能

- DoH、可选 UDP/TCP 普通 DNS，以及主服务管理的原生 DoQ。
- UDP、TCP、DoT、DoH、DoQ 上游，Bootstrap DNS、回退上游与客户端独立解析策略。
- 黑白名单、规则订阅、DNS 重写、响应过滤及客户端独立设置。
- 服务屏蔽目录自动更新、时间表、安全搜索、安全浏览与家长控制选项。
- TTL 与乐观缓存、ECS、DNSSEC 请求处理和 IPv6 控制。
- 查询日志、留存周期、IP 匿名化、统计图表及运行时客户端发现。
- 可选 Linux DHCP、网卡检查、租约与静态租约管理。
- 明暗主题、移动端布局与独立管理员登录。当前源码快照尚未接入 Chitanda SSO。

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
