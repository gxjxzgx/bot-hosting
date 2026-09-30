# bot-hosting-x-node

Node.js 代理节点部署程序（由 Python 版移植，功能对等）：启动 Xray-core，按环境变量生成 VLESS / VMess / Trojan / Hysteria2 / Reality / SOCKS5 节点，可选 Cloudflare Argo 隧道，内置探针上报。

## 部署（Docker）

```bash
docker run -d --name bot-node \
  -e UUID=你的UUID \
  -e PORT=3000 \
  -p 3000:3000 \
  ghcr.io/<owner>/bot-hosting-x-node:latest
```

镜像由 GitHub Actions 自动构建并推送到 GHCR（`ghcr.io/<owner>/bot-hosting-x-node`），支持 `linux/amd64` 和 `linux/arm64`。

## 主要环境变量

| 变量 | 说明 |
|---|---|
| `UUID` | 节点 UUID，未设置则随机生成 |
| `PORT` | HTTP 服务端口（订阅 `/sub`），默认 3000 |
| `NAME` | 节点名前缀 |
| `ARGO_DOMAIN` / `ARGO_AUTH` | 固定 Argo 隧道域名与 Token（留空用快速隧道） |
| `REALITY_PORT` / `HY2_PORT` / `S5_PORT` / `WS_PORT` | 各协议直连端口，留空不启用 |
| `CDN_DOMAIN` / `DIRECT_WS_PORT` | TLS 直连域名与端口 |
| `UPLOAD_URL` / `PROJECT_URL` | 节点上传订阅器 |
| `BOT_TOKEN` / `CHAT_ID` | Telegram 推送 |
| `PROBE_ID` / `PROBE_SECRET` / `PROBE_URL` | 探针上报 |

完整变量列表见 `index.js` 顶部。
