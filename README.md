# WireGuard 管理器（fn-wg-web）

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.2.9-green.svg)](#)
[![Platform](https://img.shields.io/badge/platform-fnOS%20x86_64%20%7C%20arm64-orange.svg)](#)
[![Docker](https://img.shields.io/badge/docker-linuxserver%2Fwireguard-lightgrey.svg)](#)

在飞牛 OS（fnOS）上以 Docker 容器方式部署 WireGuard 服务端的可视化 Web 管理面板。安装即用，浏览器全程操作，无需命令行：点击部署自动拉取 `linuxserver/wireguard:latest` 镜像并创建容器，可视化完成服务器配置、客户端创建与状态监控。

- 一键部署 WireGuard 服务端，不向系统安装任何 wireguard 软件包
- 配置目录映射选填，所有配置与客户端文件集中保存在 NAS 目录
- 客户端配置支持文本、二维码扫码、文件下载三种方式导出
- 实时展示客户端在线状态、握手时间与上下行流量

## 功能特性

| 模块 | 说明 |
|------|------|
| Docker 部署 | 一键拉取镜像、创建容器（NET_ADMIN/SYS_MODULE 能力、UDP 端口映射、重启自愈）；自动接管已存在的同名容器 |
| 服务器配置 | 公网 IP/域名（Endpoint）、UDP 端口（默认 51820）、内网网段（默认 `10.13.13.0/24`）、DNS、KeepAlive、NAT 转发，公钥一键复制 |
| 客户端管理 | 一键创建、批量生成（自动编号）；全量代理或仅内网分流（AllowedIPs）；二维码扫码导入；配置下载/复制；删除即时生效 |
| 保存与应用分离 | 「保存设置」仅写配置，「应用到运行时」才重启容器生效，防止误操作 |
| 实时监控 | 容器/接口运行状态、配置一致性、客户端在线/离线、握手时间、上下行流量，10 秒自动刷新 |
| 数据持久化 | 配置存于 fnOS 官方持久卷，应用升级/卸载均不丢失；需要彻底清理时在应用内一键操作 |
| fnOS 原生集成 | 打包为 `.fpk` 应用，应用中心手动安装，桌面图标进入管理面板 |

## 快速开始

系统要求：fnOS（Debian 12，x86_64 / arm64）、已启用 Docker、root 权限安装；公网接入需要公网 IP 或 DDNS 域名，并在路由器转发对应 UDP 端口。

1. 下载 `dist/fn-wg-web_0.2.9_all.fpk`
2. 登录飞牛 NAS 桌面 → 应用中心 → 左下角「手动安装」→ 选择 fpk 上传安装
3. 桌面出现「WireGuard 管理器」图标，打开应用
4. 填写配置目录映射等参数，点击「部署 WireGuard 容器」（首次自动拉取镜像，约 1-2 分钟）

外部浏览器访问：`http://NAS_IP:51821`

## 使用指南

### 部署容器（首次）

| 字段 | 说明 |
|------|------|
| 配置目录映射 | 容器 `/config` 映射的 NAS 目录（选填，默认 `/vol1/docker/wireguard`） |
| UDP 端口 | WireGuard 监听端口，默认 `51820`（路由器需放行） |
| 内网网段 | `INTERNAL_SUBNET`，默认 `10.13.13.0/24`，服务器占用 `.1` |
| 公网 IP / 域名 | 客户端 Endpoint，留空自动探测公网 IP |
| 客户端 DNS | 默认 `1.1.1.1, 8.8.8.8` |

点击部署后系统按序执行：创建配置映射目录 → 拉取镜像并创建容器 → 容器就绪后生成服务器密钥（若镜像已生成 `wg0.conf` 则直接接管其密钥）→ 应用配置、启动隧道。

### 创建客户端

右侧「创建客户端」：填写名称（支持批量，如填数字前缀一次生成多个）与路由模式（全量/分流）。创建后自动弹出二维码（手机扫码导入）与配置文件（下载/复制）。客户端增删后容器自动重启同步，即时生效。

### 修改配置

修改端口/域名/网段等参数 → 「保存设置」→ 「应用到运行时」（重启容器生效）。已创建的客户端需重新下载配置。修改网段需先删除全部客户端；彻底变更可用「重置服务器」。

### 文件位置

| 路径 | 说明 |
|------|------|
| `<映射目录>/wg_confs/wg0.conf` | 服务器配置（容器内 wg-quick 加载） |
| `<映射目录>/` | 客户端配置、密钥、二维码 PNG（容器自动生成） |
| `/usr/fn-wg-web/` | 管理服务（`wg-manager.py` + `web/`） |
| `/var/apps/fn-wg-web/var/state.json` | 应用配置（官方持久卷，升级/卸载保留） |
| `/var/log/fn-wg-web.log` | 管理服务日志 |

## 技术架构

- 后端：Python 3 标准库 REST API，零第三方依赖；以 root 运行（fpk `install_type=root`）
- WireGuard 服务端完全运行于 `linuxserver/wireguard` 容器：状态查询走 `docker exec wireguard wg show`，配置应用走「写 `wg0.conf` + `docker restart wireguard`」
- 客户端密钥对由容器内 `wg genkey` / `wg pubkey` 生成，私钥仅存于 `state.json`
- 部署后自动从实际 `wg0.conf` 同步服务器密钥，保证客户端配置中的公钥与实际一致
- 前端：原生 HTML/CSS/JS + 本地 qrcode 库（二维码浏览器端生成，无需联网）

### 数据目录策略

配置（`state.json`）存放在 fnOS 官方持久卷 `/var/apps/fn-wg-web/var`（即 `/usr/local/apps/@appdata/fn-wg-web`），由应用中心统一管理。程序文件与数据目录分离：web 静态资源从 `/usr/fn-wg-web` 读取，配置写入持久卷。

### 升级与卸载语义

- 升级（应用中心升级 / 覆盖安装）：只刷新程序文件，不执行卸载清理，容器、映射目录、配置全部保留，无需重新部署
- 卸载应用：温和卸载，只停止管理服务、清理应用自身运行目录；容器与数据保留，VPN 服务不受影响
- 彻底清理：应用内「卸载并删除全部数据」按钮（双重确认），移除容器、删除映射目录与客户端数据、清空配置

## 目录结构

```
fn-wg-web/
├── README.md                 # 项目说明
├── LICENSE                   # MIT 协议
├── CHANGELOG.md              # 版本变更记录
├── .gitignore                # Git 忽略规则
├── pkg/
│   ├── files/               # 运行时文件
│   │   ├── wg-manager.py    # 管理服务（REST API + 容器编排）
│   │   └── web/             # 前端静态资源
│   │       ├── index.html
│   │       ├── app.js
│   │       ├── style.css
│   │       └── qrcode.min.js
│   └── fnos/                # fnOS 应用包内容
│       ├── manifest         # 应用清单（service_port 51821 / install_type root）
│       ├── cmd/             # 生命周期脚本（main + install/upgrade/uninstall 的 init/callback）
│       ├── config/          # privilege + resource
│       ├── ui/              # 桌面入口 + index.cgi + 图标
│       ├── ICON.PNG
│       └── ICON_256.PNG
├── build-tools/             # 打包脚本（make-icons.py / build_fpk.py）
├── build.ps1                # Windows 一键打包
└── build.sh                 # Linux / fnOS 一键打包
```

`dist/`、`build/`、`__pycache__/` 为本地生成内容，已通过 `.gitignore` 排除，不作为 GitHub 源码提交。

## 本地开发与打包

```bash
# Windows
.\build.ps1
# Linux / fnOS
./build.sh
```

产物为 `dist/fn-wg-web_<version>_all.fpk`（tar.gz 格式）。

### 本地联调（无 docker 环境）

自动降级为模拟模式预览 UI：

```bash
WG_WEB_BASE=/tmp/wgm-test python3 pkg/files/wg-manager.py --port 51821
```

## 常见问题

**客户端无法连接？** 确认路由器/NAS 防火墙放行了监听 UDP 端口；确认管理面板中公网 IP/域名（Endpoint）正确；确认客户端使用的是最新导出的配置。

**修改配置后不生效？** 「保存设置」仅写入配置，需点击「应用到运行时」重启容器生效。

**想彻底删除所有数据？** 在管理面板底部点击「卸载并删除全部数据」，双重确认后移除容器、删除映射目录并清空配置。

**升级会丢配置吗？** 不会。配置存于官方持久卷，升级/卸载应用均自动保留。

## 安全说明

管理面板无鉴权，请仅在受信任的内网环境使用；WireGuard 使用 UDP 协议，请确保防火墙放行监听端口。首次部署需要 NAS 能够访问 Docker Hub（网络异常时可在 Docker 设置中配置镜像加速）。

## License

[MIT](LICENSE)
