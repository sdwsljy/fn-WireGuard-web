# Changelog

所有重要变更记录在此文件。格式参照 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [0.3.9] - 2026-08-14

### 变更

- **无损升级后清理旧文件（四层同步升级安全删除流程）**：将 0.3.8 的「仅复制保留原件」策略升级为【复制→校验→删除原件】三步安全流程，在 4 个入口同构执行：
  - 校验条件：src/dst 都存在、dst **非空**、**字节数完全相等**，三者同时满足才删除源；任一不满足则保留原件并日志告警
  - 只删**单个具体文件**，绝不使用任何 `rm -rf` 或递归删除目录命令
  - 目录清理仅使用非递归 `rmdir`/`os.rmdir`，只移除**完全空**的目录壳
  - `LEGACY_DIR (/usr/fn-wg-web)` 自底向上尝试 `rmdir` 清空壳目录，任何非空目录都会自然保留
- **覆盖的四类旧数据**（与 0.3.8 相同，但全部升级为迁完清理）：
  1. `state.json`：`/usr/fn-wg-web/state.json` → `$TRIM_PKGVAR/state.json`（持久卷已有时按尺寸校验删旧副本）
  2. 日志：`/var/log/fn-wg-web.log*`（含 `.1`/`.2` 轮转历史）→ `$DATA_DIR/`
  3. 静态配置：`/usr/fn-wg-web/etc/**/*` → `$TRIM_PKGETC/**/*`（文件迁完清空 ETC 空目录壳）
  4. 散落配置备份：`/usr/fn-wg-web/*.{json,conf}` → `$DATA_DIR/legacy-backup/`（state.json 已迁过主路径则跳过）

## [0.3.8] - 2026-08-14

### 变更

- **无损升级迁移四层兜底增强**：迁移逻辑在 4 个独立入口同构、幂等、目标不存在才迁、原件保留不删，确保跨版本升级绝对无损：
  - ① `cmd/install_callback`（安装/覆盖安装阶段）
  - ② `cmd/upgrade_callback`（升级阶段）
  - ③ `cmd/main start`（服务启动前，shell 侧）
  - ④ `wg-manager.py` `_migrate_legacy_data_on_startup()`（Python 进程内最后一层兜底）
- **迁移覆盖 4 类旧数据**：
  1. `state.json`：`/usr/fn-wg-web/state.json` → `$TRIM_PKGVAR/state.json`（主配置）
  2. 旧日志：`/var/log/fn-wg-web.log*`（含轮转历史） → `$DATA_DIR/`（与新日志共存于官方持久卷）
  3. 静态配置：`/usr/fn-wg-web/etc/**/*` → `$TRIM_PKGETC`（递归、保持相对路径）
  4. 散落配置备份：`/usr/fn-wg-web/*.{json,conf}` → `$DATA_DIR/legacy-backup/`（无损兜底，state.json 迁过主路径后不再重复备份）
- 所有迁移均为「复制 + 目标不存在才覆盖」策略，`/usr/fn-wg-web` 旧目录下的原件完整保留，便于用户随时手动回滚/核对。

## [0.3.7] - 2026-08-14

### 变更

- **完整对齐 fnOS 官方规范（查缺补漏）**：
  - 补齐对 `TRIM_PKGETC`（静态配置目录）的感知，目录解析优先级：`WG_ETC_BASE` → `TRIM_PKGETC` → `DATA_DIR/etc`（回退），并在启动时自动 `mkdir -p`
  - 补齐 `TRIM_APPNAME` / `TRIM_APPVER`（manifest 信息）在启动日志中的展示
  - 补齐 `TRIM_TEMP_LOGFILE` 输出：`cmd/main` 未知命令错误写入官方临时日志
  - 运行日志从硬编码 `/var/log/fn-wg-web.log` 改为优先写入 `$TRIM_PKGVAR/fn-wg-web.log`（持久卷内），与应用数据共存；升级时自动迁移旧日志
  - `cmd/main` 显式通过环境变量 `WG_WEB_BASE/WG_ETC_BASE/WG_DATA_BASE/WG_LOG_FILE` 传递目录决策，避免 Python 端对 `TRIM_*` 的回退依赖在边界场景错位
  - `manifest` 新增 `disable_authorization_path = true`：本应用不使用 fnOS 系统目录授权机制（用户直接在 Web UI 填写路径），隐藏无用「授权目录」设置项
  - `manifest` 新增 `changelog` 字段，在应用中心更新页面展示更新摘要
  - `uninstall_callback` 日志清理同时覆盖持久卷新位置与历史 `/var/log` 位置，`state.json` 保留便于用户重装复用

## [0.3.6] - 2026-08-14

### 变更

- **存储结构对齐 fnOS 官方 resource 规范**（[官方文档](https://developer.fnnas.com/docs/core-concepts/resource/)）：
  - 程序文件直接从官方安装目标 `TRIM_APPDEST` 运行，不再每次启动复制到自建 `/usr/fn-wg-web`（去除冗余拷贝）
  - 持久数据改用官方持久卷环境变量 `TRIM_PKGVAR`，不再硬编码 `/var/apps/fn-wg-web/var`
  - `wg-manager.py` 的 `BASE_DIR`/`DATA_DIR` 解析优先级调整为：显式覆盖（`WG_WEB_BASE`/`WG_DATA_BASE`）→ 官方变量（`TRIM_APPDEST`/`TRIM_PKGVAR`）→ 旧路径/本地开发回退
  - 生命周期脚本（main/install/upgrade/uninstall）统一改用官方环境变量，旧版本 `/usr/fn-wg-web` 数据在安装/升级时一次性迁移到官方持久卷
  - 卸载时程序文件交由官方流程清理，仅清理历史遗留运行目录与日志

## [0.3.3] - 2026-08-11

### 修复

- **批量创建客户端忽略「分流」路由**：`/api/peers/batch` 未解析 `route_mode`/`route_cidr`，`batch_create_peers` 也未透传 `route`，导致批量生成的客户端固定为「全量代理」，UI 选择「分流」无效；现在批量创建与单创建同样按用户选择写入 `AllowedIPs`
- **批量创建逐个重启容器 → 一次性应用**：原实现每生成一个客户端即 `apply_config` 触发 `docker restart wireguard`，50 个客户端会重启 50 次导致已连客户端全部瞬断；重构为内存统一分配密钥/IP，仅在最后一次性写入 `wg0.conf` 并重启容器
- **配置导入未报告应用失败**：`/api/config/import` 即便 `apply_config` 失败仍返回「配置已导入并应用」；现区分为成功（已应用到运行时）与失败（已导入但需要手动「应用到运行时」重试），前端可据此给出准确提示
- **部署容错**：`deploy_container` 中宿主配置目录创建失败时直接抛错；现容忍 `os.makedirs` 失败（docker 挂载会自动创建目标目录），配合后续 docker run 落地主机路径
- **`INTERNAL_SUBNET` 缺前缀长度**：传给 `linuxserver/wireguard` 镜像的环境变量为 `10.13.13.0`（缺 `/24`），与镜像模板预期不符；现传入完整 CIDR（如 `10.13.13.0/24`）

## [0.3.2] - 2026-08-08

### 修复

- 修复首次使用时登录页无法显示：`/api/auth/status` 在未设置密码时返回 `auth_enabled: true`，登录页 JS 优先检查 `need_setup` 再检查 `auth_enabled`，避免无限刷新导致白屏

## [0.3.1] - 2026-08-08

### 变更

- 内网访问强制认证：启用密码认证后，所有网络访问（含内网）均需先登录，未认证时仅返回自包含登录页，不再暴露完整管理界面（HTML/CSS/JS）和任何 API
- 新增独立登录页：未认证时由后端动态生成自包含登录页面（内联 CSS/JS），支持首次设置密码与登录两种模式，登录成功后自动加载完整应用

## [0.3.0] - 2026-08-08

### 新增

- 密码认证：支持设置管理密码，启用后访问管理面板需登录（SHA-256 加盐哈希 + Cookie 会话令牌），可随时修改密码或关闭认证
- 客户端重命名：支持在线重命名客户端，无需删除重建，不涉及密钥/IP 变更
- 客户端启用/停用：支持一键停用客户端（从 wg0.conf 移除并重启容器生效），停用后配置保留可随时重新启用
- MTU 配置：服务器配置与部署向导中可自定义 MTU 值（576-9000，默认 1280），客户端配置同步生效
- 配置导入/导出：支持一键导出完整配置（state.json）为 JSON 文件，支持从 JSON 文件导入恢复或迁移配置（保留当前密码认证设置）
- 客户端搜索：客户端列表新增搜索框，支持按名称或 IP 实时过滤

### 变更

- 客户端卡片新增重命名、停用/启用操作按钮
- 安全与备份区块整合密码认证与配置备份功能
- 启动流程优先检查认证状态，未登录时自动弹出登录窗口
- 周期刷新增加登录状态检查，未登录时暂停自动刷新

## [0.2.9] - 2026-08-03

### 变更

- 卸载应用不再删除 docker 容器与数据：卸载（应用中心删除）只停止管理服务、清理应用自身运行目录，wireguard 容器、配置映射目录、客户端数据全部保留，VPN 服务不受影响
- 新增应用内「卸载并删除全部数据」按钮（服务器配置区底部、重置按钮下方）：用户双重确认后一键移除容器、删除配置映射目录（含所有客户端密钥与配置）、清空应用配置

## [0.2.8] - 2026-08-03

### 修复

- 修复打开界面报 `{"ok": false, "error": "static missing: index.html"}`：程序文件目录与数据目录彻底分离，web 资源从 `/usr/fn-wg-web` 读取，配置写入官方持久卷 `/var/apps/fn-wg-web/var`

## [0.2.7] - 2026-08-03

### 变更

- 按 fnOS 官方 fpk 标准重构升级/卸载语义：
  - 数据目录迁移到官方持久卷（`/var/apps/fn-wg-web/var`），升级/卸载均自动保留，首次启动自动迁移旧配置
  - 升级只刷新程序文件，不删容器、不删映射目录、不删配置；按容器实况保持「已部署」
  - 卸载时完整清理容器与映射数据

## [0.2.6] - 2026-08-03

### 修复

- 修复升级/更新会删除 docker 容器与映射目录、导致需要重新部署：卸载脚本不再删除容器与映射目录；升级/重装后按容器实况设置状态，无需重新部署

## [0.2.5] - 2026-08-03

### 修复

- 彻底修复点击图标提示 `{"ok": false, "error": "not found"}`：管理服务对任意未知路径统一回退到管理首页；图标入口使用 fnOS 官方 `http://${host}:51821/` 模板

## [0.2.4] - 2026-08-03

### 修复

- 修复升级/覆盖安装后配置被清空：`upgrade_init`/`install_init` 升级前先备份配置到持久目录，`install_callback`/`upgrade_callback` 安装后自动恢复；重新部署容器时沿用已保存的服务器密钥

## [0.2.3] - 2026-08-03

### 修复

- 修复点击桌面图标提示 `{"ok": false, "error": "not found"}` 无法进入界面：图标 url 改为直接打开管理端口根路径，并让 `/index.cgi` 兼容返回管理首页

## [0.2.2] - 2026-08-03

### 修复

- 修复握手状态一直显示"从未"、无流量统计：修正 `wg show wg0 dump` 的 peer 行字段解析（第一个字段即公钥，无 `peer` 前缀标记）
- 修复桌面图标未生成：`ui/` 目录冗余打进 `app.tgz`，确保安装后 `target/ui` 一定存在

## [0.2.1] - 2026-08-03

### 修复

- 修复密钥被写坏的问题（0.2.1）：
  - `wg genkey` 失败时直接报错，绝不写入伪密钥
  - 重置服务器不再停止容器，而是重新生成真实密钥并立即恢复运行
  - 启动/接管容器时自动检测并修复被写坏的密钥
  - 写入配置前校验密钥格式，非法密钥直接拒绝
  - 修复并发请求导致的状态文件写入冲突（加锁）
