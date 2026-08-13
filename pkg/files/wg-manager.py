#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fn-wg-web - WireGuard 可视化 Web 管理服务（纯 Python 标准库实现）

运行模式（按优先级自动检测）：
  1. container   已部署 linuxserver/wireguard 容器（docker exec 管理）
  2. native      系统原生 wireguard-tools（wg / wg-quick）
  3. not_deployed docker 可用但容器未部署（前端显示部署向导）
  4. mock        无任何依赖（本机演示/联调）

功能：
  - 自动部署 linuxserver/wireguard:latest 容器，目录映射由用户选填
  - 服务器配置：公网 IP/域名(Endpoint)、UDP 端口(默认 51820)、内网网段 INTERNAL_SUBNET
  - 客户端管理：创建/删除客户端、自动分配内网 IP、生成客户端配置（文本 + 二维码）
  - 实时状态：容器/接口状态、各客户端最新握手时间与传输流量
"""
import argparse
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

VERSION = "0.3.9"

# 状态文件写入锁（并发请求下防止 tmp 文件竞争）
_state_lock = threading.Lock()

# 登录失败计数（IP 维度速率限制，Bug 8）
_login_failures = {}
_LOGIN_WINDOW = 300        # 5 分钟窗口
_LOGIN_MAX_FAILS = 5       # 窗口内最多失败次数
_LOGIN_LOCK_SECONDS = 300  # 触发后锁定时长

# 会话默认参数（Bug 3）
SESSION_TTL = 7 * 24 * 3600   # 7 天过期
MAX_BODY = 10 * 1024 * 1024   # 10MB 请求体上限（Bug 14）

# CSRF：受保护方法（Bug 1）
_CSRF_METHODS = ("POST", "PUT", "DELETE", "PATCH")


class _BodyTooLarge(Exception):
    """请求体超过 MAX_BODY 限制（Bug 14）。"""
    pass

# ---------------------------------------------------------------------------
# 路径与环境（对齐 fnOS 官方 resource / 环境变量规范）
# ---------------------------------------------------------------------------
# 完整 TRIM_* 官方目录与优先级（fnOS 安装后 /var/apps/<appname> 下的软链）：
#   target/  → TRIM_APPDEST   程序文件   /vol[x]/@appcenter/<appname>
#   etc/     → TRIM_PKGETC    静态配置   /vol[x]/@appconf/<appname>
#   var/     → TRIM_PKGVAR    运行时数据 /vol[x]/@appdata/<appname>
#   home/    → TRIM_PKGHOME   用户数据   /vol[x]/@apphome/<appname>
#   tmp/     → TRIM_PKGTMP    临时文件   /vol[x]/@apptemp/<appname>
#   meta/    → TRIM_PKGMETA   元数据     /vol[x]/@appmeta/<appname>
# 其他常用信息变量：
#   TRIM_APPNAME / TRIM_APPVER  来自 manifest 的应用名/版本
#   TRIM_SERVICE_PORT           manifest 中声明的服务端口
#   TRIM_TEMP_LOGFILE           生命周期脚本临时日志
#
# 目录策略：
#   BASE_DIR  程序文件目录    WG_WEB_BASE → TRIM_APPDEST → /usr/fn-wg-web（旧/本地）
#   ETC_DIR   静态配置目录    WG_ETC_BASE  → TRIM_PKGETC → DATA_DIR/etc（回退）
#   DATA_DIR  运行时数据目录  WG_DATA_BASE → TRIM_PKGVAR → BASE_DIR（本地回退）
#   LOG_FILE  运行日志        WG_LOG_FILE  → DATA_DIR/fn-wg-web.log → /var/log/fn-wg-web.log（兼容）
BASE_DIR = (
    os.environ.get("WG_WEB_BASE")
    or os.environ.get("TRIM_APPDEST")
    or "/usr/fn-wg-web"
)
DATA_DIR = (
    os.environ.get("WG_DATA_BASE")
    or os.environ.get("TRIM_PKGVAR")
    or BASE_DIR
)
ETC_DIR = (
    os.environ.get("WG_ETC_BASE")
    or os.environ.get("TRIM_PKGETC")
    or os.path.join(DATA_DIR, "etc")
)
APP_NAME = os.environ.get("TRIM_APPNAME", "fn-wg-web")
APP_VER = os.environ.get("TRIM_APPVER") or VERSION or "0.0.0"

# Native 模式 wireguard 系统配置目录（不属于应用目录，系统级固定路径）
SYS_WG_CONF_DIR = "/etc/wireguard"
CONF_FILE = os.path.join(SYS_WG_CONF_DIR, "wg0.conf")

STATE_FILE = os.path.join(DATA_DIR, "state.json")
WEB_DIR = os.path.join(BASE_DIR, "web")
LOG_FILE = (
    os.environ.get("WG_LOG_FILE")
    or os.path.join(DATA_DIR, "fn-wg-web.log")
)

CONTAINER_NAME = os.environ.get("WG_CONTAINER_NAME", "wireguard")
CONTAINER_IMAGE = os.environ.get("WG_CONTAINER_IMAGE", "linuxserver/wireguard:latest")

DEFAULT_PORT = 51820
DEFAULT_SUBNET = "10.13.13.0/24"
DEFAULT_DNS = "1.1.1.1, 8.8.8.8"
DEFAULT_KEEPALIVE = 25
DEFAULT_CONFIG_DIR = "/vol1/docker/wireguard"

# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------

def log(msg):
    line = "%s  %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg)
    try:
        # errors="replace" 防止子进程输出中混入非 UTF-8 字节导致日志丢失（Bug 15）
        with open(LOG_FILE, "a", encoding="utf-8", errors="replace") as f:
            f.write(line + "\n")
    except Exception:
        pass
    print(line, flush=True)


def run_cmd(args, timeout=15, input_data=None):
    """执行命令，返回 (ok, stdout, stderr)。"""
    try:
        p = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout, input=input_data
        )
        return p.returncode == 0, p.stdout.strip(), p.stderr.strip()
    except FileNotFoundError:
        return False, "", "command not found: %s" % args[0]
    except subprocess.TimeoutExpired:
        return False, "", "timeout: %s" % " ".join(args)
    except Exception as e:  # noqa: BLE001
        return False, "", str(e)


def which(bin_name):
    return shutil.which(bin_name)


def docker_available():
    return which("docker") is not None


def container_exists(name=CONTAINER_NAME):
    if not docker_available():
        return False
    ok, out, _ = run_cmd(
        ["docker", "ps", "-a", "--format", "{{.Names}}"], timeout=8
    )
    return ok and name in (out or "").split()


def container_running(name=CONTAINER_NAME):
    if not container_exists(name):
        return False
    ok, out, _ = run_cmd(
        ["docker", "inspect", "-f", "{{.State.Status}}", name], timeout=8
    )
    return ok and out == "running"


def container_config_dir(name=CONTAINER_NAME):
    """从容器挂载信息解析 /config 的宿主目录。"""
    ok, out, _ = run_cmd(
        ["docker", "inspect", "-f", "{{json .Mounts}}", name], timeout=8
    )
    if not ok or not out:
        return ""
    try:
        mounts = json.loads(out)
        for m in mounts:
            if m.get("Destination") == "/config":
                return m.get("Source", "")
    except Exception:
        pass
    return ""


def get_mode():
    """运行模式判定。"""
    if container_exists():
        return "container"
    if which("wg"):
        return "native"
    if docker_available():
        return "not_deployed"
    return "mock"


def is_mock():
    return get_mode() == "mock"


# ---------------------------------------------------------------------------
# 密钥生成（容器模式走 docker exec，原生走 wg，否则伪密钥）
# ---------------------------------------------------------------------------

def wg_exec(args, stdin=None, timeout=8):
    """执行 wg 相关命令，容器模式自动包装 docker exec。"""
    if get_mode() == "container":
        cmd = ["docker", "exec"]
        if stdin is not None:
            cmd.append("-i")
        cmd.append(CONTAINER_NAME)
        cmd.extend(args)
        return run_cmd(cmd, timeout=timeout, input_data=stdin)
    return run_cmd(args, timeout=timeout, input_data=stdin)


def is_valid_key(k):
    """校验 WireGuard 私钥/公钥格式：44 字符 base64，且非 MOCK 伪密钥。"""
    return bool(k) and not k.startswith("MOCK") and len(k) == 44


def gen_key():
    """生成 WireGuard 密钥。演示模式（无任何环境）返回伪密钥；生产模式失败时抛异常。"""
    if get_mode() == "mock":
        return "MOCK%s" % (uuid.uuid4().hex + uuid.uuid4().hex)[:38]
    ok, out, _ = wg_exec(["wg", "genkey"])
    if ok and out and is_valid_key(out):
        return out
    raise RuntimeError(
        "无法生成 WireGuard 密钥（wg genkey 失败）。请确认 WireGuard 容器正在运行"
        "或系统已安装 wireguard-tools。"
    )


def derive_pub(priv):
    """由私钥推导公钥。演示模式返回伪公钥；生产模式失败时抛异常。"""
    if get_mode() == "mock":
        if priv.startswith("MOCK"):
            return "PUB%s" % priv[4:42]
        return "PUB%s" % (priv or "0" * 38)
    if not is_valid_key(priv):
        raise RuntimeError("服务器私钥无效，无法推导公钥，请重置服务器后重新初始化")
    ok, out, _ = wg_exec(["wg", "pubkey"], stdin=priv)
    if ok and out and is_valid_key(out):
        return out
    raise RuntimeError("无法推导服务器公钥（wg pubkey 失败），请确认 WireGuard 环境正常")


def detect_wan_iface():
    """检测默认路由出口网卡（原生模式 NAT 规则用）。"""
    ok, out, _ = run_cmd(["ip", "route", "show", "default"], timeout=5)
    if ok:
        m = re.search(r"dev\s+(\S+)", out)
        if m:
            return m.group(1)
    for cand in ("eth0", "enp2s0", "enp3s0", "br0", "lan0"):
        if os.path.exists("/sys/class/net/%s" % cand):
            return cand
    return "eth0"


# ---------------------------------------------------------------------------
# 状态持久化
# ---------------------------------------------------------------------------

DEFAULT_STATE = {
    "settings": {
        "endpoint": "",
        "port": DEFAULT_PORT,
        "subnet": DEFAULT_SUBNET,
        "dns": DEFAULT_DNS,
        "keepalive": DEFAULT_KEEPALIVE,
        "mtu": 1280,
        "nat": True,
        "wan_iface": "auto",
    },
    "server_private_key": "",
    "server_public_key": "",
    "server_ip": "",
    "peers": [],
    "config_dirty": False,
    "container": {
        "name": CONTAINER_NAME,
        "config_dir": "",
        "deployed": False,
    },
    "auth": {
        "enabled": False,
        "password_hash": "",
        "salt": "",
        # Bug 3：多会话令牌列表，每项 {token_hash, created_at, last_used, ua}
        "sessions": [],
    },
}


def _safe_migrate_file(src, dst):
    """
    无损迁移+清理单个文件（Python 侧与 shell 侧 _safe_migrate_file 同构）。
    三步：1) 目标不存在才 copy2；2) 校验 src/dst 都存在、dst 非空、字节数一致；
          3) 校验通过才删除 src 原件，绝不盲删。
    返回 True 表示执行了「复制→校验→删除源」全部流程（即迁移并清理成功）。
    """
    try:
        if not os.path.isfile(src):
            return False
        # Step 1: 复制（仅当目标不存在）
        if not os.path.exists(dst):
            os.makedirs(os.path.dirname(dst) or ".", exist_ok=True)
            import shutil
            shutil.copy2(src, dst)
        # Step 2: 校验
        if not (os.path.isfile(src) and os.path.isfile(dst)):
            return False
        ss = os.path.getsize(src)
        ds = os.path.getsize(dst)
        if ds <= 0 or ss != ds:
            return False
        # Step 3: 删除 src 原件（仅单文件）
        try:
            os.remove(src)
        except Exception:
            return False
        # 再次确认 src 不存在，才算清理成功
        return not os.path.exists(src)
    except Exception:
        return False


def _migrate_legacy_data_on_startup():
    """
    无损升级：Python 进程内最后一层迁移兜底（与 install_callback/upgrade_callback/main 同构）。
    每类迁移执行【复制（仅目标不存在）→ 校验目标非空且字节数等于源 → 删除原件】三步；
    目录仅用非递归 os.rmdir 清理完全空的壳；不保留未识别的文件在 LEGACY_DIR 里（只删已确认迁移的）。
    """
    LEGACY_DIR = "/usr/fn-wg-web"
    LEGACY_BACKUP = os.path.join(DATA_DIR, "legacy-backup")
    cleaned_any = False

    # 1) state.json
    legacy_state = os.path.join(LEGACY_DIR, "state.json")
    if os.path.isfile(legacy_state):
        if os.path.isfile(STATE_FILE):
            # state.json 已在持久卷；尺寸一致时删旧副本
            try:
                ss = os.path.getsize(legacy_state)
                ds = os.path.getsize(STATE_FILE)
                if ds > 0 and ss == ds:
                    try:
                        os.remove(legacy_state)
                        if not os.path.exists(legacy_state):
                            log("启动迁移兜底：已清理与持久卷一致的旧 state.json (%s, %dB)" % (legacy_state, ds))
                            cleaned_any = True
                    except Exception:
                        pass
            except Exception:
                pass
        else:
            if _safe_migrate_file(legacy_state, STATE_FILE):
                log("启动迁移兜底：state.json 已迁移并清理原件 %s → %s" % (legacy_state, STATE_FILE))
                cleaned_any = True

    # 2) 旧日志 /var/log/fn-wg-web.log* → DATA_DIR
    var_log = "/var/log"
    if os.path.isdir(var_log):
        try:
            for name in os.listdir(var_log):
                if name == "fn-wg-web.log" or name.startswith("fn-wg-web.log."):
                    src = os.path.join(var_log, name)
                    dst = os.path.join(DATA_DIR, name)
                    if _safe_migrate_file(src, dst):
                        log("启动迁移兜底：旧日志已迁移并清理原件 %s → %s" % (src, dst))
                        cleaned_any = True
        except Exception:
            pass

    # 3) LEGACY_DIR/etc → ETC_DIR（逐文件；迁完自底向上清理空目录壳）
    legacy_etc = os.path.join(LEGACY_DIR, "etc")
    if os.path.isdir(legacy_etc):
        files_touched = []
        for root, _dirs, files in os.walk(legacy_etc):
            for f in files:
                src = os.path.join(root, f)
                rel = os.path.relpath(src, legacy_etc)
                dst = os.path.join(ETC_DIR, rel)
                if _safe_migrate_file(src, dst):
                    log("启动迁移兜底：静态配置已迁移并清理原件 %s → %s" % (src, dst))
                    cleaned_any = True
                    files_touched.append(src)
        # 自底向上 rmdir 清理 legacy_etc 下所有空目录
        try:
            for r, dirs, fs in os.walk(legacy_etc, topdown=False):
                for d in dirs:
                    p = os.path.join(r, d)
                    try:
                        os.rmdir(p)
                    except Exception:
                        pass
            try:
                os.rmdir(legacy_etc)
            except Exception:
                pass
        except Exception:
            pass

    # 4) LEGACY_DIR 下散落的 *.json/*.conf → legacy-backup/（state.json 除外）
    if os.path.isdir(LEGACY_DIR):
        try:
            for name in os.listdir(LEGACY_DIR):
                if not (name.endswith(".json") or name.endswith(".conf")):
                    continue
                src = os.path.join(LEGACY_DIR, name)
                if not os.path.isfile(src):
                    continue
                os.makedirs(LEGACY_BACKUP, exist_ok=True)
                dst = os.path.join(LEGACY_BACKUP, name)
                if name == "state.json" and os.path.isfile(STATE_FILE):
                    continue  # state.json 已经主路径处理
                if _safe_migrate_file(src, dst):
                    log("启动迁移兜底：散落配置已备份并清理原件 %s → %s" % (src, dst))
                    cleaned_any = True
        except Exception:
            pass

    # 最后：LEGACY_DIR 若完全空 → 删除目录壳
    if os.path.isdir(LEGACY_DIR):
        try:
            # 自底向上 rmdir 清 LEGACY_DIR 的空子目录
            for r, dirs, fs in os.walk(LEGACY_DIR, topdown=False):
                for d in dirs:
                    p = os.path.join(r, d)
                    try:
                        os.rmdir(p)
                    except Exception:
                        pass
            try:
                os.rmdir(LEGACY_DIR)
                if not os.path.isdir(LEGACY_DIR):
                    log("启动迁移兜底：旧运行目录 %s 已空，已清理壳目录" % LEGACY_DIR)
                    cleaned_any = True
            except Exception:
                pass
        except Exception:
            pass

    return cleaned_any


def load_state():
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        for k, v in DEFAULT_STATE.items():
            if k not in data:
                data[k] = json.loads(json.dumps(v))
            elif isinstance(v, dict):
                for kk, vv in v.items():
                    data[k].setdefault(kk, vv)
        # Bug 3 兼容旧版：清理遗留的 session_token 字段
        a = data.get("auth", {})
        if "session_token" in a:
            a.pop("session_token", None)
        if "sessions" not in a:
            a["sessions"] = []
        return data
    except Exception:
        return json.loads(json.dumps(DEFAULT_STATE))


def save_state(state):
    os.makedirs(DATA_DIR, exist_ok=True)
    tmp = STATE_FILE + ".tmp"
    with _state_lock:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=False, indent=2)
        os.replace(tmp, STATE_FILE)


def is_initialized(state):
    return bool(state.get("server_private_key"))


# ---------------------------------------------------------------------------
# 密码认证
# ---------------------------------------------------------------------------

def hash_password(password, salt=None):
    """SHA-256 加盐哈希密码。"""
    if salt is None:
        salt = secrets.token_hex(16)
    h = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
    return h, salt


def verify_password(password, stored_hash, salt):
    """校验密码。"""
    h, _ = hash_password(password, salt)
    return secrets.compare_digest(h, stored_hash)


def hash_token(token):
    """会话令牌的哈希存储（避免 state.json 泄露后 token 仍可用，Bug 3）。"""
    return hashlib.sha256(b"wg-session-v1:" + token.encode("utf-8")).hexdigest()


def auth_enabled(state):
    """是否启用了密码认证。"""
    a = state.get("auth", {})
    return bool(a.get("enabled") and a.get("password_hash"))


def _gc_sessions(sessions, now=None):
    """清理过期会话（Bug 3：TTL 7 天）。返回清理后的列表。"""
    if now is None:
        now = int(time.time())
    kept = []
    for s in sessions or []:
        try:
            created = int(s.get("created_at") or 0)
            last_used = int(s.get("last_used") or created)
            if now - last_used > SESSION_TTL:
                continue  # 过期
            if now - created > SESSION_TTL * 4:
                continue  # 绝对寿命上限
        except Exception:
            continue
        kept.append(s)
    return kept


def check_auth(handler):
    """检查请求是否已认证。
    - 未设置密码 → 返回 False（强制进入设置流程）
    - 已设置密码但未启用认证 → 返回 True
    - 认证已启用 → 校验 Cookie 中的会话令牌是否在 sessions 列表中且未过期
    """
    state = load_state()
    a = state.get("auth", {})
    if not a.get("password_hash"):
        return False
    if not a.get("enabled"):
        return True
    token = ""
    cookie_header = handler.headers.get("Cookie", "")
    for part in cookie_header.split(";"):
        part = part.strip()
        if part.startswith("wg_token="):
            token = part[len("wg_token="):]
            break
    if not token:
        return False
    token_h = hash_token(token)
    sessions = a.get("sessions") or []
    now = int(time.time())
    sessions = _gc_sessions(sessions, now)
    matched = None
    for s in sessions:
        if s.get("token_hash") == token_h:
            matched = s
            break
    if not matched:
        return False
    # 更新最后使用时间（节流写盘：每 60s 写一次即可）
    if now - int(matched.get("last_used") or 0) > 60:
        matched["last_used"] = now
        try:
            save_state(state)
        except Exception:
            pass
    return True


def check_csrf(handler, allow_origin_only=False):
    """CSRF 校验（Bug 1）：
    - GET/HEAD/OPTIONS 不校验
    - 优先校验 X-CSRF-Token 头
    - 兜底校验 Origin/Referer 与 Host 同源
    - allow_origin_only=True：允许仅通过 Origin 同源通过（setup/login 等无会话场景）
    返回 True 表示通过。
    """
    if handler.command not in _CSRF_METHODS:
        return True
    # 1) 优先 X-CSRF-Token 头校验（前端登录后取得，存 localStorage）
    csrf = handler.headers.get("X-CSRF-Token", "")
    if csrf:
        state = load_state()
        for s in state.get("auth", {}).get("sessions") or []:
            if s.get("csrf_token") and secrets.compare_digest(csrf, s["csrf_token"]):
                return True
        if not allow_origin_only:
            return False
    # 2) 兜底：Origin / Referer 同源
    host = handler.headers.get("Host", "")
    origin = handler.headers.get("Origin", "") or handler.headers.get("Referer", "")
    if not host or not origin:
        return False
    try:
        from urllib.parse import urlparse as _up
        o = _up(origin)
        origin_authority = o.netloc.lower()  # host:port
        return secrets.compare_digest(origin_authority, host.lower())
    except Exception:
        return False


# 登录失败速率限制（Bug 8）
def _login_fail_key(handler):
    try:
        ip = handler.client_address[0]
    except Exception:
        ip = "unknown"
    return ip


def login_too_many_fails(handler):
    """是否已触发登录锁定。"""
    key = _login_fail_key(handler)
    rec = _login_failures.get(key)
    if not rec:
        return False
    now = time.time()
    fails = [t for t in rec["fails"] if now - t < _LOGIN_WINDOW]
    rec["fails"] = fails
    if not fails:
        _login_failures.pop(key, None)
        return False
    if len(fails) >= _LOGIN_MAX_FAILS:
        if now - rec.get("locked_at", 0) < _LOGIN_LOCK_SECONDS:
            return True
        # 锁定过期，清零
        _login_failures.pop(key, None)
        return False
    return False


def record_login_failure(handler):
    key = _login_fail_key(handler)
    now = time.time()
    rec = _login_failures.setdefault(key, {"fails": [], "locked_at": 0})
    rec["fails"].append(now)
    rec["fails"] = [t for t in rec["fails"] if now - t < _LOGIN_WINDOW]
    if len(rec["fails"]) >= _LOGIN_MAX_FAILS:
        rec["locked_at"] = now


def clear_login_failures(handler):
    _login_failures.pop(_login_fail_key(handler), None)


# ---------------------------------------------------------------------------
# 配置生成与应用
# ---------------------------------------------------------------------------

def ipaddress_ip_network(subnet):
    import ipaddress
    return ipaddress.ip_network(subnet, strict=False)


def ipaddress_ip_address(addr):
    import ipaddress
    return ipaddress.ip_address(addr)


def conf_path(state=None):
    """当前模式下 wg0.conf 的路径（优先使用传入的内存 state，避免依赖磁盘写入时序）。"""
    if get_mode() == "container":
        cfg = (state or load_state()).get("container", {}).get("config_dir", "")
        if cfg:
            return os.path.join(cfg, "wg_confs", "wg0.conf")
    return CONF_FILE


def build_wg0_conf(state):
    """生成 wg-quick 兼容的 wg0.conf 文本。"""
    s = state["settings"]
    net = ipaddress_ip_network(s["subnet"])
    server_ip = "%s/%s" % (str(net.network_address + 1), net.prefixlen)
    if get_mode() == "container":
        wan = "eth0"
    else:
        # Bug 11：尊重用户设置的出口网卡，"auto" 时再自动探测
        wan_cfg = (s.get("wan_iface") or "auto").strip()
        if wan_cfg and wan_cfg != "auto":
            wan = wan_cfg
        else:
            wan = detect_wan_iface()
    mtu = int(s.get("mtu") or 1280)
    lines = []
    lines.append("[Interface]")
    lines.append("PrivateKey = %s" % state["server_private_key"])
    lines.append("Address = %s" % server_ip)
    lines.append("ListenPort = %d" % int(s["port"]))
    lines.append("MTU = %d" % mtu)
    if s.get("nat", True):
        lines.append("PostUp = iptables -t nat -A POSTROUTING -s %s -o %s -j MASQUERADE" % (s["subnet"], wan))
        lines.append("PostUp = iptables -A FORWARD -i wg0 -j ACCEPT")
        lines.append("PostUp = iptables -A FORWARD -o wg0 -j ACCEPT")
        lines.append("PostDown = iptables -t nat -D POSTROUTING -s %s -o %s -j MASQUERADE" % (s["subnet"], wan))
        lines.append("PostDown = iptables -D FORWARD -i wg0 -j ACCEPT")
        lines.append("PostDown = iptables -D FORWARD -o wg0 -j ACCEPT")
    for peer in state["peers"]:
        if not peer.get("enabled", True):
            continue  # 已停用的客户端不写入配置
        lines.append("")
        lines.append("[Peer]")
        lines.append("# %s" % peer["name"])
        lines.append("PublicKey = %s" % peer["public_key"])
        lines.append("AllowedIPs = %s/32" % peer["ip"])
    lines.append("")
    return "\n".join(lines)


def write_conf(state):
    """写入 wg0.conf；写入前校验服务器私钥合法，防止 MOCK/非法密钥破坏容器。"""
    priv = state.get("server_private_key") or ""
    if get_mode() != "mock" and not is_valid_key(priv):
        raise RuntimeError("服务器私钥无效或缺失，无法写入配置。请重置服务器后重新初始化")
    path = conf_path(state)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(build_wg0_conf(state))
    return path


def iface_exists():
    if get_mode() == "container":
        ok, out, _ = wg_exec(["wg", "show", "interfaces"])
        return ok and "wg0" in (out or "")
    ok, out, _ = run_cmd(["ip", "link", "show", "wg0"], timeout=5)
    return ok


def enable_ip_forward():
    if get_mode() == "container":
        return
    run_cmd(["sysctl", "-w", "net.ipv4.ip_forward=1"], timeout=5)
    try:
        os.makedirs("/etc/sysctl.d", exist_ok=True)
        with open("/etc/sysctl.d/99-fn-wg-web.conf", "w", encoding="utf-8") as f:
            f.write("net.ipv4.ip_forward = 1\n")
    except Exception:
        pass


def apply_config(state):
    """写入 wg0.conf 并应用（容器模式重启容器 / 原生 syncconf / 无环境跳过）。"""
    if get_mode() == "mock":
        log("[mock] 跳过真实接口操作")
        return True, "mock mode: 未执行真实接口操作"
    try:
        write_conf(state)
    except RuntimeError as e:
        return False, str(e)
    if get_mode() == "container":
        if not container_running():
            ok, out, err = run_cmd(["docker", "start", CONTAINER_NAME], timeout=30)
            if not ok:
                return False, err or "容器启动失败"
            time.sleep(3)
            return True, "容器已启动"
        ok, out, err = run_cmd(["docker", "restart", CONTAINER_NAME], timeout=60)
        if not ok:
            return False, err or "容器重启失败"
        time.sleep(3)
        return True, "容器已重启，配置已生效"
    enable_ip_forward()
    if iface_exists():
        ok, out, err = run_cmd(
            ["bash", "-c", "wg syncconf wg0 <(wg-quick strip wg0)"], timeout=20
        )
        if ok:
            return True, "syncconf 已应用"
        ok2, out2, err2 = run_cmd(["wg", "setconf", "wg0", CONF_FILE], timeout=20)
        if ok2:
            return True, "setconf 已应用"
        return False, err2 or err or "应用配置失败"
    ok, out, err = run_cmd(["wg-quick", "up", "wg0"], timeout=30)
    if ok:
        return True, "接口已启动"
    return False, err or out or "wg-quick up 失败"


def stop_iface():
    if get_mode() == "container":
        run_cmd(["docker", "stop", CONTAINER_NAME], timeout=30)
        return True
    if get_mode() == "mock":
        return True
    run_cmd(["wg-quick", "down", "wg0"], timeout=20)
    return True


# ---------------------------------------------------------------------------
# 容器部署
# ---------------------------------------------------------------------------

def build_docker_cmd(state, config_dir):
    """构建 docker run 命令。"""
    s = state["settings"]
    subnet = ipaddress_ip_network(s["subnet"])
    # linuxserver/wireguard 镜像 INTERNAL_SUBNET 预期完整 CIDR（如 10.13.13.0/24）
    internal_subnet = str(subnet)
    endpoint = (s.get("endpoint") or "").strip() or "auto"
    dns = (s.get("dns") or "").strip() or "auto"
    keepalive = int(s.get("keepalive") or DEFAULT_KEEPALIVE)
    port = int(s.get("port") or DEFAULT_PORT)
    cmd = [
        "docker", "run", "-d",
        "--name", CONTAINER_NAME,
        "--cap-add=NET_ADMIN",
        "--cap-add=SYS_MODULE",
        "-e", "PUID=0",
        "-e", "PGID=0",
        "-e", "TZ=%s" % (os.environ.get("TZ", "Asia/Shanghai")),
        "-e", "SERVERURL=%s" % endpoint,
        "-e", "SERVERPORT=%d" % port,
        "-e", "PEERS=0",
        "-e", "PEERDNS=%s" % dns,
        "-e", "INTERNAL_SUBNET=%s" % internal_subnet,
        "-e", "ALLOWEDIPS=0.0.0.0/0, ::/0",
        "-e", "PERSISTENTKEEPALIVE_PEERS=",
        "-e", "LOG_CONFS=false",
        "-p", "%d:51820/udp" % port,
        "-v", "%s:/config" % config_dir,
        "-v", "/lib/modules:/lib/modules:ro",
        "--sysctl", "net.ipv4.conf.all.src_valid_mark=1",
        "--sysctl", "net.ipv4.ip_forward=1",
        "--restart", "unless-stopped",
        CONTAINER_IMAGE,
    ]
    return cmd


def read_conf_private_key(path):
    """从 wg0.conf 解析 PrivateKey。"""
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.startswith("PrivateKey"):
                    return line.split("=", 1)[1].strip()
    except Exception:
        pass
    return ""


def deploy_container(state, config_dir, pull=True):
    """部署 linuxserver/wireguard 容器（先部署容器，容器就绪后再生成密钥）。"""
    if not docker_available():
        raise RuntimeError("未检测到 docker，请确认 fnOS 已启用 Docker 服务")
    config_dir = (config_dir or "").strip() or DEFAULT_CONFIG_DIR
    if config_dir.endswith("/"):
        config_dir = config_dir[:-1]
    if os.path.exists(config_dir) and not os.path.isdir(config_dir):
        raise RuntimeError("配置目录路径无效，请更换目录")
    if container_exists():
        raise RuntimeError("容器 %s 已存在，如需重新部署请先移除" % CONTAINER_NAME)

    # ---- 第一步：部署 Docker 容器（不涉及密钥） ----
    # 1. 创建配置目录（容器挂载需要，仅建目录不写配置）
    #    容忍创建失败：宿主机路径不可达/无权限时，docker 挂载会自动创建
    try:
        os.makedirs(os.path.join(config_dir, "wg_confs"), exist_ok=True)
    except OSError as e:
        log("配置目录创建由 docker 接管（%s）：%s" % (config_dir, e))
    state["container"]["config_dir"] = config_dir
    state["container"]["deployed"] = False
    save_state(state)

    # 2. 拉取镜像（可选）
    if pull:
        log("拉取镜像 %s ..." % CONTAINER_IMAGE)
        ok, out, err = run_cmd(["docker", "pull", CONTAINER_IMAGE], timeout=600)
        if not ok:
            raise RuntimeError("镜像拉取失败：%s" % (err or out or "网络异常"))

    # 3. 创建容器
    cmd = build_docker_cmd(state, config_dir)
    ok, out, err = run_cmd(cmd, timeout=120)
    if not ok:
        raise RuntimeError("容器创建失败：%s" % (err or out or "docker run 失败"))

    # 4. 等待容器就绪
    for _ in range(10):
        time.sleep(1)
        if container_running():
            break
    if not container_running():
        ok, logs, _ = run_cmd(["docker", "logs", "--tail", "30", CONTAINER_NAME], timeout=8)
        raise RuntimeError("容器未正常运行，最近日志：%s" % (logs or "无"))
    log("Docker 容器已就绪: %s" % CONTAINER_NAME)

    # ---- 第二步：容器安装完成后生成/同步密钥 ----
    # 5. 若容器已自动生成 wg0.conf（镜像 server 模式行为），直接接管其密钥
    actual_conf = os.path.join(config_dir, "wg_confs", "wg0.conf")
    actual_priv = read_conf_private_key(actual_conf)
    if actual_priv and is_valid_key(actual_priv):
        log("接管容器已生成的服务器密钥")
        state["server_private_key"] = actual_priv
        state["server_public_key"] = derive_pub(actual_priv)
    elif is_valid_key(state.get("server_private_key")):
        # 6. 升级/重装场景：state 已保存有效密钥 → 复用，保证客户端配置继续有效
        log("复用已保存的服务器密钥（升级/重装保留配置）")
    else:
        # 7. 全新部署：由应用生成密钥并写入 wg0.conf，重启容器生效
        log("生成新的服务器密钥...")
        state["server_private_key"] = gen_key()
        state["server_public_key"] = derive_pub(state["server_private_key"])
    net = ipaddress_ip_network(state["settings"]["subnet"])
    state["server_ip"] = str(net.network_address + 1)
    state["config_dirty"] = True
    save_state(state)
    # 7. 写入完整 wg0.conf（含服务器密钥与现有 [Peer] 段）并应用
    ok, msg = apply_config(state)
    if not ok:
        raise RuntimeError("写入服务器配置失败：%s" % msg)
    state["container"]["deployed"] = True
    state["config_dirty"] = False
    save_state(state)
    log("密钥生成完成，配置已应用到容器: %s (config=%s)" % (CONTAINER_NAME, config_dir))
    return config_dir


def remove_container(state):
    """移除容器（保留 config_dir 数据）。"""
    if container_exists():
        run_cmd(["docker", "rm", "-f", CONTAINER_NAME], timeout=60)
    state["container"]["deployed"] = False
    save_state(state)
    log("容器已移除（配置数据保留在映射目录）")


def restart_container():
    if not container_exists():
        raise RuntimeError("容器不存在")
    ok, out, err = run_cmd(["docker", "restart", CONTAINER_NAME], timeout=60)
    if not ok:
        raise RuntimeError("容器重启失败：%s" % (err or out))
    time.sleep(2)
    return True


# ---------------------------------------------------------------------------
# 客户端管理
# ---------------------------------------------------------------------------

def next_client_ip(net, peers):
    """从网段第 2 个地址开始分配未占用的 IP。"""
    base = net.network_address + 1  # 服务器
    used = set()
    for p in peers:
        try:
            used.add(int(ipaddress_ip_address(p["ip"])))
        except Exception:
            pass
    idx = 1
    while True:
        candidate = base + idx
        if candidate >= net.broadcast_address:
            raise RuntimeError("网段地址已用尽")
        if int(candidate) not in used:
            return str(candidate)
        idx += 1


def build_client_config(state, peer):
    """生成客户端配置；路由由 peer 的 route 字段决定（full=全量 / split=分流）。"""
    s = state["settings"]
    endpoint = (s.get("endpoint") or "").strip()
    host = endpoint or "YOUR_SERVER_IP_OR_DOMAIN"
    port = int(s.get("port") or DEFAULT_PORT)
    route = peer.get("route") or {}
    if route.get("mode") == "split" and route.get("cidr"):
        allowed = route["cidr"]
    else:
        allowed = "0.0.0.0/0, ::/0"
    lines = []
    lines.append("[Interface]")
    lines.append("PrivateKey = %s" % peer["private_key"])
    lines.append("Address = %s/%s" % (peer["ip"], ipaddress_ip_network(s["subnet"]).prefixlen))
    mtu = int(s.get("mtu") or 1280)
    if mtu > 0:
        lines.append("MTU = %d" % mtu)
    dns = (s.get("dns") or "").strip()
    if dns:
        lines.append("DNS = %s" % dns)
    lines.append("")
    lines.append("[Peer]")
    lines.append("PublicKey = %s" % state["server_public_key"])
    lines.append("Endpoint = %s:%d" % (host, port))
    lines.append("AllowedIPs = %s" % allowed)
    lines.append("PersistentKeepalive = %d" % int(s.get("keepalive") or DEFAULT_KEEPALIVE))
    lines.append("")
    return "\n".join(lines)


def _alloc_peer(state, name, route=None):
    """内部辅助：在内存中分配一个客户端（不写盘、不应用）。

    供单次与批量创建共用：避免批量创建时每个客户端都触发一次容器重启。
    返回 (peer, error)，name 重复等校验失败时 peer 为 None 且 error 非空。
    """
    name = (name or "").strip()
    if not name:
        return None, "客户端名称不能为空"
    if len(name) > 32:
        return None, "客户端名称过长（最多 32 字符）"
    for p in state["peers"]:
        if p["name"] == name:
            return None, "客户端名称已存在"
    try:
        priv = gen_key()
        pub = derive_pub(priv)
    except RuntimeError as e:
        return None, str(e)
    net = ipaddress_ip_network(state["settings"]["subnet"])
    ip = next_client_ip(net, state["peers"])
    peer = {
        "id": uuid.uuid4().hex[:12],
        "name": name,
        "public_key": pub,
        "private_key": priv,
        "ip": ip,
        "created_at": int(time.time()),
        "enabled": True,
        "route": route or {"mode": "full", "cidr": ""},
    }
    return peer, None


def create_peer(state, name, route=None):
    """创建单个客户端并立即应用（容器重启生效）。"""
    peer, err = _alloc_peer(state, name, route)
    if err:
        raise ValueError(err)
    state["peers"].append(peer)
    save_state(state)
    ok, msg = apply_config(state)
    if ok:
        state["config_dirty"] = False
        save_state(state)
    return peer, ok, msg


def batch_create_peers(state, count, name_prefix, route=None):
    """批量生成客户端；一次性写入配置并应用，避免逐个重启容器。
    返回 (created, errors)，errors 为 [(name, msg), ...] 形式的失败明细（Bug 5）。
    """
    count = int(count or 1)
    if count < 1 or count > 50:
        raise ValueError("批量数量必须在 1-50 之间")
    name_prefix = (name_prefix or "").strip() or "client"
    if len(name_prefix) > 20:
        raise ValueError("名称前缀过长（最多 20 字符）")
    created = []
    errors = []  # Bug 5：记录每个失败明细
    for i in range(count):
        name = "%s-%02d" % (name_prefix, i + 1)
        peer, err = _alloc_peer(state, name, route)
        if err:
            errors.append((name, err))
            continue  # 继续尝试后续，不静默 break
        state["peers"].append(peer)
        created.append(peer)
    if created:
        save_state(state)
        # 批量创建仅在最后统一应用一次，避免逐个 docker restart
        ok, msg = apply_config(state)
        if ok:
            state["config_dirty"] = False
            save_state(state)
        log("批量创建 %d 个客户端（失败 %d 个）并应用：%s" % (
            len(created), len(errors), "成功" if ok else msg))
    return created, errors


def delete_peer(state, peer_id):
    peer = next((p for p in state["peers"] if p["id"] == peer_id), None)
    if not peer:
        raise ValueError("客户端不存在")
    state["peers"] = [p for p in state["peers"] if p["id"] != peer_id]
    save_state(state)
    ok, msg = apply_config(state)
    if ok:
        state["config_dirty"] = False
        save_state(state)
    return peer, ok, msg


def rename_peer(state, peer_id, new_name):
    """重命名客户端（仅修改名称，不涉及密钥/IP，无需重启容器）。"""
    new_name = (new_name or "").strip()
    if not new_name:
        raise ValueError("客户端名称不能为空")
    if len(new_name) > 32:
        raise ValueError("客户端名称过长（最多 32 字符）")
    peer = next((p for p in state["peers"] if p["id"] == peer_id), None)
    if not peer:
        raise ValueError("客户端不存在")
    for p in state["peers"]:
        if p["id"] != peer_id and p["name"] == new_name:
            raise ValueError("客户端名称已存在")
    old_name = peer["name"]
    peer["name"] = new_name
    save_state(state)
    return peer, old_name


def toggle_peer(state, peer_id):
    """切换客户端启用/停用状态（停用的客户端从 wg0.conf 中移除，重启容器生效）。"""
    peer = next((p for p in state["peers"] if p["id"] == peer_id), None)
    if not peer:
        raise ValueError("客户端不存在")
    peer["enabled"] = not peer.get("enabled", True)
    save_state(state)
    ok, msg = apply_config(state)
    if ok:
        state["config_dirty"] = False
        save_state(state)
    return peer, ok, msg


# ---------------------------------------------------------------------------
# 实时状态
# ---------------------------------------------------------------------------

def read_wg_dump():
    """解析 `wg show wg0 dump`，返回 {public_key: {...}}。

    dump 输出格式（tab 分隔）：
      接口行 4 列:  private_key  public_key  listen_port  fwmark
      peer 行 8 列:  public_key  preshared_key  endpoint  allowed_ips
                     latest_handshake  rx_bytes  tx_bytes  persistent_keepalive
    注意 peer 行第一个字段就是公钥本身，没有 "peer" 前缀标记。
    """
    ok, out, _ = wg_exec(["wg", "show", "wg0", "dump"])
    peers = {}
    if not ok:
        return peers
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) < 8:
            continue  # 接口行只有 4 列，跳过
        pub = parts[0]
        if not is_valid_key(pub):
            continue
        endpoint = parts[2]
        if endpoint in ("(none)", "(null)", ""):
            endpoint = ""
        peers[pub] = {
            "endpoint": endpoint,
            "allowed_ips": parts[3],
            "handshake": parts[4],
            "rx": parts[5],
            "tx": parts[6],
        }
    return peers


def fmt_bytes(v):
    try:
        n = float(v)
    except (TypeError, ValueError):
        return "0 B"
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    i = 0
    while n >= 1024 and i < len(units) - 1:
        n /= 1024.0
        i += 1
    if i == 0:
        return "%d B" % int(n)
    return "%.1f %s" % (n, units[i])


def fmt_handshake(ts, now):
    try:
        ts = int(ts)
    except (TypeError, ValueError):
        return "从未"
    if ts <= 0:
        return "从未"
    d = now - ts
    if d < 0:
        return "刚刚"
    if d < 60:
        return "%d 秒前" % d
    if d < 3600:
        return "%d 分钟前" % (d // 60)
    if d < 86400:
        return "%d 小时前" % (d // 3600)
    return "%d 天前" % (d // 86400)


def collect_peers_status(state):
    dump = read_wg_dump()
    now = int(time.time())
    result = []
    for p in state["peers"]:
        live = dump.get(p["public_key"], {})
        handshake = fmt_handshake(live.get("handshake", 0), now)
        online = bool(live.get("handshake")) and (now - int(live.get("handshake", 0) or 0) < 180)
        result.append({
            "id": p["id"],
            "name": p["name"],
            "ip": p["ip"],
            "public_key": p["public_key"],
            "created_at": p["created_at"],
            "enabled": p.get("enabled", True),
            "route": p.get("route") or {"mode": "full", "cidr": ""},
            "endpoint": live.get("endpoint", ""),
            "handshake": handshake,
            "online": online,
            "rx": fmt_bytes(live.get("rx", 0)),
            "tx": fmt_bytes(live.get("tx", 0)),
        })
    return result


# ---------------------------------------------------------------------------
# HTTP 服务
# ---------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    server_version = "fn-wg-web/" + VERSION

    # ---- 辅助 ----
    def _json(self, obj, code=200, headers=None):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if headers:
            for k, v in headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        # Bug 14：拒绝过大的请求体，防止内存耗尽
        if length > MAX_BODY:
            self._json({"ok": False, "error": "请求体过大（>%d MB）" % (MAX_BODY // (1024 * 1024))}, 413)
            raise _BodyTooLarge()  # 由 do_POST/PUT/DELETE 统一捕获
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except Exception:
            return {}

    def _bad(self, msg):
        self._json({"ok": False, "error": msg}, 400)

    # ---- 路由 ----
    def do_GET(self):
        try:
            return self._do_get_safe()
        except Exception as e:
            log("do_GET 异常: %s %s" % (self.path, e))
            try:
                self._json({"ok": False, "error": "服务器内部错误"}, 500)
            except Exception:
                pass

    def _do_get_safe(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"

        # 无需认证的 API 路由
        if path == "/api/auth/status":
            return self.api_auth_status()

        # 认证检查：启用认证且未登录时，所有请求（含静态文件、内网访问）均需认证
        if not check_auth(self):
            # API 请求 → 返回 401 JSON（前端 fetch 可识别）
            if path.startswith("/api/"):
                self._json({"ok": False, "error": "未登录", "need_auth": True}, 401)
                return
            # 非API请求 → 返回自包含登录页（不暴露完整应用界面）
            return self.serve_login_page()

        # 已认证 → 正常路由
        if path == "/" or path == "/index.html" or path == "/index.cgi":
            return self.serve_file("index.html", "text/html; charset=utf-8")
        if path == "/favicon.ico":
            self.send_response(204)
            self.end_headers()
            return
        if path == "/style.css":
            return self.serve_file("style.css", "text/css; charset=utf-8")
        if path == "/app.js":
            return self.serve_file("app.js", "application/javascript; charset=utf-8")
        if path == "/qrcode.min.js":
            return self.serve_file("qrcode.min.js", "application/javascript; charset=utf-8")
        if path == "/api/status":
            return self.api_status()
        if path == "/api/peers":
            return self.api_peers_list()
        if path == "/api/config/export":
            return self.api_config_export()
        m = re.match(r"^/api/peers/([0-9a-f]+)/config$", path)
        if m:
            return self.api_peer_config(m.group(1))
        m = re.match(r"^/api/peers/([0-9a-f]+)$", path)
        if m:
            return self.api_peer_get(m.group(1))
        # 兜底：图标/未知路径统一返回管理首页（避免 iframe 显示 JSON 404）
        return self.serve_file("index.html", "text/html; charset=utf-8")

    def do_POST(self):
        try:
            return self._route_post()
        except _BodyTooLarge:
            return  # 已发送 413 响应
        except Exception as e:
            log("do_POST 异常: %s %s" % (self.path, e))
            try:
                self._json({"ok": False, "error": "服务器内部错误"}, 500)
            except Exception:
                pass

    def _route_post(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        # 无需认证的路由（setup/login 等无会话场景使用 allow_origin_only 宽松 CSRF，避免死锁）
        if path == "/api/auth/setup":
            if not check_csrf(self, allow_origin_only=True):
                self._json({"ok": False, "error": "CSRF 校验失败"}, 403)
                return
            return self.api_auth_setup()
        if path == "/api/auth/login":
            if not check_csrf(self, allow_origin_only=True):
                self._json({"ok": False, "error": "CSRF 校验失败"}, 403)
                return
            return self.api_auth_login()

        # 以下路由需要认证
        if not check_auth(self):
            self._json({"ok": False, "error": "未登录", "need_auth": True}, 401)
            return
        # Bug 1：所有状态变更接口必须通过 CSRF 校验
        if not check_csrf(self):
            self._json({"ok": False, "error": "CSRF 校验失败"}, 403)
            return

        # Bug 2：logout 移到需要认证组（不再允许未认证调用 → DoS 管理员）
        if path == "/api/auth/logout":
            return self.api_auth_logout()
        if path == "/api/auth/disable":
            return self.api_auth_disable()

        if path == "/api/init":
            return self.api_init()
        if path == "/api/settings":
            return self.api_settings()
        if path == "/api/apply":
            return self.api_apply()
        if path == "/api/peers":
            return self.api_peer_create()
        if path == "/api/peers/batch":
            return self.api_peer_batch()
        if path == "/api/container/deploy":
            return self.api_container_deploy()
        if path == "/api/container/remove":
            return self.api_container_remove()
        if path == "/api/container/destroy":
            return self.api_container_destroy()
        if path == "/api/container/restart":
            return self.api_container_restart()
        if path == "/api/reset":
            return self.api_reset()
        if path == "/api/config/import":
            return self.api_config_import()
        if path == "/api/peers/toggle":
            return self.api_peer_toggle()
        self._json({"ok": False, "error": "not found"}, 404)

    def do_PUT(self):
        try:
            parsed = urlparse(self.path)
            path = parsed.path.rstrip("/")
            if not check_auth(self):
                self._json({"ok": False, "error": "未登录", "need_auth": True}, 401)
                return
            if not check_csrf(self):
                self._json({"ok": False, "error": "CSRF 校验失败"}, 403)
                return
            m = re.match(r"^/api/peers/([0-9a-f]+)$", path)
            if m:
                return self.api_peer_rename(m.group(1))
            self._json({"ok": False, "error": "not found"}, 404)
        except _BodyTooLarge:
            return
        except Exception as e:
            log("do_PUT 异常: %s %s" % (self.path, e))
            try:
                self._json({"ok": False, "error": "服务器内部错误"}, 500)
            except Exception:
                pass

    def do_DELETE(self):
        try:
            parsed = urlparse(self.path)
            path = parsed.path.rstrip("/")
            if not check_auth(self):
                self._json({"ok": False, "error": "未登录", "need_auth": True}, 401)
                return
            if not check_csrf(self):
                self._json({"ok": False, "error": "CSRF 校验失败"}, 403)
                return
            m = re.match(r"^/api/peers/([0-9a-f]+)$", path)
            if m:
                return self.api_peer_delete(m.group(1))
            self._json({"ok": False, "error": "not found"}, 404)
        except _BodyTooLarge:
            return
        except Exception as e:
            log("do_DELETE 异常: %s %s" % (self.path, e))
            try:
                self._json({"ok": False, "error": "服务器内部错误"}, 500)
            except Exception:
                pass

    # ---- 静态文件 ----
    def serve_file(self, name, ctype):
        fp = os.path.join(WEB_DIR, name)
        if not os.path.isfile(fp):
            self._json({"ok": False, "error": "static missing: %s" % name}, 404)
            return
        with open(fp, "rb") as f:
            body = f.read()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    # ---- 登录页（自包含，不依赖外部 CSS/JS） ----
    def serve_login_page(self):
        html = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WireGuard 管理器 · 登录</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
  background:linear-gradient(135deg,#0f172a 0%,#1e293b 100%);min-height:100vh;display:flex;align-items:center;justify-content:center}
.card{background:rgba(30,41,59,.95);border:1px solid rgba(99,102,241,.2);border-radius:16px;padding:40px 36px;width:380px;max-width:90vw;
  box-shadow:0 20px 60px rgba(0,0,0,.4)}
.logo{display:flex;align-items:center;gap:12px;margin-bottom:28px}
.logo svg{width:36px;height:36px;color:#818cf8;flex-shrink:0}
.logo h1{font-size:20px;color:#e2e8f0;font-weight:600}
.logo p{font-size:12px;color:#94a3b8;margin-top:2px}
.field{margin-bottom:20px}
.field label{display:block;font-size:13px;color:#cbd5e1;margin-bottom:6px}
.field input{width:100%;padding:12px 14px;border:1px solid rgba(148,163,184,.2);border-radius:8px;
  background:rgba(15,23,42,.6);color:#e2e8f0;font-size:15px;outline:none;transition:border .2s}
.field input:focus{border-color:#818cf8}
.field input::placeholder{color:#64748b}
.btn{width:100%;padding:13px;border:none;border-radius:8px;font-size:15px;font-weight:600;cursor:pointer;transition:all .2s}
.btn-primary{background:linear-gradient(135deg,#6366f1,#818cf8);color:#fff}
.btn-primary:hover{opacity:.9;transform:translateY(-1px)}
.btn-primary:disabled{opacity:.5;cursor:not-allowed;transform:none}
.error{color:#f87171;font-size:13px;margin-top:12px;min-height:18px}
.hint{color:#64748b;font-size:12px;margin-top:16px;text-align:center}
.hidden{display:none}
</style>
</head>
<body>
<div class="card">
  <div class="logo">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <path d="M12 3v6"/><circle cx="12" cy="12" r="3"/><path d="M12 15v6"/>
      <path d="M5.6 5.6l4.2 4.2"/><path d="M18.4 5.6l-4.2 4.2"/><path d="M5.6 18.4l4.2-4.2"/><path d="M18.4 18.4l-4.2-4.2"/>
    </svg>
    <div>
      <h1>WireGuard 管理器</h1>
      <p>fnOS 可视化 VPN 管理</p>
    </div>
  </div>
  <div id="setupField" class="field hidden">
    <label for="confirmPwd">确认密码</label>
    <input id="confirmPwd" type="password" placeholder="再次输入密码" autocomplete="new-password">
  </div>
  <div class="field">
    <label id="pwdLabel" for="pwd">密码</label>
    <input id="pwd" type="password" placeholder="请输入管理密码" autocomplete="current-password">
  </div>
  <button id="loginBtn" class="btn btn-primary" onclick="doSubmit()">登录</button>
  <p id="errMsg" class="error"></p>
  <p class="hint">所有网络访问（含内网）均需密码认证</p>
</div>
<script>
var needSetup=false;
var mode="login";
fetch("/api/auth/status").then(function(r){return r.json()}).then(function(d){
  if(d.need_setup&&!d.authed){
    needSetup=true;
    mode="setup";
    document.getElementById("pwdLabel").textContent="设置密码";
    document.getElementById("pwd").placeholder="设置管理密码（至少 4 位）";
    document.getElementById("pwd").autocomplete="new-password";
    document.getElementById("setupField").classList.remove("hidden");
    document.getElementById("loginBtn").textContent="设置密码并登录";
  }else if(!d.auth_enabled){
    location.reload();
    return;
  }
}).catch(function(){});
document.getElementById("pwd").addEventListener("keydown",function(e){
  if(e.key==="Enter")doSubmit();
});
document.getElementById("confirmPwd").addEventListener("keydown",function(e){
  if(e.key==="Enter")doSubmit();
});
function doSubmit(){
  var pwd=document.getElementById("pwd").value;
  var err=document.getElementById("errMsg");
  err.textContent="";
  if(!pwd){err.textContent="请输入密码";return;}
  if(mode==="setup"){
    var confirm=document.getElementById("confirmPwd").value;
    if(pwd!==confirm){err.textContent="两次输入的密码不一致";return;}
    if(pwd.length<4){err.textContent="密码长度至少 4 位";return;}
  }
  var btn=document.getElementById("loginBtn");
  btn.disabled=true;
  btn.textContent="请稍候...";
  var url=mode==="setup"?"/api/auth/setup":"/api/auth/login";
  fetch(url,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({password:pwd})})
    .then(function(r){return r.json()})
    .then(function(d){
      if(d.ok){
        location.reload();
      }else{
        err.textContent=d.error||"操作失败";
        btn.disabled=false;
        btn.textContent=mode==="setup"?"设置密码并登录":"登录";
      }
    })
    .catch(function(){
      err.textContent="网络错误，请重试";
      btn.disabled=false;
      btn.textContent=mode==="setup"?"设置密码并登录":"登录";
    });
}
</script>
</body>
</html>"""
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    # ---- 认证 ----
    def api_auth_status(self):
        state = load_state()
        a = state.get("auth", {})
        has_password = bool(a.get("password_hash"))
        enabled = auth_enabled(state)
        # 未设置密码 → 需要设置（强制设置页）；auth_enabled 返回 True 以触发登录页显示设置表单
        if not has_password:
            self._json({
                "ok": True,
                "auth_enabled": True,
                "authed": False,
                "need_setup": True,
            })
            return
        authed = check_auth(self) if enabled else True
        self._json({
            "ok": True,
            "auth_enabled": enabled,
            "authed": authed,
            "need_setup": False,
        })

    def _issue_session(self, state, handler):
        """创建新会话并返回 (token, csrf_token)。Bug 3：多会话列表。"""
        token = secrets.token_hex(32)
        csrf_token = secrets.token_hex(24)
        now = int(time.time())
        ua = handler.headers.get("User-Agent", "")[:200]
        session = {
            "token_hash": hash_token(token),
            "csrf_token": csrf_token,
            "created_at": now,
            "last_used": now,
            "ua": ua,
        }
        a = state.setdefault("auth", {})
        sessions = _gc_sessions(a.get("sessions") or [])
        sessions.append(session)
        # 限制最大保留会话数，防止内存膨胀
        if len(sessions) > 20:
            sessions = sessions[-20:]
        a["sessions"] = sessions
        return token, csrf_token

    def api_auth_setup(self):
        body = self._read_body()
        password = (body.get("password") or "").strip()
        if len(password) < 4:
            self._bad("密码长度至少 4 位")
            return
        state = load_state()
        a = state.setdefault("auth", {})
        if a.get("password_hash"):
            # 已设置过密码，需要先登录 + 校验旧密码（Bug 6）
            if not check_auth(self):
                self._json({"ok": False, "error": "请先登录后再修改密码"}, 401)
                return
            old_password = (body.get("old_password") or "").strip()
            if not old_password:
                self._json({"ok": False, "error": "修改密码必须提供当前密码"}, 400)
                return
            if not verify_password(old_password, a.get("password_hash", ""), a.get("salt", "")):
                log("修改密码失败：旧密码错误")
                self._json({"ok": False, "error": "当前密码错误"}, 401)
                return
        pwd_hash, salt = hash_password(password)
        a["password_hash"] = pwd_hash
        a["salt"] = salt
        a["enabled"] = True
        token, csrf_token = self._issue_session(state, self)
        save_state(state)
        log("密码认证已启用/修改")
        self._json({
            "ok": True,
            "message": "密码已设置，认证已启用",
            "csrf_token": csrf_token,  # Bug 1：返回 CSRF token 给前端
        }, headers={"Set-Cookie": "wg_token=%s; Path=/; HttpOnly; SameSite=Strict" % token})

    def api_auth_login(self):
        body = self._read_body()
        password = (body.get("password") or "").strip()
        state = load_state()
        a = state.get("auth", {})
        if not auth_enabled(state):
            self._json({"ok": True, "message": "认证未启用", "authed": True})
            return
        # Bug 8：登录速率限制
        if login_too_many_fails(self):
            log("登录被锁定（IP=%s，失败次数过多）" % self.client_address[0])
            self._json({"ok": False, "error": "登录失败次数过多，已临时锁定 5 分钟"}, 429)
            return
        if not verify_password(password, a.get("password_hash", ""), a.get("salt", "")):
            record_login_failure(self)
            log("登录失败：密码错误（IP=%s）" % self.client_address[0])
            self._json({"ok": False, "error": "密码错误"}, 401)
            return
        clear_login_failures(self)
        token, csrf_token = self._issue_session(state, self)
        save_state(state)
        log("用户登录成功（IP=%s）" % self.client_address[0])
        self._json({
            "ok": True,
            "message": "登录成功",
            "csrf_token": csrf_token,
        }, headers={"Set-Cookie": "wg_token=%s; Path=/; HttpOnly; SameSite=Strict" % token})

    def api_auth_logout(self):
        """登出当前会话（仅清除当前 token，不影响其他设备会话）。Bug 3"""
        state = load_state()
        a = state.get("auth", {})
        # 从 Cookie 提取当前 token
        token = ""
        cookie_header = self.headers.get("Cookie", "")
        for part in cookie_header.split(";"):
            part = part.strip()
            if part.startswith("wg_token="):
                token = part[len("wg_token="):]
                break
        if token:
            token_h = hash_token(token)
            sessions = _gc_sessions(a.get("sessions") or [])
            a["sessions"] = [s for s in sessions if s.get("token_hash") != token_h]
            save_state(state)
        self._json({"ok": True, "message": "已退出登录"},
                    headers={"Set-Cookie": "wg_token=; Path=/; Max-Age=0"})

    def api_auth_disable(self):
        """关闭密码认证（需要先登录）。Bug 3：清空所有会话。"""
        state = load_state()
        a = state.setdefault("auth", {})
        a["enabled"] = False
        a["sessions"] = []  # 清空所有会话
        save_state(state)
        log("密码认证已关闭")
        self._json({"ok": True, "message": "密码认证已关闭"})

    # ---- 状态 ----
    def api_status(self):
        state = load_state()
        mode = get_mode()
        initialized = is_initialized(state)
        s = state["settings"]
        online = False
        if mode == "container":
            online = container_running()
        elif mode == "native" and initialized:
            online = iface_exists()
        c = state.get("container", {})
        if mode == "container" and not c.get("config_dir"):
            c["config_dir"] = container_config_dir()
        self._json({
            "ok": True,
            "version": VERSION,
            "mode": mode,
            "mock": mode == "mock",
            "initialized": initialized,
            "interface_up": online,
            "config_dirty": bool(state.get("config_dirty")),
            "auth_enabled": auth_enabled(state),
            "settings": s,
            "server_ip": state.get("server_ip", ""),
            "server_public_key": state.get("server_public_key", ""),
            "peer_count": len(state["peers"]),
            "wan_iface": s.get("wan_iface") if s.get("wan_iface") and s.get("wan_iface") != "auto" else detect_wan_iface(),  # Bug 11：优先用户配置
            "container": {
                "name": c.get("name", CONTAINER_NAME),
                "image": CONTAINER_IMAGE,
                "config_dir": c.get("config_dir", ""),
                "deployed": mode == "container",
                "running": mode == "container" and online,
            },
        })

    # ---- 配置校验 ----
    def _validate_settings(self, body):
        errors = []
        port = int(body.get("port") or DEFAULT_PORT)
        subnet = (body.get("subnet") or "").strip()
        endpoint = (body.get("endpoint") or "").strip()
        mtu = int(body.get("mtu") or 1280)
        if not (1 <= port <= 65535):
            errors.append("端口必须在 1-65535 之间")
        if not (576 <= mtu <= 9000):
            errors.append("MTU 必须在 576-9000 之间")
        try:
            import ipaddress
            net = ipaddress.ip_network(subnet, strict=False)
            if net.prefixlen < 16:
                errors.append("内网网段前缀必须 >= 16（例如 10.13.13.0/24）")
            if str(net.network_address) == str(net.broadcast_address):
                errors.append("网段不合法")
        except Exception:
            errors.append("内网网段格式不正确，示例：10.13.13.0/24")
        if endpoint and endpoint != "auto":
            # Bug 10：DNS 标签只允许字母数字与连字符，去除下划线
            # 同时支持 IPv4 与 IPv6 形式的 endpoint
            valid_host = re.match(
                r"^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$",
                endpoint,
            ) or re.match(r"^\d{1,3}(\.\d{1,3}){3}$", endpoint) or re.match(r"^\[?[0-9a-fA-F:]+\]?$", endpoint)
            if not valid_host:
                errors.append("公网 IP/域名格式不正确")
        # Bug 11：校验 wan_iface
        wan_iface = (body.get("wan_iface") or "auto").strip()
        if wan_iface and wan_iface != "auto":
            if not re.match(r"^[a-zA-Z0-9._-]{1,15}$", wan_iface):
                errors.append("出口网卡名称格式不正确")
        return errors, port, subnet, endpoint, mtu

    # ---- 初始化 / 设置 / 应用 ----
    def api_init(self):
        body = self._read_body()
        state = load_state()
        if is_initialized(state):
            self._bad("服务器已初始化，如需修改请使用「应用设置」，或先重置服务器")
            return
        errors, port, subnet, endpoint, mtu = self._validate_settings(body)
        if errors:
            self._bad("；".join(errors))
            return
        state["settings"]["port"] = port
        state["settings"]["subnet"] = subnet
        state["settings"]["endpoint"] = endpoint
        state["settings"]["dns"] = (body.get("dns") or DEFAULT_DNS).strip()
        state["settings"]["keepalive"] = int(body.get("keepalive") or DEFAULT_KEEPALIVE)
        state["settings"]["mtu"] = mtu
        state["settings"]["nat"] = bool(body.get("nat", True))
        # Bug 11：保存 wan_iface 设置
        state["settings"]["wan_iface"] = (body.get("wan_iface") or "auto").strip() or "auto"
        try:
            state["server_private_key"] = gen_key()
            state["server_public_key"] = derive_pub(state["server_private_key"])
        except RuntimeError as e:
            self._json({"ok": False, "error": str(e)}, 500)
            return
        net = ipaddress_ip_network(subnet)
        state["server_ip"] = str(net.network_address + 1)
        state["config_dirty"] = True
        save_state(state)
        log("服务器配置已保存: endpoint=%s port=%d subnet=%s" % (endpoint or "(空)", port, subnet))
        self._json({
            "ok": True,
            "message": "服务器配置已保存",
            "server_public_key": state["server_public_key"],
            "need_apply": True,
        })

    def api_apply(self):
        """将已保存配置应用到运行时（容器重启 / wg-quick up / syncconf）。"""
        state = load_state()
        if not is_initialized(state):
            self._bad("请先完成服务器初始化")
            return
        if get_mode() == "mock":
            state["config_dirty"] = False
            save_state(state)
            self._json({"ok": True, "message": "模拟模式：已标记为已应用"})
            return
        ok, msg = apply_config(state)
        if not ok:
            self._json({"ok": False, "error": "应用到运行时失败：%s" % msg}, 500)
            return
        state["config_dirty"] = False
        save_state(state)
        log("配置已应用到运行时")
        self._json({"ok": True, "message": "已应用到运行时，接口状态：" + ("运行中" if iface_exists() else "已就绪")})

    def api_settings(self):
        body = self._read_body()
        state = load_state()
        if not is_initialized(state):
            self._bad("请先完成服务器初始化")
            return
        errors, port, subnet, endpoint, mtu = self._validate_settings(body)
        if errors:
            self._bad("；".join(errors))
            return
        subnet_changed = subnet != state["settings"]["subnet"]
        if subnet_changed and state["peers"]:
            # Bug 4：网段变更后，为每个 peer 在新网段内重新分配未占用 IP（从 .2 开始）
            # 原实现把 peer IP 改成 network_address+1（= 服务器 IP），造成 IP 冲突
            try:
                net_new = ipaddress_ip_network(subnet)
                new_peers_ips = []
                used = set()
                used.add(int(net_new.network_address) + 1)  # 服务器占用 .1
                for p in state["peers"]:
                    # 找一个新网段内未占用 IP
                    candidate = int(net_new.network_address) + 2  # 从 .2 开始
                    while candidate in used or candidate >= int(net_new.broadcast_address):
                        candidate += 1
                    if candidate >= int(net_new.broadcast_address):
                        raise RuntimeError("新网段地址不足")
                    used.add(candidate)
                    new_peers_ips.append(str(ipaddress_ip_address(candidate)))
                for p, new_ip in zip(state["peers"], new_peers_ips):
                    p["ip"] = new_ip
            except Exception as e:
                self._bad("网段变更后无法重新分配客户端 IP：%s，请先删除全部客户端或使用「重置服务器」" % e)
                return
        old_port = state["settings"]["port"]
        old_endpoint = state["settings"]["endpoint"]
        old_mtu = state["settings"].get("mtu", 1280)
        state["settings"]["port"] = port
        state["settings"]["subnet"] = subnet
        state["settings"]["endpoint"] = endpoint
        state["settings"]["dns"] = (body.get("dns") or DEFAULT_DNS).strip()
        state["settings"]["keepalive"] = int(body.get("keepalive") or DEFAULT_KEEPALIVE)
        state["settings"]["mtu"] = mtu
        state["settings"]["nat"] = bool(body.get("nat", True))
        # Bug 11：保存 wan_iface 设置
        state["settings"]["wan_iface"] = (body.get("wan_iface") or "auto").strip() or "auto"
        net = ipaddress_ip_network(subnet)
        state["server_ip"] = str(net.network_address + 1)
        changed = (port != old_port) or (endpoint != old_endpoint) or subnet_changed or (mtu != old_mtu)
        if changed:
            state["config_dirty"] = True
        save_state(state)
        self._json({
            "ok": True,
            "message": "设置已保存" + ("，请点击「应用到运行时」使其生效" if changed else ""),
            "config_changed": changed,
            "need_apply": bool(state.get("config_dirty")),
        })

    # ---- 容器管理 ----
    def api_container_deploy(self):
        body = self._read_body()
        state = load_state()
        # 保存/合并设置
        try:
            errors, port, subnet, endpoint, mtu = self._validate_settings(body)
        except Exception:
            errors = ["参数不完整"]
        if errors:
            self._bad("；".join(errors))
            return
        state["settings"]["port"] = port
        state["settings"]["subnet"] = subnet
        state["settings"]["endpoint"] = endpoint
        state["settings"]["dns"] = (body.get("dns") or DEFAULT_DNS).strip()
        state["settings"]["keepalive"] = int(body.get("keepalive") or DEFAULT_KEEPALIVE)
        state["settings"]["mtu"] = mtu
        state["settings"]["nat"] = bool(body.get("nat", True))
        # Bug 11：保存 wan_iface 设置
        state["settings"]["wan_iface"] = (body.get("wan_iface") or "auto").strip() or "auto"
        save_state(state)
        config_dir = body.get("config_dir") or DEFAULT_CONFIG_DIR
        pull = bool(body.get("pull", True))
        try:
            actual_dir = deploy_container(state, config_dir, pull=pull)
        except RuntimeError as e:
            self._json({"ok": False, "error": str(e)}, 500)
            return
        log("容器部署完成: %s" % actual_dir)
        self._json({
            "ok": True,
            "message": "WireGuard 容器部署成功",
            "config_dir": actual_dir,
        })

    def api_container_remove(self):
        state = load_state()
        remove_container(state)
        self._json({"ok": True, "message": "容器已移除（映射目录中的配置数据已保留）"})

    def api_container_destroy(self):
        """一键卸载并删除数据：移除容器 + 删除配置映射目录 + 清空应用配置数据。"""
        state = load_state()
        # 1. 移除容器
        if container_exists():
            run_cmd(["docker", "rm", "-f", CONTAINER_NAME], timeout=60)
        # 2. 删除配置映射目录（Bug 9：白名单 + 关键文件存在性校验，避免误删系统目录）
        config_dir = (state.get("container", {}).get("config_dir") or "").strip()
        removed = []
        failed = []

        def _safe_remove(path):
            """仅删除属于 wireguard 配置的目录：必须含 wg_confs/wg0.conf 文件，且不在系统保护路径。"""
            if not path or path == "/":
                return False, "空路径或根目录"
            # 系统保护路径绝对禁止
            PROTECTED = ("/usr", "/var", "/etc", "/bin", "/sbin", "/boot", "/lib",
                         "/lib64", "/dev", "/proc", "/sys", "/root", "/home",
                         "/opt", "/srv", "/mnt", "/media", "/run", "/tmp",
                         "/usr/local", "/var/apps", "/vol1", "/vol2", "/vol3",
                         "/volume1", "/volume2", "/volume3")
            norm = os.path.normpath(path)
            for p in PROTECTED:
                if norm == p:
                    return False, "受保护路径，拒绝删除：%s" % p
            # 必须存在 wg0.conf 才能确认是 wireguard 配置目录
            conf_marker = os.path.join(norm, "wg_confs", "wg0.conf")
            if not os.path.isfile(conf_marker):
                return False, "未发现 wg_confs/wg0.conf，无法确认是 wireguard 配置目录"
            try:
                shutil.rmtree(norm)
                return True, None
            except Exception as e:
                return False, str(e)

        if config_dir:
            ok_dir, err = _safe_remove(config_dir)
            if ok_dir:
                removed.append(config_dir)
            else:
                failed.append("%s: %s" % (config_dir, err))
        elif os.path.isdir(DEFAULT_CONFIG_DIR):
            ok_dir, err = _safe_remove(DEFAULT_CONFIG_DIR)
            if ok_dir:
                removed.append(DEFAULT_CONFIG_DIR)
            else:
                failed.append("%s: %s" % (DEFAULT_CONFIG_DIR, err))
        # 3. 清空应用配置数据（重置为初始状态，但保留认证设置与服务器设置）
        fresh = json.loads(json.dumps(DEFAULT_STATE))
        fresh["settings"] = json.loads(json.dumps(state["settings"]))  # 保留服务器设置（端口/网段等）
        fresh["auth"] = json.loads(json.dumps(state.get("auth", {})))  # 保留密码认证
        fresh["container"]["deployed"] = False
        save_state(fresh)
        log("一键卸载完成：容器已移除，配置目录 %s 已删除，配置数据已清空（失败：%s）" % (
            ", ".join(removed) or "无",
            "; ".join(failed) or "无"))
        self._json({
            "ok": True,
            "message": "已卸载并删除全部数据：容器、配置映射目录（%s）与应用配置均已清除%s" % (
                ", ".join(removed) or "无",
                ("；失败项：" + "; ".join(failed)) if failed else ""),
            "config_dir_removed": removed,
            "config_dir_failed": failed,
        })

    def api_container_restart(self):
        try:
            restart_container()
        except RuntimeError as e:
            self._json({"ok": False, "error": str(e)}, 500)
            return
        self._json({"ok": True, "message": "容器已重启"})

    # ---- 重置 ----
    def api_reset(self):
        """重置服务器：清空全部客户端并重新生成服务器密钥，恢复可用状态（不停容器）。"""
        state = load_state()
        try:
            new_priv = gen_key()
            new_pub = derive_pub(new_priv)
            net = ipaddress_ip_network(state["settings"]["subnet"])
            state["server_private_key"] = new_priv
            state["server_public_key"] = new_pub
            state["server_ip"] = str(net.network_address + 1)
            state["peers"] = []
            state["config_dirty"] = True
            save_state(state)
            ok, msg = apply_config(state)
            if not ok:
                self._json({"ok": False, "error": "重置后应用配置失败：%s" % msg}, 500)
                return
            log("服务器已重置，已重新生成密钥并应用")
            self._json({
                "ok": True,
                "message": "服务器已重置，已生成新的服务器密钥并恢复运行，原客户端全部失效",
                "server_public_key": new_pub,
            })
        except RuntimeError as e:
            self._json({"ok": False, "error": "重置失败：%s" % e}, 500)

    # ---- 客户端 ----
    def api_peers_list(self):
        state = load_state()
        self._json({"ok": True, "peers": collect_peers_status(state)})

    def api_peer_get(self, peer_id):
        state = load_state()
        peer = next((p for p in state["peers"] if p["id"] == peer_id), None)
        if not peer:
            self._bad("客户端不存在")
            return
        self._json({"ok": True, "peer": peer})

    def api_peer_create(self):
        body = self._read_body()
        state = load_state()
        if not is_initialized(state):
            self._bad("请先完成服务器初始化，再创建客户端")
            return
        name = body.get("name") or ""
        try:
            route = self._parse_route(body)
            peer, ok, msg = create_peer(state, name, route)
        except ValueError as e:
            self._bad(str(e))
            return
        config = build_client_config(state, peer)
        log("创建客户端: %s (%s)" % (peer["name"], peer["ip"]))
        self._json({"ok": True, "peer": peer, "config": config, "applied": ok, "apply_message": msg})

    def api_peer_batch(self):
        body = self._read_body()
        state = load_state()
        if not is_initialized(state):
            self._bad("请先完成服务器初始化，再批量创建客户端")
            return
        count = body.get("count") or 1
        name_prefix = body.get("name_prefix") or ""
        try:
            route = self._parse_route(body)
            created, errors = batch_create_peers(state, count, name_prefix, route)
        except ValueError as e:
            self._bad(str(e))
            return
        log("批量创建客户端: %d 个（前缀 %s，失败 %d 个）" % (
            len(created), name_prefix or "client", len(errors)))
        # Bug 5：返回 errors 让前端能展示失败明细
        msg = "已批量创建 %d 个客户端" % len(created)
        if errors:
            msg += "，%d 个失败" % len(errors)
        self._json({
            "ok": True,
            "peers": created,
            "errors": [{"name": n, "error": e} for n, e in errors],
            "message": msg,
            "has_failures": bool(errors),
        })

    def _parse_route(self, body):
        """解析客户端路由：full=全量代理 / split=分流（指定内网网段）。"""
        mode = body.get("route_mode") or "full"
        if mode not in ("full", "split"):
            raise ValueError("路由模式不正确")
        route = {"mode": mode, "cidr": ""}
        if mode == "split":
            cidr = (body.get("route_cidr") or "").strip()
            if not cidr:
                raise ValueError("分流模式下必须填写客户端路由（内网网段），例如 192.168.1.0/24")
            try:
                import ipaddress
                ipaddress.ip_network(cidr, strict=False)
            except Exception:
                raise ValueError("客户端路由网段格式不正确，示例：192.168.1.0/24")
            route["cidr"] = cidr
        return route

    def api_peer_config(self, peer_id):
        state = load_state()
        peer = next((p for p in state["peers"] if p["id"] == peer_id), None)
        if not peer:
            self._bad("客户端不存在")
            return
        config = build_client_config(state, peer)
        safe_name = re.sub(r"[^\w\-]+", "_", peer["name"])
        filename = "wg-%s.conf" % safe_name
        # RFC 5987：中文文件名走 filename*（UTF-8 百分号编码），ASCII 兜底保证兼容
        quoted_ascii = filename.encode("ascii", "replace").decode("ascii")
        quoted_ascii = re.sub(r'[^A-Za-z0-9._\-]', "_", quoted_ascii)
        from urllib.parse import quote
        filename_utf8 = quote(filename, safe="")
        body = config.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header(
            "Content-Disposition",
            "attachment; filename=\"%s\"; filename*=UTF-8''%s" % (quoted_ascii, filename_utf8)
        )
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def api_peer_delete(self, peer_id):
        state = load_state()
        try:
            peer, ok, msg = delete_peer(state, peer_id)
        except ValueError as e:
            self._bad(str(e))
            return
        log("删除客户端: %s (%s)" % (peer["name"], peer["ip"]))
        self._json({"ok": True, "message": "已删除客户端 %s" % peer["name"], "applied": ok, "apply_message": msg})

    def api_peer_rename(self, peer_id):
        body = self._read_body()
        new_name = body.get("name") or ""
        state = load_state()
        try:
            peer, old_name = rename_peer(state, peer_id, new_name)
        except ValueError as e:
            self._bad(str(e))
            return
        log("重命名客户端: %s → %s" % (old_name, peer["name"]))
        self._json({"ok": True, "message": "已重命名为 %s" % peer["name"], "peer": peer})

    def api_peer_toggle(self):
        body = self._read_body()
        peer_id = body.get("id") or ""
        state = load_state()
        try:
            peer, ok, msg = toggle_peer(state, peer_id)
        except ValueError as e:
            self._bad(str(e))
            return
        action = "启用" if peer.get("enabled", True) else "停用"
        log("%s客户端: %s (%s)" % (action, peer["name"], peer["ip"]))
        self._json({"ok": True, "message": "已%s客户端 %s" % (action, peer["name"]),
                     "enabled": peer.get("enabled", True), "applied": ok, "apply_message": msg})

    def api_config_export(self):
        """导出完整配置（state.json）为 JSON 文件下载。"""
        state = load_state()
        # 导出时清除会话令牌（安全考虑）
        export = json.loads(json.dumps(state))
        if "auth" in export:
            # Bug 3：清除会话列表（不再用 session_token）
            export["auth"]["sessions"] = []
        body = json.dumps(export, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Disposition", 'attachment; filename="fn-wg-web-config.json"')
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def api_config_import(self):
        """从 JSON 导入配置（覆盖当前配置）。"""
        body = self._read_body()
        if not body:
            self._bad("导入数据为空")
            return
        state = load_state()
        # 保留当前认证配置（不允许通过导入覆盖密码）
        current_auth = state.get("auth", {})
        # Bug 3：清理过期会话，避免导入时遗留无效 token
        current_auth = dict(current_auth)
        current_auth["sessions"] = _gc_sessions(current_auth.get("sessions") or [])
        try:
            # body 可能是完整的 state 对象，也可能是嵌套在 data 字段中
            imported = body.get("data") if "data" in body else body
            # 合并默认值
            fresh = json.loads(json.dumps(DEFAULT_STATE))
            for k in ("settings", "server_private_key", "server_public_key",
                       "server_ip", "peers", "config_dirty", "container"):
                if k in imported:
                    fresh[k] = imported[k]
            fresh["auth"] = current_auth
        except Exception as e:
            self._bad("导入数据格式错误：%s" % str(e))
            return
        save_state(fresh)
        # 尝试应用到运行时
        applied = True
        apply_msg = ""
        if is_initialized(fresh) and get_mode() != "mock":
            ok, msg = apply_config(fresh)
            applied = ok
            apply_msg = msg
            if ok:
                fresh["config_dirty"] = False
                save_state(fresh)
            else:
                # Bug 15B：应用失败时标记 dirty，前端可看到「待应用」状态
                fresh["config_dirty"] = True
                save_state(fresh)
        log("配置已导入（应用 %s）" % ("成功" if applied else "失败：" + apply_msg))
        if applied:
            self._json({"ok": True, "message": "配置已导入并应用到运行时"})
        else:
            self._json({
                "ok": True,
                "message": "配置已导入，但应用到运行时失败（可稍后点击「应用到运行时」重试）：%s" % apply_msg,
                "apply_failed": True,
                "apply_message": apply_msg,
            })

    # ---- 日志 ----
    def log_message(self, fmt, *args):
        # Bug 13：直接使用 client IP 字符串，避免反向 DNS 查询拖慢请求
        try:
            ip = self.client_address[0]
        except Exception:
            ip = "?"
        log("[http] %s - %s" % (ip, fmt % args))


def main():
    ap = argparse.ArgumentParser(description="fn-wg-web WireGuard 管理服务")
    ap.add_argument("--port", type=int, default=int(os.environ.get("TRIM_SERVICE_PORT", "51821")))
    ap.add_argument("--host", default="0.0.0.0")
    args = ap.parse_args()

    try:
        os.makedirs(BASE_DIR, exist_ok=True)
        os.makedirs(ETC_DIR, exist_ok=True)
        os.makedirs(DATA_DIR, exist_ok=True)
        os.makedirs(WEB_DIR, exist_ok=True)
    except Exception as e:
        log("初始化目录失败: %s" % e)

    # 无损升级：最后一层 Python 侧迁移兜底（仅当目标不存在才迁，原件保留不删）
    try:
        _migrate_legacy_data_on_startup()
    except Exception as e:
        log("旧数据迁移兜底阶段异常（已忽略）: %s" % e)

    mode = get_mode()
    log("%s %s 启动，监听 %s:%d（程序目录 %s，配置目录 %s，数据目录 %s，日志 %s，模式 %s）" % (
        APP_NAME, APP_VER, args.host, args.port, BASE_DIR, ETC_DIR, DATA_DIR, LOG_FILE, mode))
    if mode == "container":
        try:
            cfg = container_config_dir()
            if cfg:
                log("已接管容器 %s，配置目录 %s" % (CONTAINER_NAME, cfg))
                state = load_state()
                state["container"]["config_dir"] = cfg
                state["container"]["deployed"] = True
                conf = os.path.join(cfg, "wg_confs", "wg0.conf")
                priv = read_conf_private_key(conf)
                if priv and priv != state.get("server_private_key") and is_valid_key(priv):
                    # 同步实际服务器密钥（避免与 wg0.conf 不一致导致客户端无法握手）
                    state["server_private_key"] = priv
                    state["server_public_key"] = derive_pub(priv)
                elif not (priv and is_valid_key(priv)) and not is_valid_key(state.get("server_private_key")):
                    # wg0.conf 密钥缺失/非法（如之前被写入伪密钥）→ 生成真实密钥修复并重启容器
                    log("检测到 wg0.conf 密钥无效，正在生成真实密钥修复...")
                    try:
                        state["server_private_key"] = gen_key()
                        state["server_public_key"] = derive_pub(state["server_private_key"])
                        write_conf(state)
                        run_cmd(["docker", "restart", CONTAINER_NAME], timeout=60)
                        time.sleep(3)
                    except RuntimeError as e:
                        log("自动修复密钥失败：%s" % e)
                if state.get("server_public_key") and not state.get("server_ip"):
                    net = ipaddress_ip_network(state["settings"]["subnet"])
                    state["server_ip"] = str(net.network_address + 1)
                save_state(state)
        except Exception as e:
            log("容器模式初始化异常（不影响 Web 服务启动）: %s" % e)

    try:
        server = ThreadingHTTPServer((args.host, args.port), Handler)
        server.serve_forever()
    except KeyboardInterrupt:
        log("服务停止")
    except OSError as e:
        log("端口 %d 监听失败: %s" % (args.port, e))
        sys.exit(1)
    except Exception as e:
        log("服务异常: %s" % e)
        # 致命错误退出，但确保有日志
        sys.exit(2)


if __name__ == "__main__":
    main()
