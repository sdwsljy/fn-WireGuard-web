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

VERSION = "0.3.0"

# 状态文件写入锁（并发请求下防止 tmp 文件竞争）
_state_lock = threading.Lock()

# ---------------------------------------------------------------------------
# 路径与环境
# ---------------------------------------------------------------------------
# 目录策略（与 fnOS 官方 fpk 标准一致）：
#   BASE_DIR  程序文件目录（web 静态资源等），默认 /usr/fn-wg-web
#   DATA_DIR  数据目录（state.json 配置），优先官方持久卷
#             /var/apps/fn-wg-web/var （→ /usr/local/apps/@appdata/fn-wg-web，升级/卸载保留）
#   兼容旧版本：未设置 WG_DATA_BASE 时沿用 BASE_DIR（state.json 在程序目录）
BASE_DIR = os.environ.get("WG_WEB_BASE", "/usr/fn-wg-web")
DATA_DIR = os.environ.get("WG_DATA_BASE", "") or BASE_DIR
CONF_DIR = "/etc/wireguard"
CONF_FILE = os.path.join(CONF_DIR, "wg0.conf")
STATE_FILE = os.path.join(DATA_DIR, "state.json")
WEB_DIR = os.path.join(BASE_DIR, "web")
LOG_FILE = "/var/log/fn-wg-web.log"

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
        with open(LOG_FILE, "a", encoding="utf-8") as f:
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
        "session_token": "",
    },
}


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


def auth_enabled(state):
    """是否启用了密码认证。"""
    a = state.get("auth", {})
    return bool(a.get("enabled") and a.get("password_hash"))


def check_auth(handler):
    """检查请求是否已认证（Cookie 中的 session_token）。未启用认证时返回 True。"""
    state = load_state()
    if not auth_enabled(state):
        return True
    token = ""
    cookie_header = handler.headers.get("Cookie", "")
    for part in cookie_header.split(";"):
        part = part.strip()
        if part.startswith("wg_token="):
            token = part[len("wg_token="):]
            break
    expected = state.get("auth", {}).get("session_token", "")
    return bool(token) and bool(expected) and secrets.compare_digest(token, expected)


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
    internal_subnet = str(subnet.network_address)
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
    os.makedirs(os.path.join(config_dir, "wg_confs"), exist_ok=True)
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


def create_peer(state, name, route=None):
    name = (name or "").strip()
    if not name:
        raise ValueError("客户端名称不能为空")
    if len(name) > 32:
        raise ValueError("客户端名称过长（最多 32 字符）")
    for p in state["peers"]:
        if p["name"] == name:
            raise ValueError("客户端名称已存在")
    priv = gen_key()
    pub = derive_pub(priv)
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
    state["peers"].append(peer)
    save_state(state)
    ok, msg = apply_config(state)
    if ok:
        state["config_dirty"] = False
        save_state(state)
    return peer, ok, msg


def batch_create_peers(state, count, name_prefix):
    """批量生成客户端；创建后同步应用到运行时。"""
    count = int(count or 1)
    if count < 1 or count > 50:
        raise ValueError("批量数量必须在 1-50 之间")
    name_prefix = (name_prefix or "").strip() or "client"
    if len(name_prefix) > 20:
        raise ValueError("名称前缀过长（最多 20 字符）")
    created = []
    for i in range(count):
        name = "%s-%02d" % (name_prefix, i + 1)
        try:
            peer, ok, msg = create_peer(state, name)
        except ValueError as e:
            if created:
                break
            raise e
        created.append(peer)
    return created


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
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except Exception:
            return {}

    def _bad(self, msg):
        self._json({"ok": False, "error": msg}, 400)

    # ---- 路由 ----
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"

        # 无需认证的路由
        if path == "/api/auth/status":
            return self.api_auth_status()
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

        # 以下路由需要认证
        if not check_auth(self):
            self._json({"ok": False, "error": "未登录", "need_auth": True}, 401)
            return

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
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        # 无需认证的路由
        if path == "/api/auth/setup":
            return self.api_auth_setup()
        if path == "/api/auth/login":
            return self.api_auth_login()
        if path == "/api/auth/logout":
            return self.api_auth_logout()

        # 以下路由需要认证
        if not check_auth(self):
            self._json({"ok": False, "error": "未登录", "need_auth": True}, 401)
            return

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
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        if not check_auth(self):
            self._json({"ok": False, "error": "未登录", "need_auth": True}, 401)
            return
        m = re.match(r"^/api/peers/([0-9a-f]+)$", path)
        if m:
            return self.api_peer_rename(m.group(1))
        self._json({"ok": False, "error": "not found"}, 404)

    def do_DELETE(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        if not check_auth(self):
            self._json({"ok": False, "error": "未登录", "need_auth": True}, 401)
            return
        m = re.match(r"^/api/peers/([0-9a-f]+)$", path)
        if m:
            return self.api_peer_delete(m.group(1))
        self._json({"ok": False, "error": "not found"}, 404)

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

    # ---- 认证 ----
    def api_auth_status(self):
        state = load_state()
        a = state.get("auth", {})
        enabled = auth_enabled(state)
        authed = check_auth(self) if enabled else True
        self._json({
            "ok": True,
            "auth_enabled": enabled,
            "authed": authed,
            "need_setup": not a.get("password_hash"),
        })

    def api_auth_setup(self):
        body = self._read_body()
        password = (body.get("password") or "").strip()
        if len(password) < 4:
            self._bad("密码长度至少 4 位")
            return
        state = load_state()
        a = state.setdefault("auth", {})
        if a.get("password_hash"):
            # 已设置过密码，需要先登录
            if not check_auth(self):
                self._json({"ok": False, "error": "请先登录后再修改密码"}, 401)
                return
        pwd_hash, salt = hash_password(password)
        a["password_hash"] = pwd_hash
        a["salt"] = salt
        a["enabled"] = True
        token = secrets.token_hex(32)
        a["session_token"] = token
        save_state(state)
        log("密码认证已启用")
        self._json({"ok": True, "message": "密码已设置，认证已启用"},
                    headers={"Set-Cookie": "wg_token=%s; Path=/; HttpOnly; SameSite=Strict" % token})

    def api_auth_login(self):
        body = self._read_body()
        password = (body.get("password") or "").strip()
        state = load_state()
        a = state.get("auth", {})
        if not auth_enabled(state):
            self._json({"ok": True, "message": "认证未启用", "authed": True})
            return
        if not verify_password(password, a.get("password_hash", ""), a.get("salt", "")):
            self._json({"ok": False, "error": "密码错误"}, 401)
            return
        token = secrets.token_hex(32)
        a["session_token"] = token
        save_state(state)
        log("用户登录成功")
        self._json({"ok": True, "message": "登录成功"},
                    headers={"Set-Cookie": "wg_token=%s; Path=/; HttpOnly; SameSite=Strict" % token})

    def api_auth_logout(self):
        state = load_state()
        state.setdefault("auth", {})["session_token"] = ""
        save_state(state)
        self._json({"ok": True, "message": "已退出登录"},
                    headers={"Set-Cookie": "wg_token=; Path=/; Max-Age=0"})

    def api_auth_disable(self):
        """关闭密码认证（需要先登录）。"""
        state = load_state()
        a = state.setdefault("auth", {})
        a["enabled"] = False
        a["session_token"] = ""
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
            "wan_iface": detect_wan_iface(),
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
            valid_host = re.match(
                r"^([a-zA-Z0-9]([a-zA-Z0-9\-_]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-_]{0,61}[a-zA-Z0-9])?$",
                endpoint,
            ) or re.match(r"^\d{1,3}(\.\d{1,3}){3}$", endpoint)
            if not valid_host:
                errors.append("公网 IP/域名格式不正确")
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
            self._bad("内网网段已变更且存在客户端，请先删除全部客户端，或使用「重置服务器」重新初始化")
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
        net = ipaddress_ip_network(subnet)
        state["server_ip"] = str(net.network_address + 1)
        if subnet_changed:
            for p in state["peers"]:
                try:
                    if int(ipaddress_ip_address(p["ip"])) > int(net.broadcast_address):
                        p["ip"] = str(net.network_address + 1)
                except Exception:
                    pass
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
        # 2. 删除配置映射目录（精确读取用户配置的路径，避免误删其他数据）
        config_dir = (state.get("container", {}).get("config_dir") or "").strip()
        removed = []
        if config_dir and config_dir != "/" and os.path.isdir(config_dir):
            removed.append(config_dir)
            shutil.rmtree(config_dir, ignore_errors=True)
        elif not config_dir and os.path.isdir(DEFAULT_CONFIG_DIR):
            removed.append(DEFAULT_CONFIG_DIR)
            shutil.rmtree(DEFAULT_CONFIG_DIR, ignore_errors=True)
        # 3. 清空应用配置数据（重置为初始状态）
        fresh = json.loads(json.dumps(DEFAULT_STATE))
        fresh["settings"] = json.loads(json.dumps(state["settings"]))  # 保留服务器设置（端口/网段等）
        fresh["container"]["deployed"] = False
        save_state(fresh)
        log("一键卸载完成：容器已移除，配置目录 %s 已删除，配置数据已清空" % (", ".join(removed) or "无"))
        self._json({
            "ok": True,
            "message": "已卸载并删除全部数据：容器、配置映射目录（%s）与应用配置均已清除" % (", ".join(removed) or "无"),
            "config_dir_removed": removed,
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
            created = batch_create_peers(state, count, name_prefix)
        except ValueError as e:
            self._bad(str(e))
            return
        log("批量创建客户端: %d 个（前缀 %s）" % (len(created), name_prefix or "client"))
        self._json({"ok": True, "peers": created, "message": "已批量创建 %d 个客户端" % len(created)})

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
            export["auth"]["session_token"] = ""
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
        if is_initialized(fresh) and get_mode() != "mock":
            ok, msg = apply_config(fresh)
            if ok:
                fresh["config_dirty"] = False
                save_state(fresh)
        log("配置已导入")
        self._json({"ok": True, "message": "配置已导入并应用"})

    # ---- 日志 ----
    def log_message(self, fmt, *args):
        log("[http] %s - %s" % (self.address_string(), fmt % args))


def main():
    ap = argparse.ArgumentParser(description="fn-wg-web WireGuard 管理服务")
    ap.add_argument("--port", type=int, default=int(os.environ.get("TRIM_SERVICE_PORT", "51821")))
    ap.add_argument("--host", default="0.0.0.0")
    args = ap.parse_args()

    os.makedirs(BASE_DIR, exist_ok=True)
    os.makedirs(WEB_DIR, exist_ok=True)
    mode = get_mode()
    log("fn-wg-web %s 启动，监听 %s:%d（数据目录 %s，模式 %s）" % (
        VERSION, args.host, args.port, BASE_DIR, mode))
    if mode == "container":
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

    try:
        server = ThreadingHTTPServer((args.host, args.port), Handler)
        server.serve_forever()
    except KeyboardInterrupt:
        log("服务停止")
    except OSError as e:
        log("端口 %d 监听失败: %s" % (args.port, e))
        sys.exit(1)


if __name__ == "__main__":
    main()
