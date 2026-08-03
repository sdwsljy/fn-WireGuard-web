/* ============================================================
   fn-wg-web - WireGuard 管理器 前端逻辑
   ============================================================ */
"use strict";

const $ = (id) => document.getElementById(id);
const state = {
  status: null,
  peers: [],
  currentPeer: null,   // 详情弹窗中的客户端
  currentConfig: "",
  initDone: false,
};

/* ---------------- 工具 ---------------- */

function toast(msg, type) {
  const box = $("toastBox");
  const el = document.createElement("div");
  el.className = "toast" + (type ? " " + type : "");
  el.textContent = msg;
  box.appendChild(el);
  setTimeout(() => {
    el.style.opacity = "0";
    el.style.transition = "opacity 0.3s";
    setTimeout(() => el.remove(), 320);
  }, 3200);
}

async function api(path, opts) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...opts,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok || data.ok === false) {
    throw new Error(data.error || ("请求失败 HTTP " + res.status));
  }
  return data;
}

function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

/* ---------------- 状态徽章 ---------------- */

function setBadge(mode, text) {
  const b = $("statusBadge");
  b.className = "badge badge-" + mode;
  b.querySelector(".badge-text").textContent = text;
}

/* ---------------- 状态加载 ---------------- */

async function loadStatus(silent) {
  try {
    const st = await api("/api/status");
    state.status = st;
    renderStatus();
    if (!silent) await loadPeers();
    return st;
  } catch (e) {
    setBadge("error", "连接失败");
    if (!silent) toast(e.message, "err");
  }
}

function renderStatus() {
  const st = state.status;
  if (!st) return;

  $("ver").textContent = "v" + st.version;

  // 依赖警告
  $("depsWarning").classList.toggle("hidden", !st.mock);

  // 部署向导
  renderDeploy(st);

  // 徽章
  if (st.mock) {
    setBadge("error", "依赖缺失");
  } else if (!st.initialized) {
    setBadge("warn", "未初始化");
  } else if (st.interface_up) {
    setBadge("ok", "运行中");
  } else {
    setBadge("warn", "接口未运行");
  }

  // 表单填充
  const s = st.settings || {};
  $("fEndpoint").value = s.endpoint || "";
  $("fPort").value = s.port || 51820;
  $("fSubnet").value = s.subnet || "10.13.13.0/24";
  $("fDns").value = s.dns || "";
  $("fKeepalive").value = s.keepalive || 25;
  $("fNat").checked = s.nat !== false;

  // 初始化提示 & 按钮
  const hint = $("initHint");
  const btn = $("saveBtn");
  const applyBtn = $("applyBtn");
  const dirty = !!st.config_dirty;
  if (st.initialized) {
    hint.textContent = "已初始化";
    hint.className = "panel-tag on";
    btn.textContent = "保存设置";
    applyBtn.classList.remove("hidden");
    $("dirtyHint").classList.toggle("hidden", !dirty);
    applyBtn.classList.toggle("btn-apply", dirty);
  } else {
    hint.textContent = "首次使用";
    hint.className = "panel-tag";
    btn.textContent = "一键生成服务端配置";
    applyBtn.classList.add("hidden");
    $("dirtyHint").classList.add("hidden");
  }
  state.initDone = st.initialized;

  // 公钥 / 元信息
  $("serverKey").textContent = st.server_public_key || "尚未生成";
  $("metaIface").textContent = st.interface_up ? "运行中" : (st.initialized ? "未运行" : "未初始化");
  $("metaSrvIp").textContent = st.server_ip || "-";
  $("metaWan").textContent = st.wan_iface || "-";
  $("metaPeers").textContent = String(st.peer_count);
}

/* ---------------- 容器部署向导 ---------------- */

function renderDeploy(st) {
  const form = $("deployForm");
  const statusBox = $("deployStatus");
  const mockHint = $("mockHint");
  const tag = $("deployTag");
  const c = st.container || {};

  if (st.mode === "container") {
    form.classList.add("hidden");
    statusBox.classList.remove("hidden");
    mockHint.classList.add("hidden");
    tag.textContent = "已部署";
    tag.className = "panel-tag on";
    $("cName").textContent = c.name || "wireguard";
    $("cImage").textContent = (c.image || "").replace("docker.io/library/", "");
    $("cRunning").textContent = c.running ? "运行中" : "已停止";
    $("cConfigDir").textContent = c.config_dir || "-";
    $("cRunning").style.color = c.running ? "var(--ok)" : "var(--danger)";
  } else if (st.mode === "mock") {
    form.classList.add("hidden");
    statusBox.classList.add("hidden");
    mockHint.classList.remove("hidden");
    tag.textContent = "不可用";
    tag.className = "panel-tag";
  } else {
    // not_deployed / native：显示部署表单
    form.classList.remove("hidden");
    statusBox.classList.add("hidden");
    mockHint.classList.add("hidden");
    tag.textContent = st.mode === "not_deployed" ? "未部署" : "原生模式";
    tag.className = "panel-tag";
    // 用已保存设置预填
    if (st.initialized) {
      $("dPort").value = st.settings.port || 51820;
      $("dSubnet").value = st.settings.subnet || "10.13.13.0/24";
      $("dEndpoint").value = st.settings.endpoint || "";
      $("dDns").value = st.settings.dns || "1.1.1.1, 8.8.8.8";
    }
  }
}

async function deployContainer() {
  const body = {
    config_dir: $("fConfigDir").value.trim(),
    port: parseInt($("dPort").value, 10),
    subnet: $("dSubnet").value.trim(),
    endpoint: $("dEndpoint").value.trim(),
    dns: $("dDns").value.trim(),
    keepalive: 25,
    nat: true,
    pull: true,
  };
  if (!body.config_dir) {
    toast("请填写配置目录映射路径", "err");
    return;
  }
  const btn = $("deployBtn");
  btn.disabled = true;
  btn.textContent = "正在部署 Docker 容器（拉取镜像可能需要几分钟）...";
  try {
    const res = await api("/api/container/deploy", {
      method: "POST",
      body: JSON.stringify(body),
    });
    toast(res.message + "（配置目录：" + res.config_dir + "）", "ok");
    await loadStatus();
    await loadPeers();
  } catch (e) {
    toast(e.message, "err");
  } finally {
    btn.disabled = false;
    btn.textContent = "部署 WireGuard 容器";
  }
}

async function removeContainer() {
  if (!confirm("确定移除 wireguard 容器？\n映射目录中的配置数据会保留，如需重新部署可直接再次部署。")) return;
  try {
    await api("/api/container/remove", { method: "POST" });
    toast("容器已移除", "ok");
    await loadStatus();
    await loadPeers();
  } catch (e) {
    toast(e.message, "err");
  }
}

async function restartContainer() {
  try {
    const res = await api("/api/container/restart", { method: "POST" });
    toast(res.message, "ok");
    setTimeout(() => loadStatus(), 3000);
  } catch (e) {
    toast(e.message, "err");
  }
}

/* ---------------- 设置保存 / 应用 ---------------- */

async function saveSettings() {
  const body = {
    endpoint: $("fEndpoint").value.trim(),
    port: parseInt($("fPort").value, 10),
    subnet: $("fSubnet").value.trim(),
    dns: $("fDns").value.trim(),
    keepalive: parseInt($("fKeepalive").value, 10),
    nat: $("fNat").checked,
  };
  const btn = $("saveBtn");
  btn.disabled = true;
  try {
    const url = state.initDone ? "/api/settings" : "/api/init";
    const res = await api(url, {
      method: "POST",
      body: JSON.stringify(body),
    });
    toast(res.message + (res.need_apply ? "，请点击「应用到运行时」" : ""), "ok");
    await loadStatus();
    await loadPeers();
    if (res.need_apply && state.initDone) {
      $("applyBtn").classList.remove("hidden");
      $("applyBtn").classList.add("btn-apply");
      $("dirtyHint").classList.remove("hidden");
    }
  } catch (e) {
    toast(e.message, "err");
  } finally {
    btn.disabled = false;
  }
}

async function applyConfig() {
  const btn = $("applyBtn");
  btn.disabled = true;
  try {
    const res = await api("/api/apply", { method: "POST" });
    toast(res.message, "ok");
    await loadStatus();
    await loadPeers();
  } catch (e) {
    toast(e.message, "err");
  } finally {
    btn.disabled = false;
  }
}

/* ---------------- 客户端 ---------------- */

async function loadPeers() {
  try {
    const data = await api("/api/peers");
    state.peers = data.peers || [];
    renderPeers();
  } catch (e) {
    // 未初始化时忽略
  }
}

function peerCard(p) {
  const initial = esc((p.name || "?").slice(0, 1).toUpperCase());
  const online = !!p.online;
  const rx = esc(p.rx || "0 B");
  const tx = esc(p.tx || "0 B");
  const route = (p.route || {}).mode === "split" ? "分流" : "全量";
  return `
  <div class="peer-card">
    <div class="peer-avatar ${online ? "" : "off"}">${initial}</div>
    <div class="peer-info">
      <div class="peer-name">
        <span>${esc(p.name)}</span>
        <span class="route-tag" title="客户端路由模式">${route}</span>
        <span class="peer-state ${online ? "s-on" : "s-off"}">
          <span class="sdot"></span>${online ? "在线" : "离线"}
        </span>
      </div>
      <div class="peer-meta">
        <span>内网 IP <b>${esc(p.ip)}</b></span>
        <span>握手 <b>${esc(p.handshake)}</b></span>
        <span>↓ <b>${rx}</b></span>
        <span>↑ <b>${tx}</b></span>
      </div>
    </div>
    <div class="peer-actions">
      <button class="btn btn-act" data-act="qr" data-id="${p.id}" title="二维码 / 配置" aria-label="二维码">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><path d="M14 14h3v3h-3zM20 14h1M14 20h1M18 18h3"/></svg>
      </button>
      <button class="btn btn-act" data-act="dl" data-id="${p.id}" title="下载配置" aria-label="下载">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="M7 10l5 5 5-5"/><path d="M12 15V3"/></svg>
      </button>
      <button class="btn btn-act btn-del" data-act="del" data-id="${p.id}" title="删除客户端" aria-label="删除">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/><path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><path d="M10 11v6M14 11v6"/></svg>
      </button>
    </div>
  </div>`;
}

function renderPeers() {
  const list = $("peerList");
  const empty = $("emptyBox");
  if (!state.peers.length) {
    $("emptyText").textContent = state.initDone ? "暂无客户端" : "尚未初始化服务器";
    empty.style.display = "";
    list.querySelectorAll(".peer-card").forEach((n) => n.remove());
    return;
  }
  empty.style.display = "none";
  list.querySelectorAll(".peer-card").forEach((n) => n.remove());
  const frag = document.createDocumentFragment();
  state.peers.forEach((p) => {
    const div = document.createElement("div");
    div.innerHTML = peerCard(p).trim();
    frag.appendChild(div.firstChild);
  });
  list.appendChild(frag);
}

/* ---------------- 创建客户端 ---------------- */

function openCreate() {
  if (!state.initDone) {
    toast("请先完成服务器初始化", "err");
    return;
  }
  $("peerName").value = "";
  $("peerCount").value = "1";
  $("routeCidr").value = "";
  setRouteMode("full");
  $("createModal").hidden = false;
  setTimeout(() => $("peerName").focus(), 60);
}

function setRouteMode(mode) {
  document.querySelectorAll("#routeSeg .seg-btn").forEach((b) => {
    b.classList.toggle("on", b.dataset.route === mode);
  });
  $("cidrField").classList.toggle("hidden", mode !== "split");
}

async function confirmCreate() {
  const name = $("peerName").value.trim();
  const count = parseInt($("peerCount").value, 10) || 1;
  const mode = document.querySelector("#routeSeg .seg-btn.on").dataset.route;
  if (!name) {
    toast("请输入客户端名称 / 前缀", "err");
    return;
  }
  if (count < 1 || count > 50) {
    toast("创建数量必须在 1-50 之间", "err");
    return;
  }
  if (mode === "split" && !$("routeCidr").value.trim()) {
    toast("分流模式请填写客户端路由（真实内网网段）", "err");
    return;
  }
  const btn = $("createConfirm");
  btn.disabled = true;
  try {
    if (count === 1) {
      const res = await api("/api/peers", {
        method: "POST",
        body: JSON.stringify({
          name,
          route_mode: mode,
          route_cidr: $("routeCidr").value.trim(),
        }),
      });
      $("createModal").hidden = true;
      toast("客户端「" + name + "」创建成功", "ok");
      state.currentPeer = res.peer;
      state.currentConfig = res.config;
      await loadStatus(true);
      await loadPeers();
      openDetail(res.peer, res.config);
    } else {
      const res = await api("/api/peers/batch", {
        method: "POST",
        body: JSON.stringify({
          count,
          name_prefix: name,
          route_mode: mode,
          route_cidr: $("routeCidr").value.trim(),
        }),
      });
      $("createModal").hidden = true;
      toast("已批量创建 " + res.peers.length + " 个客户端", "ok");
      await loadStatus(true);
      await loadPeers();
    }
  } catch (e) {
    toast(e.message, "err");
  } finally {
    btn.disabled = false;
  }
}

/* ---------------- 详情弹窗（二维码 + 配置） ---------------- */

async function openDetail(peer, config) {
  if (!config) {
    try {
      const r = await fetch("/api/peers/" + peer.id + "/config");
      config = await r.text();
    } catch (e) {
      toast("获取配置失败", "err");
      return;
    }
  }
  state.currentPeer = peer;
  state.currentConfig = config;
  $("detailTitle").textContent = peer.name;
  $("cfgText").textContent = config;

  // 生成二维码（qrcode-generator）
  const box = $("qrBox");
  box.innerHTML = "";
  try {
    const qr = qrcode(0, "M");
    qr.addData(config);
    qr.make();
    const img = document.createElement("img");
    img.src = qr.createDataURL(6, 2);
    img.alt = "WireGuard 客户端配置二维码";
    box.appendChild(img);
  } catch (e) {
    box.innerHTML = '<p class="hint">二维码生成失败，可直接下载配置文件</p>';
  }
  $("detailModal").hidden = false;
}

function downloadConfig() {
  const peer = state.currentPeer;
  if (!peer || !state.currentConfig) return;
  const blob = new Blob([state.currentConfig], { type: "text/plain" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "wg-" + (peer.name || "client").replace(/[^\w\-]+/g, "_") + ".conf";
  document.body.appendChild(a);
  a.click();
  setTimeout(() => {
    URL.revokeObjectURL(a.href);
    a.remove();
  }, 200);
}

function copyConfig() {
  if (!state.currentConfig) return;
  const done = () => toast("客户端配置已复制", "ok");
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(state.currentConfig).then(done).catch(() => fallbackCopy(state.currentConfig, done));
  } else {
    fallbackCopy(state.currentConfig, done);
  }
}

/* ---------------- 删除 / 重置 ---------------- */

async function deletePeer(id) {
  const p = state.peers.find((x) => x.id === id);
  if (!p) return;
  if (!confirm("确定删除客户端「" + p.name + "」？该设备将立即无法连接。")) return;
  try {
    await api("/api/peers/" + id, { method: "DELETE" });
    toast("已删除客户端「" + p.name + "」", "ok");
    await loadStatus(true);
    await loadPeers();
  } catch (e) {
    toast(e.message, "err");
  }
}

async function resetServer() {
  if (!confirm("确定重置服务器？\n将删除全部客户端、密钥与配置，且需要重新初始化。")) return;
  if (!confirm("再次确认：此操作不可恢复，所有已生成的客户端配置将失效！")) return;
  try {
    await api("/api/reset", { method: "POST" });
    toast("服务器已重置", "ok");
    await loadStatus();
    await loadPeers();
  } catch (e) {
    toast(e.message, "err");
  }
}

async function destroyAll() {
  if (!confirm("确定卸载并删除全部数据？\n将删除 wireguard 容器、配置映射目录（含所有客户端密钥与配置）以及应用配置。")) return;
  if (!confirm("再次确认：此操作不可恢复！\n所有客户端将永久失效，需要重新部署并重新创建客户端。")) return;
  const btn = $("destroyBtn");
  btn.disabled = true;
  btn.textContent = "正在卸载并删除数据...";
  try {
    const res = await api("/api/container/destroy", { method: "POST" });
    toast(res.message, "ok");
    await loadStatus();
    await loadPeers();
  } catch (e) {
    toast(e.message, "err");
  } finally {
    btn.disabled = false;
    btn.textContent = "卸载并删除全部数据（容器 + 配置目录 + 客户端）";
  }
}

/* ---------------- 复制公钥 ---------------- */

function copyKey() {
  const key = $("serverKey").textContent;
  if (!key || key === "尚未生成") {
    toast("服务器公钥尚未生成", "err");
    return;
  }
  const done = () => toast("服务器公钥已复制", "ok");
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(key).then(done).catch(() => fallbackCopy(key, done));
  } else {
    fallbackCopy(key, done);
  }
}

function fallbackCopy(text, done) {
  const ta = document.createElement("textarea");
  ta.value = text;
  ta.style.position = "fixed";
  ta.style.opacity = "0";
  document.body.appendChild(ta);
  ta.select();
  try { document.execCommand("copy"); done(); } catch (e) { /* ignore */ }
  ta.remove();
}

/* ---------------- 事件绑定 ---------------- */

function bindEvents() {
  $("saveBtn").addEventListener("click", saveSettings);
  $("applyBtn").addEventListener("click", applyConfig);
  $("addBtn").addEventListener("click", openCreate);
  $("deployBtn").addEventListener("click", deployContainer);
  $("restartBtn").addEventListener("click", restartContainer);
  $("removeBtn").addEventListener("click", removeContainer);
  $("refreshBtn").addEventListener("click", () => {
    loadStatus();
    toast("已刷新", "ok");
  });
  $("copyKeyBtn").addEventListener("click", copyKey);
  $("resetBtn").addEventListener("click", resetServer);
  $("destroyBtn").addEventListener("click", destroyAll);
  $("createConfirm").addEventListener("click", confirmCreate);
  $("downloadBtn").addEventListener("click", downloadConfig);
  $("copyCfgBtn").addEventListener("click", copyConfig);

  $("peerName").addEventListener("keydown", (e) => {
    if (e.key === "Enter") confirmCreate();
  });

  // 路由模式切换
  document.querySelectorAll("#routeSeg .seg-btn").forEach((b) => {
    b.addEventListener("click", () => setRouteMode(b.dataset.route));
  });

  // 客户端操作（事件委托）
  $("peerList").addEventListener("click", (e) => {
    const btn = e.target.closest("[data-act]");
    if (!btn) return;
    const act = btn.dataset.act;
    const id = btn.dataset.id;
    const p = state.peers.find((x) => x.id === id);
    if (!p) return;
    if (act === "qr") openDetail(p);
    else if (act === "dl") {
      state.currentPeer = p;
      fetch("/api/peers/" + id + "/config")
        .then((r) => r.text())
        .then((cfg) => {
          state.currentConfig = cfg;
          downloadConfig();
        })
        .catch(() => toast("下载失败", "err"));
    } else if (act === "del") deletePeer(id);
  });

  // 关闭弹窗
  document.querySelectorAll("[data-close]").forEach((b) => {
    b.addEventListener("click", () => {
      const m = b.closest(".modal-mask");
      if (m) m.hidden = true;
    });
  });
  document.querySelectorAll(".modal-mask").forEach((m) => {
    m.addEventListener("click", (e) => {
      if (e.target === m) m.hidden = true;
    });
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      document.querySelectorAll(".modal-mask").forEach((m) => (m.hidden = true));
    }
  });
}

/* ---------------- 启动 ---------------- */

bindEvents();
loadStatus().then(() => {
  // 周期刷新客户端状态
  setInterval(() => {
    if (document.visibilityState === "visible") {
      loadStatus(true).then(() => loadPeers());
    }
  }, 10000);
});
