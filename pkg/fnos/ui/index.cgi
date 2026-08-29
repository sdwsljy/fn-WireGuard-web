#!/bin/sh
# 本应用已迁移到 fnOS 统一网关，不再监听独立 TCP 端口（51821）。
# 兼容旧版 CGI 入口：直接跳转到统一网关路径（经 fnOS 登录态校验后转发到应用 Unix Socket）。
cat <<'EOF'
Content-Type: text/html

<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WireGuard 管理器</title>
<meta http-equiv="refresh" content="0;url=/app/fn-wg-web/">
<script>location.replace('/app/fn-wg-web/');</script>
</head>
<body>
<p>正在跳转到 <a href="/app/fn-wg-web/">WireGuard 管理器</a>...</p>
</body>
</html>
EOF
