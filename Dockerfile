# fn-wg-web - WireGuard 管理器（Docker 版）
#
# 架构说明：
#   管理容器通过挂载宿主机 docker.sock 创建/管理 wireguard 容器（与 fnOS 版同架构），
#   所有 WireGuard 配置读写通过 `docker exec` 进入 wireguard 容器完成，
#   因此无需在 compose 中挂载宿主机映射目录。
#
# 构建：
#   docker build -t fn-wg-web:0.3.3 .
#   docker compose up -d --build

FROM python:3.12-alpine

# docker CLI：通过宿主 socket 执行 docker 命令管理 wireguard 容器
# tzdata：TZ 环境变量生效需要
RUN apk add --no-cache docker-cli tzdata

ENV WG_WEB_BASE=/usr/fn-wg-web \
    WG_DATA_BASE=/var/apps/fn-wg-web/var \
    WG_CONTAINER_NAME=wireguard \
    WG_CONTAINER_IMAGE=linuxserver/wireguard:latest \
    TZ=Asia/Shanghai

# 程序文件（wg-manager.py + web/）
COPY pkg/files/ /usr/fn-wg-web/

# 数据目录（state.json 持久化，compose 中以命名卷挂载）
RUN mkdir -p /var/apps/fn-wg-web/var

EXPOSE 51821

# 健康检查：管理端口始终返回 200（未登录时返回登录页）
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget -qO /dev/null http://127.0.0.1:51821/ || exit 1

CMD ["python3", "/usr/fn-wg-web/wg-manager.py", "--host", "0.0.0.0", "--port", "51821"]
