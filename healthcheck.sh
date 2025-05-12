#!/bin/sh

# 读取 SOCKS 配置
CONFIG_PATH="/app/etc/config.json"
PORT=$(jq -r '.socks.port' $CONFIG_PATH)
USERNAME=$(jq -r '.socks.username' $CONFIG_PATH)
PASSWORD=$(jq -r '.socks.password' $CONFIG_PATH)

# 设置默认端口
if [ -z "$PORT" ] || [ "$PORT" = "null" ]; then
    PORT="1080"  # 默认端口
fi

# 使用 curl 通过 SOCKS 代理检查连接
check_url() {
    if [ -n "$USERNAME" ] && [ "$USERNAME" != "null" ] && [ -n "$PASSWORD" ] && [ "$PASSWORD" != "null" ]; then
        curl --silent --connect-timeout 5 --max-time 10 --socks5 "127.0.0.1:$PORT" --proxy-user "$USERNAME:$PASSWORD" "$1" -o /dev/null -w "%{http_code}"
    else
        curl --silent --connect-timeout 5 --max-time 10 --socks5 "127.0.0.1:$PORT" "$1" -o /dev/null -w "%{http_code}"
    fi
}

status_gstatic=$(check_url "http://connectivitycheck.gstatic.com/generate_204")


if [ "$status_gstatic" = "204" ]; then
    echo "[Health Check] OK(Google)"
    exit 0
fi

status_cloudflare=$(check_url "http://cp.cloudflare.com/")
if [ "$status_cloudflare" = "204" ]; then
    echo "[Health Check] OK(Cloudflare)"
    exit 0
else
    echo "[Health Check] Failed!!!"
    exit 1
fi
