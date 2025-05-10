#!/bin/sh
set -e


# 配置文件路径
CONFIG_PATH=${CONFIG_PATH:-"/app/etc/config.json"}

# 创建参数数组
ARGS=()

# 添加配置文件参数
ARGS+=("--config" "$CONFIG_PATH")

# 处理设备名称（如果提供）
if [ ! -z "$DEVICE_NAME" ]; then
  ARGS+=("--name" "$DEVICE_NAME")
fi

# 处理区域设置
if [ ! -z "$LOCALE" ]; then
  ARGS+=("--locale" "$LOCALE")
else
  ARGS+=("--locale" "zh_CN")
fi

# 处理设备模型
if [ ! -z "$MODEL" ]; then
  ARGS+=("--model" "$MODEL")
fi

# 处理JWT令牌（如果是团队注册）
if [ ! -z "$JWT" ]; then
  ARGS+=("--jwt" "$JWT")
fi

# 处理是否接受服务条款
if [ ! -z "$ACCEPT_TOS" ]; then
  ARGS+=("--accept-tos" "$ACCEPT_TOS")
else
  ARGS+=("--accept-tos" "true")
fi

# 处理是否重置SOCKS5配置
if [ ! -z "$RESET_CONFIG" ] && [ "$RESET_CONFIG" = "true" ]; then
  ARGS+=("--reset-config")
fi

echo "========================="
echo "启动USCF代理服务..."
echo "配置文件路径: $CONFIG_PATH"
echo "========================="

# 捕获SIGTERM和SIGINT信号以优雅退出
trap 'echo "接收到终止信号，正在关闭服务..."; exit 0' TERM INT

# 执行uscf proxy命令并传递参数
exec /bin/uscf proxy "${ARGS[@]}"



