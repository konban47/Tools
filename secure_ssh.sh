#!/bin/bash

# ==========================================================
# 脚本名称: Debian 12 SSH & Fail2ban 全能加固脚本 (Pipe兼容版)
# ==========================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# 1. 权限与系统检查
[[ $EUID -ne 0 ]] && echo -e "${RED}错误: 必须以 root 权限运行！${NC}" && exit 1

# 2. 获取当前 IP (更鲁棒的检测方式)
CURRENT_IP=$(echo $SSH_CLIENT | awk '{print $1}')
[ -z "$CURRENT_IP" ] && CURRENT_IP=$(who am i | awk '{print $NF}' | tr -d '()')
[[ "$CURRENT_IP" =~ ^[0-9a-fA-F:.]+$ ]] || CURRENT_IP="未知"

echo -e "${BLUE}检测到您的当前登录 IP 为: ${YELLOW}$CURRENT_IP${NC}"

# 3. 用户交互输入 (关键点：使用 < /dev/tty 强制读取键盘)
echo -e "${GREEN}--- 配置选项 ---${NC}"

while true; do
    echo -n "请输入新 SSH 端口 (1024-65535, 默认 22): "
    read SSH_PORT < /dev/tty
    SSH_PORT=${SSH_PORT:-22}
    if [[ "$SSH_PORT" -eq 22 ]]; then break; fi
    if [[ "$SSH_PORT" -lt 1024 || "$SSH_PORT" -gt 65535 ]]; then
        echo -e "${RED}无效端口，请输入 1024-65535。${NC}"
    elif ss -tuln | grep -q ":$SSH_PORT "; then
        echo -e "${RED}端口 $SSH_PORT 已被占用。${NC}"
    else
        break
    fi
done

echo -n "是否禁止 root 直接登录? (y/n, 默认 n): "
read DENY_ROOT < /dev/tty

echo -n "最大尝试次数 (默认 3): "
read MAX_RETRY < /dev/tty
MAX_RETRY=${MAX_RETRY:-3}

echo -n "封禁时长 (如 1h, 1d, -1为永久, 默认 24h): "
read BAN_TIME < /dev/tty
BAN_TIME=${BAN_TIME:-24h}

echo -n "当前 IP 白名单有效时长 (如 48h, 7d, 默认 48h): "
read WHITE_TIME < /dev/tty
WHITE_TIME=${WHITE_TIME:-48h}

# 4. 安装依赖
echo -e "${BLUE}正在同步仓库并安装必要软件...${NC}"
apt update && apt install -y fail2ban curl ufw sed

# 5. SSH 配置硬化
echo -e "${BLUE}正在配置 SSH 服务...${NC}"
cp /etc/ssh/sshd_config "/etc/ssh/sshd_config.bak.$(date +%F)"
sed -i "s/^#Port 22/Port $SSH_PORT/" /etc/ssh/sshd_config
sed -i "s/^Port [0-9]*/Port $SSH_PORT/" /etc/ssh/sshd_config

if [[ "$DENY_ROOT" == "y" ]]; then
    sed -i "s/^#PermitRootLogin.*/PermitRootLogin no/" /etc/ssh/sshd_config
    sed -i "s/^PermitRootLogin.*/PermitRootLogin no/" /etc/ssh/sshd_config
fi

# 6. 防火墙配置
if command -v ufw >/dev/null 2>&1; then
    ufw allow "$SSH_PORT"/tcp
    if [[ "$(ufw status)" == "status: inactive" ]]; then
        echo -n "是否现在开启 UFW? (y/n): "
        read ENABLE_UFW < /dev/tty
        [[ "$ENABLE_UFW" == "y" ]] && ufw --force enable
    fi
fi

# 7. Fail2ban 高级配置
echo -e "${BLUE}正在生成 Fail2ban 配置文件...${NC}"
cat <<EOF > /etc/fail2ban/jail.local
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1 $CURRENT_IP
bantime = $BAN_TIME
findtime = 1h
maxretry = $MAX_RETRY
backend = systemd

[sshd]
enabled = true
port = $SSH_PORT
logpath = %(sshd_log)s
mode = normal
EOF

# 8. 创建定时移除任务 (如果 IP 识别成功)
if [[ "$CURRENT_IP" != "未知" ]]; then
    # 格式化 IP 字符串用于 Unit 名称 (点换成横杠)
    SAFE_IP=$(echo $CURRENT_IP | sed 's/[.:]/-/g')
    systemd-run --unit="f2b-unwhitelist-$SAFE_IP" \
                --on-active="$WHITE_TIME" \
                /bin/bash -c "sed -i 's/ $CURRENT_IP//g' /etc/fail2ban/jail.local && systemctl restart fail2ban"
fi

# 9. 重启服务
systemctl restart ssh
systemctl restart fail2ban

# 10. 结果报告
echo -e "\n${GREEN}==============================================${NC}"
echo -e "新 SSH 端口: ${YELLOW}$SSH_PORT${NC}"
echo -e "白名单 IP: ${YELLOW}$CURRENT_IP${NC}"
echo -e "白名单有效期: ${YELLOW}$WHITE_TIME${NC}"
echo -e "封禁策略: ${YELLOW}1小时内失败 $MAX_RETRY 次即封禁 $BAN_TIME${NC}"
echo -e "${RED}重要提示: 请保留当前终端，新开窗口尝试登录！${NC}"
echo -e "测试命令: ssh -p $SSH_PORT 用户名@$(curl -s ifconfig.me || echo '你的服务器IP')${NC}"
echo -e "${GREEN}==============================================${NC}"
