#!/bin/bash

# ==========================================================
# 脚本名称: Debian 12 SSH & Fail2ban 全能加固脚本 (带临时白名单)
# 功能: 修改端口、48h临时白名单、Fail2ban配置、SSH硬化
# ==========================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# 1. 权限与系统检查
[[ $EUID -ne 0 ]] && echo -e "${RED}错误: 必须以 root 权限运行！${NC}" && exit 1

# 2. 获取当前 IP
CURRENT_IP=$(who am i | awk '{print $NF}' | tr -d '()')
# 如果是本地终端或获取失败，设为空
[[ "$CURRENT_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || CURRENT_IP=""

echo -e "${BLUE}检测到您的当前登录 IP 为: ${YELLOW}${CURRENT_IP:-"未知"}${NC}"

# 3. 用户交互输入
echo -e "${GREEN}--- 配置选项 ---${NC}"

while true; do
    read -p "请输入新 SSH 端口 (1024-65535, 默认 22): " SSH_PORT
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

read -p "是否禁止 root 直接登录? (y/n, 默认 n): " DENY_ROOT
read -p "最大尝试次数 (默认 3): " MAX_RETRY
MAX_RETRY=${MAX_RETRY:-3}

read -p "封禁时长 (如 1h, 1d, -1为永久, 默认 24h): " BAN_TIME
BAN_TIME=${BAN_TIME:-24h}

# 新增：白名单时长
read -p "当前 IP 白名单有效时长 (如 48h, 7d, 默认 48h): " WHITE_TIME
WHITE_TIME=${WHITE_TIME:-48h}

# 4. 安装依赖
echo -e "${BLUE}正在同步仓库并安装必要软件...${NC}"
apt update && apt install -y fail2ban curl ufw sed

# 5. SSH 配置硬化
echo -e "${BLUE}正在配置 SSH 服务...${NC}"
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%F)
sed -i "s/^#Port 22/Port $SSH_PORT/" /etc/ssh/sshd_config
sed -i "s/^Port [0-9]*/Port $SSH_PORT/" /etc/ssh/sshd_config

if [[ "$DENY_ROOT" == "y" ]]; then
    sed -i "s/^#PermitRootLogin.*/PermitRootLogin no/" /etc/ssh/sshd_config
    sed -i "s/^PermitRootLogin.*/PermitRootLogin no/" /etc/ssh/sshd_config
fi

# 6. 防火墙配置
if command -v ufw >/dev/null 2>&1; then
    ufw allow "$SSH_PORT"/tcp
    [[ "$(ufw status)" == "status: inactive" ]] && ufw --force enable
fi

# 7. Fail2ban 高级配置
echo -e "${BLUE}正在生成 Fail2ban 配置文件...${NC}"
# 注意：ignoreip 中加入了 $CURRENT_IP
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

# 8. 核心逻辑：创建定时移除任务
if [[ -n "$CURRENT_IP" ]]; then
    echo -e "${BLUE}正在创建白名单自动清理任务 (有效期: $WHITE_TIME)...${NC}"
    
    # 使用 systemd-run 创建一次性定时任务
    # 任务逻辑：等待指定时间后，从 ignoreip 中删除该 IP 并重启 fail2ban
    systemd-run --unit="f2b-unwhitelist-${CURRENT_IP//./-}" \
                --on-active="$WHITE_TIME" \
                /bin/bash -c "sed -i 's/ $CURRENT_IP//g' /etc/fail2ban/jail.local && systemctl restart fail2ban"
    
    echo -e "${YELLOW}任务已创建：$CURRENT_IP 将在 $WHITE_TIME 后从白名单中移除。${NC}"
fi

# 9. 重启服务
systemctl restart ssh
systemctl restart fail2ban

# 10. 结果报告
echo -e "\n${GREEN}==============================================${NC}"
echo -e "新 SSH 端口: ${YELLOW}$SSH_PORT${NC}"
echo -e "白名单 IP: ${YELLOW}${CURRENT_IP:-"无"}${NC}"
echo -e "白名单有效期: ${YELLOW}$WHITE_TIME${NC}"
echo -e "封禁策略: ${YELLOW}1小时内失败 $MAX_RETRY 次即封禁 $BAN_TIME${NC}"
echo -e "${RED}请务必新开窗口测试登录: ssh -p $SSH_PORT user@$(curl -s ifconfig.me)${NC}"
echo -e "${GREEN}==============================================${NC}"
