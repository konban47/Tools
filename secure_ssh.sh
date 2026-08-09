#!/usr/bin/env bash

# Debian/Ubuntu SSH + Fail2ban hardening script.
# Safe to run through: bash <(curl -fsSL URL) --ssh-port 29648 ...

set -Eeuo pipefail
umask 077

readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

SSH_PORT=''
MAX_RETRY='3'
BAN_TIME='-1'
FIND_TIME='1h'
ROOT_LOGIN='unchanged'
NON_INTERACTIVE=0
MANAGE_UFW=0

BACKUP_DIR=''
SSH_SERVICE=''
MODIFIED=0
COMMITTED=0
UFW_RULE_ADDED=0

SSH_CONFIG='/etc/ssh/sshd_config'
SSH_DROPIN='/etc/ssh/sshd_config.d/00-secure-ssh.conf'
F2B_CONFIG='/etc/fail2ban/jail.d/sshd.local'

info() { printf '%b\n' "${BLUE}$*${NC}"; }
ok() { printf '%b\n' "${GREEN}$*${NC}"; }
warn() { printf '%b\n' "${YELLOW}$*${NC}" >&2; }
die() { printf '%b\n' "${RED}错误: $*${NC}" >&2; return 1; }

usage() {
    cat <<'EOF'
用法:
  secure_ssh.sh --ssh-port PORT [选项]

选项:
  --ssh-port PORT              SSH 监听端口（1-65535，必填）
  --max-retry N                Fail2ban 最大失败次数（默认 3）
  --bantime TIME               封禁时长（默认 -1，即永久）
  --findtime TIME              统计窗口（默认 1h）
  --permit-root-login VALUE    yes、prohibit-password、no 或 unchanged
  --manage-ufw                 仅当 UFW 已启用时放行新端口；绝不启用 UFW
  --non-interactive            禁止交互，缺少必填参数时直接报错
  -h, --help                   显示帮助

示例:
  bash <(curl -fsSL https://example/secure_ssh.sh) \
    --ssh-port 29648 --max-retry 3 --bantime -1 \
    --permit-root-login yes --non-interactive
EOF
}

need_value() {
    [[ $# -ge 2 && -n ${2:-} ]] || die "参数 $1 缺少值"
}

while (($#)); do
    case "$1" in
        --) shift ;;
        --ssh-port)
            need_value "$@"; SSH_PORT=$2; shift 2 ;;
        --max-retry)
            need_value "$@"; MAX_RETRY=$2; shift 2 ;;
        --bantime)
            need_value "$@"; BAN_TIME=$2; shift 2 ;;
        --findtime)
            need_value "$@"; FIND_TIME=$2; shift 2 ;;
        --permit-root-login)
            need_value "$@"; ROOT_LOGIN=$2; shift 2 ;;
        --manage-ufw)
            MANAGE_UFW=1; shift ;;
        --non-interactive)
            NON_INTERACTIVE=1; shift ;;
        -h|--help)
            usage; exit 0 ;;
        *)
            die "未知参数: $1（使用 --help 查看帮助）" ;;
    esac
done

[[ ${EUID:-$(id -u)} -eq 0 ]] || die '必须以 root 权限运行'

if [[ -z $SSH_PORT && $NON_INTERACTIVE -eq 0 && -r /dev/tty ]]; then
    printf '请输入新 SSH 端口: ' >/dev/tty
    read -r SSH_PORT </dev/tty
fi

[[ -n $SSH_PORT ]] || die '必须指定 --ssh-port'
[[ $SSH_PORT =~ ^[0-9]+$ ]] || die 'SSH 端口必须是整数'
((SSH_PORT >= 1 && SSH_PORT <= 65535)) || die 'SSH 端口范围必须是 1-65535'
[[ $MAX_RETRY =~ ^[0-9]+$ ]] || die '--max-retry 必须是整数'
((MAX_RETRY >= 1 && MAX_RETRY <= 100)) || die '--max-retry 范围必须是 1-100'

case "$ROOT_LOGIN" in
    yes|prohibit-password|forced-commands-only|no|unchanged) ;;
    *) die '--permit-root-login 必须是 yes、prohibit-password、no 或 unchanged' ;;
esac

[[ -r /etc/os-release ]] || die '无法识别操作系统'
# shellcheck disable=SC1091
. /etc/os-release
case "${ID:-}" in
    debian|ubuntu) ;;
    *) die "仅支持 Debian/Ubuntu，当前系统为 ${ID:-未知}" ;;
esac

for cmd in awk cp flock grep install mktemp ss systemctl; do
    command -v "$cmd" >/dev/null 2>&1 || die "缺少必要命令: $cmd"
done

exec 9>/run/lock/secure-ssh.lock
flock -n 9 || die '另一个 secure_ssh.sh 实例正在运行'

if [[ -x /usr/sbin/sshd ]]; then
    SSHD_BIN='/usr/sbin/sshd'
else
    SSHD_BIN=$(command -v sshd || true)
fi
[[ -n ${SSHD_BIN:-} ]] || die '未找到 sshd，请先安装 openssh-server'
[[ -f $SSH_CONFIG ]] || die "未找到 $SSH_CONFIG"

if systemctl cat ssh.service >/dev/null 2>&1; then
    SSH_SERVICE='ssh.service'
elif systemctl cat sshd.service >/dev/null 2>&1; then
    SSH_SERVICE='sshd.service'
else
    die '未找到 SSH systemd 服务'
fi

mapfile -t OLD_PORTS < <("$SSHD_BIN" -T | awk '$1 == "port" {print $2}')
OLD_ROOT_LOGIN=$("$SSHD_BIN" -T | awk '$1 == "permitrootlogin" {print $2; exit}')
CURRENT_IP=${SSH_CONNECTION:-}
CURRENT_IP=${CURRENT_IP%% *}
[[ -n $CURRENT_IP ]] || CURRENT_IP='未知'

info "当前 SSH 端口: ${OLD_PORTS[*]:-未知}；当前 PermitRootLogin: ${OLD_ROOT_LOGIN:-未知}"
info "当前连接 IP: $CURRENT_IP"

if ! printf '%s\n' "${OLD_PORTS[@]}" | grep -qx "$SSH_PORT"; then
    OCCUPIED=$(ss -H -ltnp | awk -v suffix=":$SSH_PORT" '$4 ~ (suffix "$") {print}')
    [[ -z $OCCUPIED ]] || die "端口 $SSH_PORT 已被占用: $OCCUPIED"
fi

# Port 可多次声明；为保证旧端口真正关闭，拒绝隐藏在 drop-in 中的额外 Port。
EXTRA_PORT_FILES=$(grep -Els '^[[:space:]]*Port[[:space:]]+[0-9]+' /etc/ssh/sshd_config.d/*.conf 2>/dev/null || true)
if [[ -n $EXTRA_PORT_FILES && $EXTRA_PORT_FILES != "$SSH_DROPIN" ]]; then
    die "其他 SSH drop-in 中存在 Port 指令，请先人工处理: $EXTRA_PORT_FILES"
fi

UFW_ACTIVE=0
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q '^Status: active'; then
    if [[ $MANAGE_UFW -eq 0 ]]; then
        die '检测到 UFW 已启用。为防止锁死，请加 --manage-ufw；该选项只放行端口，不会启用 UFW'
    fi
    UFW_ACTIVE=1
else
    info 'UFW 未启用；脚本不会安装、启用或修改 UFW。'
fi

if ! dpkg-query -W -f='${db:Status-Abbrev}' fail2ban 2>/dev/null | grep -q '^ii '; then
    info '正在安装 Fail2ban...'
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y --no-install-recommends fail2ban
fi

install -d -m 0755 /etc/ssh/sshd_config.d /etc/fail2ban/jail.d /var/backups/secure-ssh
BACKUP_DIR="/var/backups/secure-ssh/$(date -u +%Y%m%dT%H%M%SZ)-$$"
install -d -m 0700 "$BACKUP_DIR"

SSH_DROPIN_EXISTED=0
F2B_EXISTED=0
cp -a "$SSH_CONFIG" "$BACKUP_DIR/sshd_config"
if [[ -e $SSH_DROPIN ]]; then
    SSH_DROPIN_EXISTED=1
    cp -a "$SSH_DROPIN" "$BACKUP_DIR/00-secure-ssh.conf"
fi
if [[ -e $F2B_CONFIG ]]; then
    F2B_EXISTED=1
    cp -a "$F2B_CONFIG" "$BACKUP_DIR/sshd.local"
fi

rollback() {
    local exit_code=$1 line=$2
    trap - ERR
    if [[ $MODIFIED -eq 1 && $COMMITTED -eq 0 ]]; then
        warn "第 $line 行执行失败，正在从 $BACKUP_DIR 回滚..."
        cp -a "$BACKUP_DIR/sshd_config" "$SSH_CONFIG"
        if [[ $SSH_DROPIN_EXISTED -eq 1 ]]; then
            cp -a "$BACKUP_DIR/00-secure-ssh.conf" "$SSH_DROPIN"
        else
            rm -f "$SSH_DROPIN"
        fi
        if [[ $F2B_EXISTED -eq 1 ]]; then
            cp -a "$BACKUP_DIR/sshd.local" "$F2B_CONFIG"
        else
            rm -f "$F2B_CONFIG"
        fi
        "$SSHD_BIN" -t && systemctl restart "$SSH_SERVICE" || true
        fail2ban-client -t >/dev/null 2>&1 && systemctl restart fail2ban.service || true
    fi
    if [[ $UFW_RULE_ADDED -eq 1 ]]; then
        ufw --force delete allow "${SSH_PORT}/tcp" >/dev/null 2>&1 || true
    fi
    exit "$exit_code"
}
trap 'rollback "$?" "$LINENO"' ERR

TMP_MAIN=$(mktemp)
TMP_SSH=$(mktemp)
TMP_F2B=$(mktemp)
cleanup_tmp() { rm -f "$TMP_MAIN" "$TMP_SSH" "$TMP_F2B"; }
trap cleanup_tmp EXIT

# 只改全局首个 Port，并注释其余全局 Port，保留文件的其他内容与 Match 块。
awk -v new_port="$SSH_PORT" '
    BEGIN { inserted = 0; in_match = 0 }
    /^[[:space:]]*Match[[:space:]]/ {
        if (!inserted) { print "Port " new_port; inserted = 1 }
        in_match = 1
    }
    !in_match && /^[[:space:]]*#?[[:space:]]*Port[[:space:]]+[0-9]+([[:space:]]|$)/ {
        if (!inserted) { print "Port " new_port; inserted = 1 }
        else { print "# " $0 "  # disabled by secure_ssh.sh" }
        next
    }
    { print }
    END { if (!inserted) print "Port " new_port }
' "$SSH_CONFIG" >"$TMP_MAIN"

{
    echo '# Managed by secure_ssh.sh. Local changes may be overwritten.'
    [[ $ROOT_LOGIN == unchanged ]] || echo "PermitRootLogin $ROOT_LOGIN"
    echo 'PermitEmptyPasswords no'
    echo "MaxAuthTries $MAX_RETRY"
    echo 'LoginGraceTime 30'
    echo 'IgnoreRhosts yes'
    echo 'HostbasedAuthentication no'
    echo 'UseDNS no'
    echo 'LogLevel VERBOSE'
} >"$TMP_SSH"

cat >"$TMP_F2B" <<EOF
# Managed by secure_ssh.sh. Local changes may be overwritten.
[sshd]
enabled = true
port = $SSH_PORT
backend = systemd
mode = normal
ignoreip = 127.0.0.1/8 ::1
findtime = $FIND_TIME
maxretry = $MAX_RETRY
bantime = $BAN_TIME
EOF

MODIFIED=1
install -m 0600 "$TMP_MAIN" "$SSH_CONFIG"
install -m 0600 "$TMP_SSH" "$SSH_DROPIN"
install -m 0644 "$TMP_F2B" "$F2B_CONFIG"

info '正在校验 SSH 配置...'
"$SSHD_BIN" -t
mapfile -t EFFECTIVE_PORTS < <("$SSHD_BIN" -T | awk '$1 == "port" {print $2}')
[[ ${#EFFECTIVE_PORTS[@]} -eq 1 && ${EFFECTIVE_PORTS[0]} == "$SSH_PORT" ]] || \
    die "SSH 生效端口不是唯一的 $SSH_PORT，而是: ${EFFECTIVE_PORTS[*]:-未知}"

if [[ $ROOT_LOGIN != unchanged ]]; then
    EFFECTIVE_ROOT=$("$SSHD_BIN" -T | awk '$1 == "permitrootlogin" {print $2; exit}')
    [[ $EFFECTIVE_ROOT == "$ROOT_LOGIN" ]] || \
        die "PermitRootLogin 未按预期生效（实际: $EFFECTIVE_ROOT）"
fi

EFFECTIVE_MAX_AUTH=$("$SSHD_BIN" -T | awk '$1 == "maxauthtries" {print $2; exit}')
[[ $EFFECTIVE_MAX_AUTH == "$MAX_RETRY" ]] || \
    die "MaxAuthTries 未按预期生效（实际: $EFFECTIVE_MAX_AUTH）"

info '正在校验 Fail2ban 配置...'
fail2ban-client -t

if [[ $UFW_ACTIVE -eq 1 ]] && ! ufw status | grep -Eq "(^|[[:space:]])${SSH_PORT}/tcp([[:space:]]|$)"; then
    info "UFW 已启用，正在放行 ${SSH_PORT}/tcp（不会启用或重置 UFW）..."
    ufw allow "${SSH_PORT}/tcp"
    UFW_RULE_ADDED=1
fi

info '正在重启 SSH 与 Fail2ban...'
systemctl restart "$SSH_SERVICE"
systemctl enable --now fail2ban.service >/dev/null
systemctl restart fail2ban.service
systemctl is-active --quiet "$SSH_SERVICE"
systemctl is-active --quiet fail2ban.service

for _ in {1..20}; do
    if ss -H -ltn | awk -v suffix=":$SSH_PORT" '$4 ~ (suffix "$") {found=1} END {exit !found}'; then
        break
    fi
    sleep 0.25
done
ss -H -ltn | awk -v suffix=":$SSH_PORT" '$4 ~ (suffix "$") {found=1} END {exit !found}'

fail2ban-client status sshd >/dev/null
JAIL_PORT=''
while IFS= read -r action; do
    if action_port=$(fail2ban-client get sshd action "$action" port 2>/dev/null); then
        JAIL_PORT=$(printf '%s' "$action_port" | tr -d '[:space:]')
        break
    fi
done < <(fail2ban-client get sshd actions | awk 'NR > 1 && NF == 1 {print $1}')
JAIL_RETRY=$(fail2ban-client get sshd maxretry | tr -d '[:space:]')
JAIL_BANTIME=$(fail2ban-client get sshd bantime | tr -d '[:space:]')
[[ $JAIL_PORT == "$SSH_PORT" ]] || die "Fail2ban sshd 端口未生效（实际: $JAIL_PORT）"
[[ $JAIL_RETRY == "$MAX_RETRY" ]] || die "Fail2ban maxretry 未生效（实际: $JAIL_RETRY）"
[[ $JAIL_BANTIME == "$BAN_TIME" ]] || die "Fail2ban bantime 未生效（实际: $JAIL_BANTIME）"

COMMITTED=1
ok 'SSH 与 Fail2ban 配置完成。'
printf '%b\n' "SSH 端口: ${YELLOW}$SSH_PORT${NC}"
printf '%b\n' "PermitRootLogin: ${YELLOW}${ROOT_LOGIN/unchanged/$OLD_ROOT_LOGIN}${NC}"
printf '%b\n' "Fail2ban: ${YELLOW}${FIND_TIME} 内失败 ${MAX_RETRY} 次，封禁 ${BAN_TIME}${NC}"
printf '%b\n' "备份目录: ${YELLOW}$BACKUP_DIR${NC}"
warn "请保留当前会话，并从新终端验证: ssh -p $SSH_PORT root@<服务器IP>"
