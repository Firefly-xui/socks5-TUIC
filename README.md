# 一键安装
在安装前请确保你的系统支持`bash`环境,且系统网络正常  


# 配置要求  
## 内存  
- 128MB minimal/256MB+ recommend  
## OS  
- Ubuntu 22-24

-FinalShell下载地址 [FinalShell](https://dl.hostbuf.com/finalshell3/finalshell_windows_x64.exe)

# socks5落地机搭建
请自行搭建socks5协议，或者参考：[3X-UI](https://github.com/Firefly-xui/3x-ui)。

# TUIC中转机搭建
```
bash <(curl -Ls https://raw.githubusercontent.com/Firefly-xui/socks5-TUIC/master/socks5-TUIC.sh)
```  

极速连接与低延迟：基于 QUIC over UDP，初次连接快（支持 0-RTT）；

天然抗丢包：自动适应丢包重传，非常适合波动大的移动网络；

Obfs 模式内置：内建 Salty / Salamander 混淆插件，绕过 DPI 检测；

密码认证 + TLS 模拟：能有效避免端口扫描和握手特征识别。

缺点：

纯 UDP 架构受部分运营商影响（如 NAT 设备封锁）；

部分地区存在对 UDP 流量限速策略（如校园网）；

v2rayN 等传统客户端支持较弱（需 plugin）；

适用场景：

海外 VPS 接入移动端；

追求低延迟流媒体服务；

与服务器之间稳定性可控时非常高效；


# 客户端配置

配置文件地址：/opt/tuic_relay_config.json

window配置V2rayN

V2rayN客户端下载[V2rayN](https://github.com/Firefly-xui/3x-ui/releases/download/3x-ui/v2rayN-windows-64.zip)。


| 协议组合                            | 抗封锁   | 延迟    | 稳定性   | 部署复杂度 | 适用建议       |
| ------------------------------- | ----- | ----- | ----- | ----- | ---------- |
| socks5 + TUIC       | ★★★★☆ | ★★★★★ | ★★★★☆ | ★★★★★ | 游戏直播等低延迟场景场景 |
| Hysteria2 + UDP + TLS + Obfs    | ★★★☆☆ | ★★★★★ | ★★★☆☆ | ★★☆☆☆ | 电影流媒体等大流量场景 |
| TUIC + UDP + QUIC + TLS         | ★★★★☆ | ★★★★★ | ★★★★☆ | ★★★★☆ | 游戏直播等低延迟场景场景 |
| VLESS + Reality + uTLS + Vision | ★★★★★ | ★★★☆☆ | ★★★★☆ | ★☆☆☆☆ | 安全可靠长期稳定场景     |

