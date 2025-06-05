#!/bin/sh
# /etc/sing-box/iptables-tproxy.sh
cmd="$1"
mark=1
listen_port=1536

# 定义跳过的 IPv4 网络
ipv4_skip="0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.17.0.0/16 192.0.0.0/24 192.168.0.0/24 224.0.0.0/4 240.0.0.0/4 255.255.255.255/32"
# 本地网段 192.168.1.0/24 （根据实际网络环境修改）
local_net="192.168.1.0/24"

# 定义跳过的 IPv6 网络
ipv6_skip="::1/128 fe80::/10"
ula_net="fd00::/8"  # ULA 网段

_add_rules() {
    # ---------------------- IPv4: mangle 表 PREROUTING ----------------------
    # 新建 DIVERT 链，用于 MATCH socket (透明代理) 的标记流量
    iptables -t mangle -N DIVERT 2>/dev/null || true
    iptables -t mangle -F DIVERT

    # 将与本地 socket 连接相关的 TCP 报文先跳到 DIVERT 链
    iptables -t mangle -A PREROUTING -p tcp -m socket -j DIVERT

    # DIVERT 链：对匹配的 TCP 报文标记并接受（prevent further processing）
    iptables -t mangle -A DIVERT -j MARK --set-mark $mark
    iptables -t mangle -A DIVERT -j ACCEPT

    # 跳过指定 IPv4 网段（PREROUTING 入口）
    for net in $ipv4_skip; do
        iptables -t mangle -A PREROUTING -d $net -j RETURN
    done
    # 跳过本地网段 (TCP 全部跳过；UDP 仅端口非 53 跳过)
    iptables -t mangle -A PREROUTING -d $local_net -p tcp -j RETURN
    iptables -t mangle -A PREROUTING -d $local_net -p udp ! --dport 53 -j RETURN

    # 跳过标记已设置的数据包（避免重复处理）
    iptables -t mangle -A PREROUTING -m mark --mark 0xff -j RETURN

    # 对其它 IPv4 TCP/UDP 流量使用 TPROXY 转发到本地端口
    iptables -t mangle -A PREROUTING -p tcp -j TPROXY --on-port $listen_port --tproxy-mark $mark/0x1
    iptables -t mangle -A PREROUTING -p udp -j TPROXY --on-port $listen_port --tproxy-mark $mark/0x1

    # ---------------------- IPv4: mangle 表 OUTPUT ----------------------
    # 本地发出的数据包（OUTPUT）同样跳过上述网段、已标记的包，然后打标记
    for net in $ipv4_skip; do
        iptables -t mangle -A OUTPUT -d $net -j RETURN
    done
    iptables -t mangle -A OUTPUT -d $local_net -p tcp -j RETURN
    iptables -t mangle -A OUTPUT -d $local_net -p udp ! --dport 53 -j RETURN
    iptables -t mangle -A OUTPUT -m mark --mark 0xff -j RETURN

    # 标记本地发出的 TCP/UDP 包
    iptables -t mangle -A OUTPUT -p tcp -j MARK --set-mark $mark
    iptables -t mangle -A OUTPUT -p udp -j MARK --set-mark $mark

    # ---------------------- IPv6: mangle 表 PREROUTING ----------------------
    ip6tables -t mangle -N DIVERT 2>/dev/null || true
    ip6tables -t mangle -F DIVERT
    ip6tables -t mangle -A PREROUTING -p tcp -m socket -j DIVERT
    ip6tables -t mangle -A DIVERT -j MARK --set-mark $mark
    ip6tables -t mangle -A DIVERT -j ACCEPT

    # 跳过指定 IPv6 网段
    for net in $ipv6_skip; do
        ip6tables -t mangle -A PREROUTING -d $net -j RETURN
    done
    # 跳过 ULA 网段 (TCP 全部跳过；UDP 仅端口非 53 跳过)
    ip6tables -t mangle -A PREROUTING -d $ula_net -p tcp -j RETURN
    ip6tables -t mangle -A PREROUTING -d $ula_net -p udp ! --dport 53 -j RETURN
    ip6tables -t mangle -A PREROUTING -m mark --mark 0xff -j RETURN

    # TPROXY 处理剩余的 IPv6 流量
    ip6tables -t mangle -A PREROUTING -p tcp -j TPROXY --on-port $listen_port --tproxy-mark $mark/0x1
    ip6tables -t mangle -A PREROUTING -p udp -j TPROXY --on-port $listen_port --tproxy-mark $mark/0x1

    # ---------------------- IPv6: mangle 表 OUTPUT ----------------------
    for net in $ipv6_skip; do
        ip6tables -t mangle -A OUTPUT -d $net -j RETURN
    done
    ip6tables -t mangle -A OUTPUT -d $ula_net -p tcp -j RETURN
    ip6tables -t mangle -A OUTPUT -d $ula_net -p udp ! --dport 53 -j RETURN
    ip6tables -t mangle -A OUTPUT -m mark --mark 0xff -j RETURN

    ip6tables -t mangle -A OUTPUT -p tcp -j MARK --set-mark $mark
    ip6tables -t mangle -A OUTPUT -p udp -j MARK --set-mark $mark
}

_del_rules() {
    # 删除所有添加的规则（根据实际情况可更精确地删除各条规则）
    iptables -t mangle -F PREROUTING
    iptables -t mangle -F OUTPUT
    iptables -t mangle -F DIVERT
    iptables -t mangle -X DIVERT 2>/dev/null

    ip6tables -t mangle -F PREROUTING
    ip6tables -t mangle -F OUTPUT
    ip6tables -t mangle -F DIVERT
    ip6tables -t mangle -X DIVERT 2>/dev/null
}

case "$cmd" in
    start)
        _add_rules
        ;;
    stop)
        _del_rules
        ;;
    *)
        echo "Usage: $0 {start|stop}"
        ;;
esac

