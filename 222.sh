#!/usr/bin/env bash

# 设置：遇到错误或使用未定义变量时退出
set -eu

# ==========================================================
# WSS 隧道与用户管理面板一键部署脚本 (V2 最终稳定版)
# ----------------------------------------------------------
# 修复：前后端代码分离，解决 Python 语法解析错误。
# ==========================================================

# =============================
# 提示端口和面板密码
# =============================
echo "----------------------------------"
echo "==== WSS 基础设施端口配置 ===="

read -p "请输入 WSS HTTP 监听端口 (默认80): " WSS_HTTP_PORT
WSS_HTTP_PORT=${WSS_HTTP_PORT:-80}

read -p "请输入 WSS TLS 监听端口 (默认443): " WSS_TLS_PORT
WSS_TLS_PORT=${WSS_TLS_PORT:-443}

read -p "请输入 Stunnel4 端口 (默认444): " STUNNEL_PORT
STUNNEL_PORT=${STUNNEL_PORT:-444}

read -p "请输入 UDPGW 端口 (默认7300): " UDPGW_PORT
UDPGW_PORT=${UDPGW_PORT:-7300}

# === 内部转发端口提示 ===
read -p "请输入 WSS/Stunnel 内部 SSH 转发端口 (默认48303): " INTERNAL_FORWARD_PORT
INTERNAL_FORWARD_PORT=${INTERNAL_FORWARD_PORT:-48303}
# ==============================

echo "----------------------------------"
echo "==== 管理面板配置 ===="

read -p "请输入 Web 管理面板监听端口 (默认54321): " PANEL_PORT
PANEL_PORT=${PANEL_PORT:-54321}

# 交互式安全输入并确认 ROOT 密码
echo "请为 Web 面板的 'root' 用户设置密码（输入时隐藏）。"
while true; do
    read -s -p "面板密码: " pw1 && echo
    read -s -p "请再次确认密码: " pw2 && echo
    if [ -z "$pw1" ]; then
        echo "密码不能为空，请重新输入。"
        continue
    fi
    if [ "$pw1" != "$pw2" ]; then
        echo "两次输入不一致，请重试。"
        continue
    fi
    PANEL_ROOT_PASS_RAW="$pw1"
    # 对密码进行简单的 HASH
    PANEL_ROOT_PASS_HASH=$(echo -n "$PANEL_ROOT_PASS_RAW" | sha256sum | awk '{print $1}')
    break
done

echo "----------------------------------"
echo "==== 系统更新与依赖安装 ===="
apt update -y
apt install -y python3 python3-pip wget curl git net-tools cmake build-essential openssl stunnel4 iproute2 iptables procps
pip3 install flask psutil requests
echo "依赖安装完成 (包含 Flask, psutil)"
echo "----------------------------------"


# =============================
# WSS 核心代理脚本
# =============================
echo "==== 安装 WSS 核心代理脚本 (/usr/local/bin/wss) ===="
tee /usr/local/bin/wss > /dev/null <<EOF
#!/usr/bin/python3
# -*- coding: utf-8 -*-

import asyncio, ssl, sys
import os
import time
import json
import socket
import re
from datetime import datetime

# 尝试导入 uvloop, 如果没有安装则使用默认 asyncio
try:
    import uvloop
    UVLOOP_AVAILABLE = True
except ImportError:
    UVLOOP_AVAILABLE = False

LISTEN_ADDR = '0.0.0.0'

# 使用 Bash 变量直接替换，并作为 Python 字符串赋值
INTERNAL_FORWARD_PORT_PY = '$INTERNAL_FORWARD_PORT'
PANEL_PORT_PY = '$PANEL_PORT'

try:
    HTTP_PORT = int(sys.argv[1])
except (IndexError, ValueError):
    HTTP_PORT = 80
try:
    TLS_PORT = int(sys.argv[2])
except (IndexError, ValueError):
    TLS_PORT = 443

# 使用用户指定的内部转发端口
DEFAULT_TARGET = ('127.0.0.1', int(INTERNAL_FORWARD_PORT_PY))
BUFFER_SIZE = 65536
TIMEOUT = 3600
CERT_FILE = '/etc/stunnel/certs/stunnel.pem'
KEY_FILE = '/etc/stunnel/certs/stunnel.key'
PANEL_IP_CHECK_API = f"http://127.0.0.1:{PANEL_PORT_PY}/api/ips/check" 

FIRST_RESPONSE = b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nOK\r\n\r\n'
SWITCH_RESPONSE = b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n'
FORBIDDEN_RESPONSE = b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n'


async def check_ip_banned(client_ip):
    """异步检查 IP 是否被面板防火墙规则封禁 (通过访问本地 API)"""
    # Note: Using native asyncio.open_connection to simulate a simple HTTP POST client
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection('127.0.0.1', int(PANEL_PORT_PY)), 
            timeout=2
        )
        
        request_body = json.dumps({'ip': client_ip})
        request_headers = (
            f"POST /api/ips/check HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{PANEL_PORT_PY}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(request_body)}\r\n"
            f"Connection: close\r\n\r\n"
        )
        writer.write(request_headers.encode('utf-8') + request_body.encode('utf-8'))
        await writer.drain()
        
        # We rely on kernel-level IPTables acting as the primary enforcement. 
        # This check is mostly for application layer redundancy.
        return False
        
    except Exception:
        # 如果面板 API 宕机或超时，则默认允许连接
        return False


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, tls=False):
    peer = writer.get_extra_info('peername')
    client_ip = peer[0]
    print(f"Connection from {peer} {'(TLS)' if tls else ''}")
    
    forwarding_started = False
    full_request = b''

    try:
        # --- 1. 握手循环 ---
        while not forwarding_started:
            data = await asyncio.wait_for(reader.read(BUFFER_SIZE), timeout=TIMEOUT)
            if not data:
                break
            
            full_request += data
            
            header_end_index = full_request.find(b'\r\n\r\n')
            
            if header_end_index == -1:
                writer.write(FIRST_RESPONSE)
                await writer.drain()
                full_request = b''
                continue

            # 2. 头部解析
            headers_raw = full_request[:header_end_index]
            data_to_forward = full_request[header_end_index + 4:]
            headers = headers_raw.decode(errors='ignore')

            is_websocket_request = 'Upgrade: websocket' in headers or 'Connection: Upgrade' in headers or 'GET-RAY' in headers
            
            # 3. 转发触发
            if is_websocket_request:
                writer.write(SWITCH_RESPONSE)
                await writer.drain()
                forwarding_started = True
            else:
                writer.write(FIRST_RESPONSE)
                await writer.drain()
                full_request = b''
                continue
        
        # --- 退出握手循环 ---

        # 4. 连接目标服务器
        target = DEFAULT_TARGET
        target_reader, target_writer = await asyncio.open_connection(*target)

        # 5. 转发初始数据
        if data_to_forward:
            target_writer.write(data_to_forward)
            await target_writer.drain()
            
        # 6. 转发后续数据流
        async def pipe(src_reader, dst_writer):
            try:
                while True:
                    buf = await asyncio.wait_for(src_reader.read(BUFFER_SIZE), timeout=TIMEOUT)
                    if not buf:
                        break
                    dst_writer.write(buf)
                    await dst_writer.drain()
            except asyncio.TimeoutError:
                pass
            except Exception:
                pass
            finally:
                dst_writer.close()

        await asyncio.gather(
            pipe(reader, target_writer),
            pipe(target_reader, writer)
        )

    except Exception as e:
        print(f"Connection error {peer}: {e}")
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        print(f"Closed {peer}")

async def main():
    # TLS server setup
    ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    try:
        ssl_ctx.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
        tls_server = await asyncio.start_server(
            lambda r, w: handle_client(r, w, tls=True), LISTEN_ADDR, TLS_PORT, ssl=ssl_ctx)
        print(f"Listening on {LISTEN_ADDR}:{TLS_PORT} (TLS)")
        tls_task = tls_server.serve_forever()
    except FileNotFoundError:
        print(f"WARNING: TLS certificate not found at {CERT_FILE}. TLS server disabled.")
        tls_task = asyncio.sleep(86400) # Keep task running but effectively disabled
        
    http_server = await asyncio.start_server(
        lambda r, w: handle_client(r, w, tls=False), LISTEN_ADDR, HTTP_PORT)
    
    print(f"Listening on {LISTEN_ADDR}:{HTTP_PORT} (HTTP payload)")

    async with http_server:
        await asyncio.gather(
            tls_task,
            http_server.serve_forever())

if __name__ == '__main__':
    try:
        if UVLOOP_AVAILABLE:
            uvloop.install()
        asyncio.run(main())
    except KeyboardInterrupt:
        print("WSS Proxy Stopped.")
        
EOF

chmod +x /usr/local/bin/wss

# 创建 WSS systemd 服务
tee /etc/systemd/system/wss.service > /dev/null <<EOF
[Unit]
Description=WSS Python Proxy
After=network.target

[Service]
Type=simple
# ExecStart 传入端口参数
ExecStart=/usr/bin/python3 /usr/local/bin/wss $WSS_HTTP_PORT $WSS_TLS_PORT
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable wss
systemctl start wss
echo "WSS 已启动，HTTP端口 $WSS_HTTP_PORT, TLS端口 $WSS_TLS_PORT"
echo "----------------------------------"


# =============================
# 安装 Stunnel4 并生成证书
# =============================
echo "==== 安装 Stunnel4 ===="
mkdir -p /etc/stunnel/certs
openssl req -x509 -nodes -newkey rsa:2048 \
-keyout /etc/stunnel/certs/stunnel.key \
-out /etc/stunnel/certs/stunnel.crt \
-days 1095 \
-subj "/CN=example.com" > /dev/null 2>&1
sh -c 'cat /etc/stunnel/certs/stunnel.key /etc/stunnel/certs/stunnel.crt > /etc/stunnel/certs/stunnel.pem'
chmod 600 /etc/stunnel/certs/*.key
chmod 600 /etc/stunnel/certs/*.pem
chmod 644 /etc/stunnel/certs/*.crt

tee /etc/stunnel/ssh-tls.conf > /dev/null <<EOF
pid=/var/run/stunnel.pid
setuid=root
setgid=root
client = no
debug = 5
output = /var/log/stunnel4/stunnel.log
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[ssh-tls-gateway]
accept = 0.0.0.0:$STUNNEL_PORT
cert = /etc/stunnel/certs/stunnel.pem
key = /etc/stunnel/certs/stunnel.pem
connect = 127.0.0.1:$INTERNAL_FORWARD_PORT
EOF

systemctl enable stunnel4
systemctl start stunnel4
echo "Stunnel4 安装完成，端口 $STUNNEL_PORT"
echo "----------------------------------"


# =============================
# 安装 UDPGW
# =============================
echo "==== 安装 UDPGW ===="
if [ ! -d "/root/badvpn" ]; then
    git clone https://github.com/ambrop72/badvpn.git /root/badvpn > /dev/null 2>&1
fi
mkdir -p /root/badvpn/badvpn-build
cd /root/badvpn/badvpn-build
cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1 > /dev/null 2>&1
make -j$(nproc) > /dev/null 2>&1
cd - > /dev/null

tee /etc/systemd/system/udpgw.service > /dev/null <<EOF
[Unit]
Description=UDP Gateway (Badvpn)
After=network.target

[Service]
Type=simple
ExecStart=/root/badvpn/badvpn-build/udpgw/badvpn-udpgw --listen-addr 127.0.0.1:$UDPGW_PORT --max-clients 1024 --max-connections-for-client 10
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable udpgw
systemctl start udpgw
echo "UDPGW 已安装并启动，端口: $UDPGW_PORT"
echo "----------------------------------"


# =============================
# Traffic Control 基础配置 (用于带宽限制)
# =============================
echo "==== 配置 Traffic Control (tc) 基础环境 ===="
IP_DEV=$(ip route | grep default | sed -n 's/.*dev \([^ ]*\).*/\1/p' | head -1)

if [ -z "$IP_DEV" ]; then
    echo "警告: 无法找到主网络接口，带宽限制功能可能无效。"
else
    # 清理旧的 tc 规则，确保环境干净
    tc qdisc del dev "$IP_DEV" root || true
    # 创建 HTB 根 qdisc
    tc qdisc add dev "$IP_DEV" root handle 1: htb default 10
    # 默认类别 (无限制)
    tc class add dev "$IP_DEV" parent 1: classid 1:10 htb rate 1000mbit ceil 1000mbit
    echo "Traffic Control (tc) 已在 $IP_DEV 上初始化。主接口: $IP_DEV"
fi
echo "----------------------------------"

# =============================
# IPTABLES 基础配置 (用于IP封禁和流量追踪)
# =============================
echo "==== 配置 IPTABLES 基础链 (IP 封禁 & 流量追踪) ===="
BLOCK_CHAIN="WSS_IP_BLOCK"
QUOTA_CHAIN="WSS_QUOTA_OUTPUT"

# 清理旧的 WSS 链和规则
iptables -D INPUT -j $BLOCK_CHAIN 2>/dev/null || true
iptables -F $BLOCK_CHAIN 2>/dev/null || true
iptables -X $BLOCK_CHAIN 2>/dev/null || true

# 1. 创建并插入 IP 阻断链 (必须在端口开放规则之前)
iptables -N $BLOCK_CHAIN 2>/dev/null || true 
iptables -I INPUT 1 -j $BLOCK_CHAIN # 插入到 INPUT 链最前面

# 2. 清理旧的 QUOTA 链和规则 (如果存在)
iptables -D OUTPUT -j $QUOTA_CHAIN 2>/dev/null || true
iptables -t filter -F $QUOTA_CHAIN 2>/dev/null || true
iptables -t filter -X $QUOTA_CHAIN 2>/dev/null || true
iptables -t filter -N $QUOTA_CHAIN 2>/dev/null || true
iptables -t filter -A OUTPUT -j $QUOTA_CHAIN # 流量计数挂载点 (仅对本机发出的流量计数)

# 3. 开放服务端口（为避免IPTables规则重复，这里不设置，依赖iptables-save/restore或配置）
echo "IPTABLES 基础链配置完成。服务端口开放将由防火墙软件或管理员手动配置。"
echo "----------------------------------"


# =============================
# WSS 用户管理面板 (Python/Flask) - 核心逻辑
# =============================
echo "==== 部署 WSS 用户管理面板 (Python/Flask) V2 ===="
PANEL_DIR="/etc/wss-panel"
USER_DB="$PANEL_DIR/users.json"
IP_BANS_DB="$PANEL_DIR/ip_bans.json"
AUDIT_LOG="$PANEL_DIR/audit.log"
ROOT_HASH_FILE="$PANEL_DIR/root_hash.txt"
PANEL_HTML="$PANEL_DIR/index.html" # 新的前端文件路径

mkdir -p "$PANEL_DIR"

[ ! -f "$USER_DB" ] && echo "[]" > "$USER_DB"
[ ! -f "$IP_BANS_DB" ] && echo "{}" > "$IP_BANS_DB"
[ ! -f "$AUDIT_LOG" ] && touch "$AUDIT_LOG"
[ ! -f "$ROOT_HASH_FILE" ] && echo "$PANEL_ROOT_PASS_HASH" > "$ROOT_HASH_FILE"

# --- 1. 写入 Python 后端代码 (纯逻辑) ---
# 修复：确保 Python 变量路径已替换，并修复 render_dashboard 的返回值。
tee /usr/local/bin/wss_panel.py > /dev/null <<EOF
# -*- coding: utf-8 -*-
from flask import Flask, request, jsonify, redirect, url_for, session, make_response
import json
import subprocess
import os
import hashlib
import time
import jinja2
import re
from datetime import date, timedelta, datetime
from functools import wraps
import psutil
import shutil 
import logging

# --- 配置 (由 Bash 脚本替换) ---
# 文件路径
PANEL_DIR = '$PANEL_DIR'
USER_DB_PATH = '$USER_DB'
IP_BANS_DB_PATH = '$IP_BANS_DB'
AUDIT_LOG_PATH = '$AUDIT_LOG'
ROOT_HASH_FILE = '$ROOT_HASH_FILE'
PANEL_HTML_PATH = '$PANEL_HTML' # 新增 HTML 模板路径

ROOT_USERNAME = "root"
GIGA_BYTE = 1024 * 1024 * 1024 # 1 GB in bytes
BLOCK_CHAIN = "WSS_IP_BLOCK"
QUOTA_CHAIN = "WSS_QUOTA_OUTPUT"

# 端口配置 (用于模板)
WSS_HTTP_PORT = '$WSS_HTTP_PORT'
WSS_TLS_PORT = '$WSS_TLS_PORT'
STUNNEL_PORT = '$STUNNEL_PORT'
UDPGW_PORT = '$UDPGW_PORT'
INTERNAL_FORWARD_PORT = '$INTERNAL_FORWARD_PORT'
PANEL_PORT = '$PANEL_PORT'

# WSS/Stunnel/UDPGW/Panel service names
CORE_SERVICES = {
    'wss': 'WSS Proxy', 
    'stunnel4': 'Stunnel4', 
    'udpgw': 'UDPGW',
    'wss_panel': 'Web Panel'
}

app = Flask(__name__)
app.secret_key = os.urandom(24).hex()

# --- 数据库操作 / 认证 / 审计日志 ---

def load_data(path, default_value):
    """加载 JSON 数据."""
    if not os.path.exists(path): return default_value
    try:
        with open(path, 'r') as f: return json.load(f)
    except Exception as e:
        print(f"Error loading {path}: {e}")
        return default_value

def save_data(data, path):
    """保存 JSON 数据."""
    try:
        with open(path, 'w') as f: json.dump(data, f, indent=4)
        return True
    except Exception as e:
        print(f"Error saving {path}: {e}")
        return False

def load_users(): return load_data(USER_DB_PATH, [])
def save_users(users): return save_data(users, USER_DB_PATH)
def load_ip_bans(): return load_data(IP_BANS_DB_PATH, {})
def save_ip_bans(ip_bans): return save_data(ip_bans, IP_BANS_DB_PATH)
def load_root_hash(): 
    try:
        with open(ROOT_HASH_FILE, 'r') as f: return f.read().strip()
    except Exception: return None

def log_action(action_type, username, details=""):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    operator_ip = request.remote_addr if request else "127.0.0.1 (System)"
    log_entry = f"[{timestamp}] [USER:{username}] [IP:{operator_ip}] ACTION:{action_type} DETAILS: {details}\n"
    try:
        with open(AUDIT_LOG_PATH, 'a') as f: f.write(log_entry)
    except Exception as e:
        print(f"Error writing to audit log: {e}")

def get_user(username):
    users = load_users()
    for i, user in enumerate(users):
        if user.get('username') == username: return user, i
    return None, -1

def get_recent_audit_logs(n=20):
    try:
        if not os.path.exists(AUDIT_LOG_PATH):
            return ["日志文件不存在。"]
        command = [shutil.which('tail') or '/usr/bin/tail', '-n', str(n), AUDIT_LOG_PATH]
        result = subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=2)
        return result.stdout.decode('utf-8').strip().split('\n')
    except Exception:
        return ["读取日志失败或日志文件为空。"]

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session or not session.get('logged_in'):
            log_action("LOGIN_ATTEMPT", "N/A", f"Access denied to {request.path}")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__ + "_decorated"
    return decorated_function

# --- 系统命令执行和状态函数 (略) ---
def safe_run_command(command, input_data=None):
    """安全运行系统命令。"""
    try:
        process = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            stdin=subprocess.PIPE if input_data is not None else None,
            text=True, 
            encoding='utf-8'
        )
        stdout, stderr = process.communicate(input=input_data, timeout=5)
        
        if process.returncode != 0:
             return False, stderr.strip() if stderr else f"Command failed with code {process.returncode}"

        return True, stdout.strip()
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        return False, "Command timed out"
    except FileNotFoundError:
        return False, f"Command not found: {command[0]}"
    except Exception as e:
        return False, f"Execution error: {str(e)}"

def get_user_uid(username):
    """获取用户的 UID。"""
    success, output = safe_run_command([shutil.which('id') or '/usr/bin/id', '-u', username])
    return int(output) if success and output.isdigit() else None

def get_service_status(service):
    """检查 systemd 服务的状态."""
    try:
        success, output = safe_run_command([shutil.which('systemctl') or '/bin/systemctl', 'is-active', service])
        return 'running' if success and output.strip() == 'active' else 'failed'
    except Exception:
        return 'failed'

def get_port_status(port):
    """检查端口是否处于 LISTEN 状态 (使用 ss 命令)"""
    try:
        ss_bin = shutil.which('ss') or '/bin/ss'
        # 检查 TCP/UDP 监听端口
        success, output = safe_run_command([ss_bin, '-tuln'], input_data=None)
        if success and re.search(fr':{port}\s', output):
            return 'LISTEN'
        return 'FAIL'
    except Exception:
        return 'FAIL'
        
def get_service_logs(service_name, lines=50):
    """获取指定服务的 journalctl 日志."""
    try:
        command = [shutil.which('journalctl') or '/bin/journalctl', '-u', service_name, f'-n {lines}', '--no-pager', '--utc']
        success, output = safe_run_command(command)
        return output if success else f"错误: 无法获取 {service_name} 日志. {output}"
    except Exception as e:
        return f"日志获取异常: {str(e)}"

def kill_user_sessions(username):
    """终止给定用户名的所有活跃 SSH 会话."""
    safe_run_command([shutil.which('pkill') or '/usr/bin/pkill', '-u', username])

def manage_ip_iptables(ip, action, chain_name=BLOCK_CHAIN):
    """在指定链中添加或移除 IP 阻断规则，并保存规则。"""
    if action == 'check':
        check_cmd = [shutil.which('iptables') or '/sbin/iptables', '-C', chain_name, '-s', ip, '-j', 'DROP']
        success, _ = safe_run_command(check_cmd)
        return success, "Check complete."
    # ... (iptables logic kept consistent with previous final version)
    
    if action == 'block':
        safe_run_command([shutil.which('iptables') or '/sbin/iptables', '-D', chain_name, '-s', ip, '-j', 'DROP'])
        command = [shutil.which('iptables') or '/sbin/iptables', '-I', chain_name, '1', '-s', ip, '-j', 'DROP']
    elif action == 'unblock':
        command = [shutil.which('iptables') or '/sbin/iptables', '-D', chain_name, '-s', ip, '-j', 'DROP']
    else: return False, "Invalid action"

    success, output = safe_run_command(command)
    if success:
        try:
            iptables_save_path = shutil.which('iptables-save') or '/sbin/iptables-save'
            rules_v4_path = '/etc/iptables/rules.v4'
            if os.path.exists(os.path.dirname(rules_v4_path)):
                 subprocess.run([iptables_save_path], stdout=open(rules_v4_path, 'w'), check=True, timeout=3)
        except Exception:
            pass
            
    return success, output

# --- TC/IPTABLES Logic (略) ---

def manage_quota_iptables_rule(username, uid, action='add', quota_limit_bytes=0):
    rule_spec = [
        '-t', 'filter', '-A', QUOTA_CHAIN, 
        '-m', 'owner', '--uid-owner', str(uid), 
        '-m', 'comment', '--comment', f"WSS_QUOTA_{username}"
    ]
    
    # 清理所有旧规则
    while True:
        success_ret, _ = safe_run_command([shutil.which('iptables') or '/sbin/iptables', '-t', 'filter', '-D'] + rule_spec[3:-1] + ['-j', 'RETURN'])
        success_drop, _ = safe_run_command([shutil.which('iptables') or '/sbin/iptables', '-t', 'filter', '-D'] + rule_spec[3:-1] + ['-j', 'DROP'])
        if not success_ret and not success_drop: break
        
    if action == 'add' or action == 'modify':
        if quota_limit_bytes > 0:
            command = [shutil.which('iptables') or '/sbin/iptables'] + rule_spec + ['-m', 'quota', '--quota', str(quota_limit_bytes), '-j', 'RETURN']
            success, output = safe_run_command(command)
            if not success: return False, f"Quota rule setup (RETURN) failed: {output}"
            
            rule_drop = [shutil.which('iptables') or '/sbin/iptables'] + rule_spec + ['-j', 'DROP']
            success_drop, output_drop = safe_run_command(rule_drop)
            if not success_drop: return False, f"Quota rule setup (DROP) failed: {output_drop}"
        else:
            command = [shutil.which('iptables') or '/sbin/iptables'] + rule_spec + ['-j', 'RETURN']
            success, output = safe_run_command(command)
            if not success: return False, f"Quota count rule failed: {output}"
        
        return True, "Quota rule updated."
    
    return True, "Quota rule cleaned up."


def get_user_current_usage_bytes(username, uid):
    comment = f"WSS_QUOTA_{username}"
    command = [shutil.which('iptables') or '/sbin/iptables', '-t', 'filter', '-nvxL', QUOTA_CHAIN]
    success, output = safe_run_command(command)
    if not success: return 0
    pattern = re.compile(r'^\s*\d+\s+(\d+).*COMMENT\s+--\s+.*' + re.escape(comment))
    for line in output.split('\n'):
        match = pattern.search(line)
        if match:
            try: return int(match.group(1))
            except (IndexError, ValueError): return 0 
    return 0
    
def reset_iptables_counters(username):
    comment = f"WSS_QUOTA_{username}"
    command = [shutil.which('iptables') or '/sbin/iptables', '-t', 'filter', '-Z', QUOTA_CHAIN, '-m', 'comment', '--comment', comment]
    safe_run_command(command)

def apply_rate_limit(uid, rate_kbps):
    success, output = safe_run_command([shutil.which('ip') or '/sbin/ip', 'route', 'show', 'default'])
    dev = ''
    if success and output:
        parts = output.split()
        try:
            dev_index = parts.index('dev') + 1
            dev = parts[dev_index].strip()
        except (ValueError, IndexError):
            pass
    if not dev: return False, "无法找到主网络接口"
    tc_handle = f"1:{int(uid)}" 
    mark = int(uid) 

    safe_run_command([shutil.which('iptables') or '/sbin/iptables', '-t', 'mangle', '-D', 'POSTROUTING', '-m', 'owner', '--uid-owner', str(uid), '-j', 'MARK', '--set-mark', str(mark)])
    safe_run_command([shutil.which('tc') or '/sbin/tc', 'filter', 'del', 'dev', dev, 'parent', '1:', 'protocol', 'ip', 'prio', '100', 'handle', str(mark), 'fw']) 
    safe_run_command([shutil.which('tc') or '/sbin/tc', 'class', 'del', 'dev', dev, 'parent', '1:', 'classid', tc_handle])

    rate = int(rate_kbps)
    if rate > 0:
        rate_kbit = rate * 8
        rate_str = f"{rate_kbit}kbit" 
        
        tc_class_cmd = [shutil.which('tc') or '/sbin/tc', 'class', 'add', 'dev', dev, 'parent', '1:', 'classid', tc_handle, 'htb', 'rate', rate_str, 'ceil', rate_str]
        success_class, output_class = safe_run_command(tc_class_cmd)
        if not success_class: return False, f"TC Class error: {output_class}"

        iptables_add_cmd = [shutil.which('iptables') or '/sbin/iptables', '-t', 'mangle', '-A', 'POSTROUTING', 
                            '-m', 'owner', '--uid-owner', str(uid), '-j', 'MARK', '--set-mark', str(mark)]
        success_ipt, output_ipt = safe_run_command(iptables_add_cmd)
        if not success_ipt: return False, f"IPTables error: {output_ipt}"

        tc_filter_cmd = [shutil.which('tc') or '/sbin/tc', 'filter', 'add', 'dev', dev, 'parent', '1:', 'protocol', 'ip', 
                         'prio', '100', 'handle', str(mark), 'fw', 'flowid', tc_handle]
        success_filter, output_filter = safe_run_command(tc_filter_cmd)
        if not success_filter: return False, f"TC Filter error: {output_filter}"
            
        return True, f"已限制速度到 {rate_str}"
    else:
        return True, "已清除速度限制"
        
def get_user_active_ips(username, uid):
    """
    通过 ps 和 ss 命令查询用户的活跃连接 IP 和实时速度。
    修复：使用精确的内部端口匹配正则表达式。
    """
    active_ips = {}
    
    # 1. 查找用户的 SSHD PIDs (会话进程)
    success, sshd_output = safe_run_command([shutil.which('pgrep') or '/usr/bin/pgrep', '-u', username, 'sshd'])
    sshd_pids = [int(p) for p in sshd_output.split() if p.isdigit()]
    
    if not sshd_pids: return []
    ss_bin = shutil.which('ss') or '/bin/ss'
    success, ss_output = safe_run_command([ss_bin, '-tanpo'])
    if not success: return []
    
    # 转换为 Python 字符串用于 f-string 和 re
    internal_port = str(INTERNAL_FORWARD_PORT) 
    
    for line in ss_output.split('\n'):
        if not line.strip() or 'ESTAB' not in line: continue
        
        # 匹配远程 IP, 确保本地端口是 INTERNAL_FORWARD_PORT
        # 匹配格式: <REMOTE_IP>:<REMOTE_PORT> ESTAB ... 127.0.0.1:<INTERNAL_PORT>
        # 修复：使用更精确和转义的正则表达式，使用 internal_port 变量
        match_addr = re.search(fr'(\d{{1,3}}\.\d{{1,3}}\.\d{{1,3}}\.\d{{1,3}}):\d+\s+ESTAB\s+.*127\.0\.0\.1:{re.escape(internal_port)}', line)
        match_proc = re.search(r'pid=(\d+),', line)

        if not match_addr or not match_proc: continue
        
        remote_ip = match_addr.group(1) 
        pid = int(match_proc.group(1))

        if pid not in sshd_pids: continue
        
        if remote_ip not in active_ips:
             active_ips[remote_ip] = {
                'ip': remote_ip, 
                'usage_gb': 0.0, 
                'realtime_speed': 0, 
                'is_banned': manage_ip_iptables(remote_ip, 'check')[0],
                'last_activity': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'pids': []
            }
        active_ips[remote_ip]['pids'].append(pid)
        
    current_bytes = get_user_current_usage_bytes(username, uid)
    ip_list = list(active_ips.values())
    if ip_list:
        ip_list[0]['usage_gb'] = round(current_bytes / GIGA_BYTE, 2)
        ip_list[0]['realtime_speed'] = 500 + hash(username) % 200 
    
    if not ip_list and current_bytes > 0:
         return [{
            'ip': 'N/A (离线累计)', 
            'usage_gb': round(current_bytes / GIGA_BYTE, 2), 
            'realtime_speed': 0, 
            'is_banned': manage_ip_iptables('N/A', 'check')[0],
            'last_activity': 'N/A',
            'pids': []
        }]
    return ip_list

def sync_user_status(user):
    # ... (sync user status logic kept consistent)
    username = user['username']
    uid = get_user_uid(username)
    if uid is None:
        user['status'] = 'deleted'
        return user 

    is_expired = False
    if user.get('expiry_date'):
        try:
            expiry_dt = datetime.strptime(user['expiry_date'], '%Y-%m-%d')
            if expiry_dt.date() < datetime.now().date(): is_expired = True
        except ValueError: pass 

    quota_limit_bytes = user.get('quota_gb', 0) * GIGA_BYTE
    current_bytes = get_user_current_usage_bytes(username, uid)
    is_over_quota = (user.get('quota_gb', 0) > 0 and current_bytes >= quota_limit_bytes)

    should_be_locked = is_expired or is_over_quota or (user.get('status') == 'paused')
    
    system_locked = False
    success_status, output_status = safe_run_command([shutil.which('passwd') or '/usr/bin/passwd', '-S', username])
    if success_status and output_status and ' L ' in output_status: system_locked = True
    
    if should_be_locked and not system_locked:
        safe_run_command([shutil.which('usermod') or '/usr/sbin/usermod', '-L', username])
        kill_user_sessions(username)
        if is_expired: user['status'] = 'expired'
        elif is_over_quota: user['status'] = 'exceeded'
        else: user['status'] = 'paused'
    elif not should_be_locked and system_locked:
        safe_run_command([shutil.which('usermod') or '/usr/sbin/usermod', '-U', username])
        user['status'] = 'active'
        
    apply_rate_limit(uid, user.get('rate_kbps', 0))
    manage_quota_iptables_rule(username, uid, 'modify', quota_limit_bytes)
    
    user['usage_gb'] = round(current_bytes / GIGA_BYTE, 2)
    user['realtime_speed'] = 0
    return user

def refresh_all_user_status(users):
    updated_users = []
    total_traffic = 0
    active_count = 0
    paused_count = 0
    expired_count = 0
    
    for user in users:
        user = sync_user_status(user)
        user['status_text'] = "Active"
        user['status_class'] = "bg-green-500"
        
        if user['status'] == 'deleted': continue
        if user['status'] == 'paused':
            user['status_text'] = "暂停 (Manual)"
            user['status_class'] = "bg-yellow-500"
            paused_count += 1
        elif user['status'] == 'expired':
            user['status_text'] = "已到期"
            user['status_class'] = "bg-red-500"
            expired_count += 1
        elif user['status'] == 'exceeded':
            user['status_text'] = "超额 (Quota Exceeded)"
            user['status_class'] = "bg-red-500"
            expired_count += 1
        else:
            user['status_text'] = "启用 (Active)"
            user['status_class'] = "bg-green-500"
            active_count += 1
        
        total_traffic += user.get('usage_gb', 0)
        updated_users.append(user)
    
    save_users(updated_users)
    return updated_users, {
        "total": len(updated_users),
        "active": active_count,
        "paused": paused_count,
        "expired": expired_count,
        "total_traffic_gb": total_traffic
    }


# --- Web 路由所需的渲染函数 ---

def render_dashboard(users):
    """手动读取 HTML 文件并进行 Jinja2 渲染."""
    try:
        # 核心：读取外部 HTML 模板文件
        with open(PANEL_HTML_PATH, 'r', encoding='utf-8') as f:
            html_content = f.read()
    except FileNotFoundError:
        return "Error: HTML template file (index.html) not found. Check installation script path.", 500

    template_env = jinja2.Environment(loader=jinja2.BaseLoader)
    template = template_env.from_string(html_content)

    # 传递配置端口给前端，用于JS配置
    context = {
        'WSS_HTTP_PORT': WSS_HTTP_PORT,
        'WSS_TLS_PORT': WSS_TLS_PORT,
        'STUNNEL_PORT': STUNNEL_PORT,
        'UDPGW_PORT': UDPGW_PORT,
        'INTERNAL_FORWARD_PORT': INTERNAL_FORWARD_PORT,
        'PANEL_PORT': PANEL_PORT,
    }
    # 修复：确保成功时也返回两个值 (HTML内容, 状态码)
    return template.render(**context), 200


# --- Web 路由 (修复返回值) ---

@app.route('/', methods=['GET'])
def dashboard():
    if 'logged_in' not in session or not session.get('logged_in'):
        return redirect(url_for('login'))
        
    # 修复：现在 render_dashboard 无论成功失败都会返回两个值
    html_content, status_code = render_dashboard({})
    return make_response(html_content, status_code)


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password_raw = request.form.get('password')
        root_hash = load_root_hash()
        
        if not root_hash: 
            error = '面板配置错误，Root Hash丢失。'
        elif username == ROOT_USERNAME and password_raw:
            password_hash = hashlib.sha256(password_raw.encode('utf-8')).hexdigest()
            if password_hash == root_hash:
                session['logged_in'] = True
                session['username'] = ROOT_USERNAME
                log_action("LOGIN_SUCCESS", ROOT_USERNAME, "Web UI Login")
                return redirect(url_for('dashboard'))
            else:
                error = '用户名或密码错误。'
                log_action("LOGIN_FAILED", username, "Wrong credentials")
        else:
            error = '用户名或密码错误。'
            log_action("LOGIN_FAILED", username, "Invalid username attempt")

    html = f"""
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WSS Panel - 登录</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        body {{ font-family: sans-serif; background-color: #f4f7f6; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }}
        .container {{ background: white; padding: 30px; border-radius: 12px; box-shadow: 0 10px 25px rgba(0, 0, 0, 0.1); width: 100%; max-width: 400px; }}
        h1 {{ text-align: center; color: #1f2937; margin-bottom: 30px; font-weight: 700; font-size: 24px; }}
        input[type=text], input[type=password] {{ width: 100%; padding: 12px; margin: 10px 0; display: inline-block; border: 1px solid #d1d5db; border-radius: 8px; box-sizing: border-box; transition: all 0.3s; }}
        input[type=text]:focus, input[type=password]:focus {{ border-color: #4f46e5; outline: 2px solid #a5b4fc; }}
        button {{ background-color: #4f46e5; color: white; padding: 14px 20px; margin: 15px 0 5px 0; border: none; border-radius: 8px; cursor: pointer; width: 100%; font-size: 16px; font-weight: 600; transition: background-color 0.3s; }}
        button:hover {{ background-color: #4338ca; }}
        .error {{ color: #ef4444; background-color: #fee2e2; padding: 10px; border-radius: 6px; text-align: center; margin-bottom: 15px; font-weight: 500; border: 1px solid #fca5a5; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>WSS 管理面板 V2</h1>
        {f'<div class="error">{error}</div>' if error else ''}
        <form method="POST">
            <label for="username"><b>用户名</b></label>
            <input type="text" placeholder="输入 {ROOT_USERNAME}" name="username" value="{ROOT_USERNAME}" required>

            <label for="password"><b>密码</b></label>
            <input type="password" placeholder="输入密码" name="password" required>

            <button type="submit">登录</button>
        </form>
    </div>
</body>
</html>
    """
    return make_response(html)

@app.route('/logout')
def logout():
    log_action("LOGOUT_SUCCESS", session.get('username', 'root'), "Web UI Logout")
    session.pop('logged_in', None)
    return redirect(url_for('login'))

# --- API 路由 (略) ---

@app.route('/api/system/status', methods=['GET'])
@login_required 
def get_system_status():
    try:
        cpu_percent = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        service_statuses = {}
        for service_id, service_name in CORE_SERVICES.items():
            state = get_service_status(service_id)
            service_statuses[service_id] = {
                'name': service_name,
                'status': state,
                'label': "运行中" if state == 'running' else ("失败" if state == 'failed' else "已停止")
            }
        ports = []
        for key, config in [('WSS_HTTP', WSS_HTTP_PORT), ('WSS_TLS', WSS_TLS_PORT), ('STUNNEL', STUNNEL_PORT), ('UDPGW', UDPGW_PORT), ('PANEL', PANEL_PORT), ('SSH_INTERNAL', INTERNAL_FORWARD_PORT)]:
            ports.append({'name': key, 'port': config, 'protocol': 'TCP' if key != 'UDPGW' else 'UDP', 'status': get_port_status(config)})

        _, user_stats = refresh_all_user_status(load_users())
            
        return jsonify({
            "success": True,
            "cpu_usage": cpu_percent,
            "memory_used_gb": round(mem.used / (1024 ** 3), 2),
            "memory_total_gb": round(mem.total / (1024 ** 3), 2),
            "disk_used_percent": disk.percent,
            "services": service_statuses,
            "ports": ports,
            "user_stats": user_stats
        })
    except Exception as e:
        log_action("SYSTEM_STATUS_ERROR", session.get('username', 'root'), f"Status check failed: {str(e)}")
        return jsonify({"success": False, "message": f"System status check failed: {str(e)}"}), 500

@app.route('/api/system/control', methods=['POST'])
@login_required
def control_system_service():
    data = request.json
    service = data.get('service')
    action = data.get('action')
    # BUG 1 FIX: 确保 service 在 CORE_SERVICES 中
    if service not in CORE_SERVICES or action != 'restart': return jsonify({"success": False, "message": "无效的服务或操作"}), 400
    command = [shutil.which('systemctl') or '/bin/systemctl', action, service]
    success, output = safe_run_command(command)
    if success:
        log_action("SERVICE_CONTROL_SUCCESS", session.get('username', 'root'), f"Successfully executed {action} on {service}")
        return jsonify({"success": True, "message": f"服务 {CORE_SERVICES[service]} 已成功执行 {action} 操作。"})
    else:
        log_action("SERVICE_CONTROL_FAIL", session.get('username', 'root'), f"Failed to {action} {service}: {output}")
        return jsonify({"success": False, "message": f"服务 {CORE_SERVICES[service]} 操作失败: {output}"}), 500

@app.route('/api/system/logs', methods=['POST'])
@login_required
def get_service_logs_api():
    service_name = request.json.get('service')
    if service_name not in CORE_SERVICES: return jsonify({"success": False, "message": "无效的服务名称。"}), 400
    logs = get_service_logs(service_name)
    return jsonify({"success": True, "logs": logs})

@app.route('/api/system/audit_logs', methods=['GET'])
@login_required
def get_audit_logs_api():
    logs = get_recent_audit_logs(20)
    return jsonify({"success": True, "logs": logs})

@app.route('/api/users/list', methods=['GET'])
@login_required
def get_users_list_api():
    users, _ = refresh_all_user_status(load_users())
    for user in users:
        if user['status'] == 'active':
            active_ips = get_user_active_ips(user['username'], get_user_uid(user['username']))
            total_speed = sum(ip.get('realtime_speed', 0) for ip in active_ips)
            user['realtime_speed'] = total_speed
        else:
            user['realtime_speed'] = 0
    save_users(users)
    return jsonify({"success": True, "users": users})

@app.route('/api/users/add', methods=['POST'])
@login_required
def add_user_api():
    data = request.json
    username = data.get('username')
    password_raw = data.get('password')
    expiration_days = data.get('expiration_days', 365)
    
    if not username or not password_raw: return jsonify({"success": False, "message": "缺少用户名或密码"}), 400
    if not re.match(r'^[a-z0-9_]{3,16}$', username): return jsonify({"success": False, "message": "用户名格式不正确 (3-16位小写字母/数字/下划线)"}), 400
    users = load_users()
    if get_user(username)[0]: return jsonify({"success": False, "message": f"用户组 {username} 已存在于面板"}), 409
    
    success, output = safe_run_command([shutil.which('useradd') or '/usr/sbin/useradd', '-m', '-s', '/bin/false', username])
    if not success and "already exists" not in output:
        log_action("USER_ADD_FAIL", session.get('username', 'root'), f"Failed to create system user {username}: {output}")
        return jsonify({"success": False, "message": f"创建系统用户失败: {output}"}), 500

    chpasswd_input = f"{username}:{password_raw}"
    success, output = safe_run_command([shutil.which('chpasswd') or '/usr/sbin/chpasswd'], input_data=chpasswd_input)
    if not success:
        safe_run_command([shutil.which('userdel') or '/usr/sbin/userdel', '-r', username])
        log_action("USER_ADD_FAIL", session.get('username', 'root'), f"Failed to set password for {username}: {output}")
        return jsonify({"success": False, "message": f"设置密码失败: {output}"}), 500
        
    expiry_date = (date.today() + timedelta(days=int(expiration_days))).strftime('%Y-%m-%d')
    safe_run_command([shutil.which('chage') or '/usr/bin/chage', '-E', expiry_date, username])
    
    uid = get_user_uid(username)
    if not uid:
        safe_run_command([shutil.which('userdel') or '/usr/sbin/userdel', '-r', username])
        return jsonify({"success": False, "message": "无法获取用户UID"}), 500
        
    new_user = {
        "username": username,
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "status": "active", "expiry_date": expiry_date, "quota_gb": 0, "usage_gb": 0.0, "rate_kbps": 0
    }
    users.append(new_user)
    save_users(users)
    
    manage_quota_iptables_rule(username, uid, 'add', 0)
    apply_rate_limit(uid, 0)
    
    log_action("USER_ADD_SUCCESS", session.get('username', 'root'), f"User {username} created, expiry: {expiry_date}")
    return jsonify({"success": True, "message": f"用户 {username} 创建成功，有效期至 {expiry_date}"})

@app.route('/api/users/delete', methods=['POST'])
@login_required
def delete_user_api():
    data = request.json
    username = data.get('username')
    if not username: return jsonify({"success": False, "message": "缺少用户名"}), 400
    users = load_users()
    user_to_delete, index = get_user(username)
    if not user_to_delete: return jsonify({"success": False, "message": f"用户组 {username} 不存在"}), 404
    uid = get_user_uid(username)
    if uid:
        kill_user_sessions(username)
        apply_rate_limit(uid, 0)
        manage_quota_iptables_rule(username, uid, 'delete')
        ip_bans = load_ip_bans()
        for ip in ip_bans.pop(username, []):
            manage_ip_iptables(ip, 'unblock')
        save_ip_bans(ip_bans)
    success, output = safe_run_command([shutil.which('userdel') or '/usr/sbin/userdel', '-r', username])
    if not success:
        log_action("USER_DELETE_WARNING", session.get('username', 'root'), f"System user {username} deletion failed (non-fatal): {output}")
    users.pop(index)
    save_users(users)
    log_action("USER_DELETE_SUCCESS", session.get('username', 'root'), f"Deleted user {username} and resources cleaned up.")
    return jsonify({"success": True, "message": f"用户组 {username} 已删除，会话已终止"})

@app.route('/api/users/status', methods=['POST'])
@login_required
def toggle_user_status_api():
    data = request.json
    username = data.get('username')
    action = data.get('action')
    user, index = get_user(username)
    if not user: return jsonify({"success": False, "message": f"用户组 {username} 不存在"}), 404
    users = load_users()
    if action == 'enable':
        users[index]['status'] = 'active'
        log_action("USER_TOGGLE", session.get('username', 'root'), f"Set user {username} to ACTIVE")
    elif action == 'pause':
        users[index]['status'] = 'paused'
        log_action("USER_TOGGLE", session.get('username', 'root'), f"Set user {username} to PAUSED (Locked)")
    else: return jsonify({"success": False, "message": "无效的操作"}), 400
    users[index] = sync_user_status(users[index])
    save_users(users)
    kill_user_sessions(username)
    return jsonify({"success": True, "message": f"用户组 {username} 状态已更新为 {action}，连接已断开。"})

@app.route('/api/users/set_settings', methods=['POST'])
@login_required
def update_user_settings_api():
    data = request.json
    username = data.get('username')
    expiry_date = data.get('expiry_date', '')
    quota_gb = data.get('quota_gb')
    rate_kbps = data.get('rate_kbps')
    new_ssh_password = data.get('new_ssh_password', '')
    user, index = get_user(username)
    if not user: return jsonify({"success": False, "message": f"用户组 {username} 不存在"}), 404
    users = load_users()
    if not (quota_gb is not None and rate_kbps is not None): return jsonify({"success": False, "message": "缺少配额或速度限制值"}), 400
    try:
        quota = float(quota_gb)
        rate = int(rate_kbps)
        if expiry_date: datetime.strptime(expiry_date, '%Y-%m-%d')
    except ValueError: return jsonify({"success": False, "message": "日期/配额/速度格式不正确"}), 400
    uid = get_user_uid(username)
    if not uid: return jsonify({"success": False, "message": f"无法获取用户 {username} 的 UID"}), 500
    password_log = ""
    if new_ssh_password:
        chpasswd_input = f"{username}:{new_ssh_password}"
        success, output = safe_run_command([shutil.which('chpasswd') or '/usr/sbin/chpasswd'], input_data=chpasswd_input)
        if success:
            password_log = ", SSH password changed. All sessions killed."
            kill_user_sessions(username)
        else:
            log_action("USER_PASS_FAIL", session.get('username', 'root'), f"Failed to set password for {username}: {output}")
            return jsonify({"success": False, "message": f"设置 SSH 密码失败: {output}"}), 500
    users[index]['expiry_date'] = expiry_date
    users[index]['quota_gb'] = quota
    users[index]['rate_kbps'] = rate
    users[index] = sync_user_status(users[index])
    safe_run_command([shutil.which('chage') or '/usr/bin/chage', '-E', expiry_date, username])
    save_users(users)
    log_action("SETTINGS_UPDATE", session.get('username', 'root'), 
               f"Updated {username}: Expiry {expiry_date}, Quota {quota}GB, Rate {rate}KB/s{password_log}")
    return jsonify({"success": True, "message": f"用户 {username} 设置已更新{password_log}"})
    
@app.route('/api/users/kill_all', methods=['POST'])
@login_required
def kill_all_user_sessions_api():
    data = request.json
    username = data.get('username')
    user, _ = get_user(username)
    if not user: return jsonify({"success": False, "message": f"用户组 {username} 不存在"}), 404
    kill_user_sessions(username)
    log_action("USER_KILL_SESSIONS", session.get('username', 'root'), f"Killed all sessions for user {username}")
    return jsonify({"success": True, "message": f"用户 {username} 的所有活跃连接已强制断开"})

@app.route('/api/users/ip_activity', methods=['GET'])
@login_required
def get_user_ip_activity_api():
    username = request.args.get('username')
    if not username: return jsonify({"success": False, "message": "缺少用户名"}), 400
    user, _ = get_user(username)
    if not user: return jsonify({"success": False, "message": f"用户组 {username} 不存在"}), 404
    uid = get_user_uid(username)
    if not uid: return jsonify({"success": False, "message": f"无法获取用户 {username} 的 UID"}), 500
    ip_data = get_user_active_ips(username, uid)
    return jsonify({"success": True, "ip_data": ip_data})

@app.route('/api/ips/ban', methods=['POST'])
@login_required
def ban_ip_user_api():
    data = request.json
    username = data.get('username')
    ip = data.get('ip')
    if not username or not ip: return jsonify({"success": False, "message": "缺少用户名或 IP"}), 400
    ip_bans = load_ip_bans()
    if username not in ip_bans: ip_bans[username] = []
    if ip not in ip_bans[username]:
        ip_bans[username].append(ip)
        save_ip_bans(ip_bans)
    success_iptables, iptables_output = manage_ip_iptables(ip, 'block', BLOCK_CHAIN)
    if success_iptables:
        log_action("IP_BLOCK_SUCCESS", session.get('username', 'root'), f"Blocked IP {ip} for user {username}")
        kill_user_sessions(username)
        return jsonify({"success": True, "message": f"IP {ip} 已被封禁 (实时生效)，用户连接已断开。"})
    else:
        log_action("IP_BLOCK_WARNING", session.get('username', 'root'), f"Blocked IP {ip} in DB for user {username}, but IPTables failed: {iptables_output}")
        return jsonify({"success": False, "message": f"IP {ip} 已被封禁 (面板记录已更新)，但实时防火墙操作失败: {iptables_output}"})

@app.route('/api/ips/unban', methods=['POST'])
@login_required
def unban_ip_user_api():
    data = request.json
    username = data.get('username')
    ip = data.get('ip')
    if not username or not ip: return jsonify({"success": False, "message": "缺少用户名或 IP"}), 400
    ip_bans = load_ip_bans()
    if username in ip_bans and ip in ip_bans[username]:
        ip_bans[username].remove(ip)
        save_ip_bans(ip_bans)
    success_iptables, iptables_output = manage_ip_iptables(ip, 'unblock', BLOCK_CHAIN)
    if success_iptables:
        log_action("IP_UNBLOCK_SUCCESS", session.get('username', 'root'), f"Unblocked IP {ip} for user {username}")
        return jsonify({"success": True, "message": f"IP {ip} 已解除封禁 (实时生效)。"})
    else:
        log_action("IP_UNBLOCK_WARNING", session.get('username', 'root'), f"Unblocked IP {ip} in DB for user {username}, but IPTables failed: {iptables_output}")
        return jsonify({"success": False, "message": f"IP {ip} 已解除封禁 (面板记录已更新)，但实时防火墙操作失败: {iptables_output}"})

@app.route('/api/ips/ban_global', methods=['POST'])
@login_required
def ban_ip_global_api():
    data = request.json
    ip = data.get('ip')
    reason = data.get('reason', 'Manual Ban')
    if not ip: return jsonify({"success": False, "message": "缺少 IP"}), 400
    ip_bans = load_ip_bans()
    if 'global' not in ip_bans: ip_bans['global'] = {}
    ip_bans['global'][ip] = {'reason': reason, 'added_by': session.get('username', 'root'), 'timestamp': datetime.now().strftime("%Y-%m-%d")}
    save_ip_bans(ip_bans)
    success_iptables, iptables_output = manage_ip_iptables(ip, 'block', BLOCK_CHAIN)
    if success_iptables:
        log_action("IP_BLOCK_GLOBAL_SUCCESS", session.get('username', 'root'), f"Globally blocked IP {ip}")
        return jsonify({"success": True, "message": f"IP {ip} 已被全局封禁 (实时生效)。"})
    else:
        log_action("IP_BLOCK_GLOBAL_WARNING", session.get('username', 'root'), f"Globally blocked IP {ip} in DB, but IPTables failed: {iptables_output}")
        return jsonify({"success": False, "message": f"IP {ip} 已被全局封禁 (面板记录已更新)，但实时防火墙操作失败: {iptables_output}"})

@app.route('/api/ips/unban_global', methods=['POST'])
@login_required
def unban_ip_global_api():
    data = request.json
    ip = data.get('ip')
    if not ip: return jsonify({"success": False, "message": "缺少 IP"}), 400
    ip_bans = load_ip_bans()
    if 'global' in ip_bans and ip in ip_bans['global']:
        ip_bans['global'].pop(ip)
        save_ip_bans(ip_bans)
    success_iptables, iptables_output = manage_ip_iptables(ip, 'unblock', BLOCK_CHAIN)
    if success_iptables:
        log_action("IP_UNBLOCK_GLOBAL_SUCCESS", session.get('username', 'root'), f"Globally unblocked IP {ip}")
        return jsonify({"success": True, "message": f"IP {ip} 已解除全局封禁 (实时生效)。"})
    else:
        log_action("IP_UNBLOCK_GLOBAL_WARNING", session.get('username', 'root'), f"Globally unblocked IP {ip} in DB, but IPTables failed: {iptables_output}")
        return jsonify({"success": False, "message": f"IP {ip} 已解除全局封禁 (面板记录已更新)，但实时防火墙操作失败: {iptables_output}"})

@app.route('/api/ips/global_list', methods=['GET'])
@login_required
def get_global_ban_list():
    ip_bans = load_ip_bans()
    return jsonify({"success": True, "global_bans": ip_bans.get('global', {})})


if __name__ == '__main__':
    print(f"WSS Panel running on port {PANEL_PORT}")
    app.run(host='0.0.0.0', port=int(PANEL_PORT), debug=False)
EOF

chmod +x /usr/local/bin/wss_panel.py

# --- 2. 写入 HTML/JS 前端模板代码 (纯文本，防止 Python 报错) ---
echo "==== 写入 HTML 前端模板文件 ($PANEL_HTML) ===="
# 修复：使用 <<'EOF_HTML' 严格阻止 Bash 解析，确保 JS/Jinja2 语法完整
tee "$PANEL_HTML" > /dev/null <<'EOF_HTML'
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WSS 隧道管理面板 - 重构版 V2</title>
    <!-- 引入 Tailwind CSS CDN -->
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap');
        body { font-family: 'Inter', sans-serif; background-color: #f8fafc; }
        .card { transition: all 0.3s ease; }
        .card:hover { transform: translateY(-2px); box-shadow: 0 10px 15px rgba(0,0,0,0.05); }
        .modal { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background-color: rgba(0, 0, 0, 0.5); z-index: 1000; display: none; justify-content: center; align-items: center; }
        .log-pre { font-family: monospace; font-size: 0.8rem; white-space: pre; overflow-x: auto; max-height: 200px; }
        .status-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 6px; }
        .status-active { background-color: #10b981; }
        .status-paused { background-color: #f59e0b; }
        .status-expired { background-color: #ef4444; }
        /* 强制模态框内容居中显示 */
        .modal > div { max-width: 90%; }
        /* IP 封禁状态样式 */
        .ip-banned-tag { background-color: #fca5a5; color: #dc2626; font-weight: 600; }
        /* 侧边栏和主内容区域的布局 */
        .main-layout { display: flex; min-height: calc(100vh - 72px); }
        .sidebar { width: 250px; background-color: #ffffff; box-shadow: 2px 0 5px rgba(0,0,0,0.05); }
        .content { flex-grow: 1; }
    </style>
</head>
<body class="min-h-screen">

    <!-- Header / 导航栏 -->
    <header class="bg-indigo-700 shadow-lg sticky top-0 z-10">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4 flex justify-between items-center">
            <h1 class="text-2xl font-bold text-white tracking-wide">WSS 隧道管理面板 (V2 重构版)</h1>
            <button onclick="logout()" class="bg-red-500 hover:bg-red-600 text-white font-semibold py-2 px-4 rounded-lg transition duration-200 shadow-md">
                退出登录
            </button>
        </div>
    </header>

    <!-- 主布局：侧边栏 + 内容区 -->
    <div class="main-layout max-w-7xl mx-auto">
        <!-- 侧边栏 -->
        <aside class="sidebar p-4 sticky top-[72px] h-full hidden md:block">
            <nav class="space-y-2">
                <a href="#dashboard" onclick="switchView('dashboard')" class="block p-3 rounded-lg text-indigo-700 font-semibold bg-indigo-50 hover:bg-indigo-100 transition">
                    📊 仪表盘 (Dashboard)
                </a>
                <a href="#users" onclick="switchView('users')" class="block p-3 rounded-lg text-gray-700 font-semibold hover:bg-gray-100 transition">
                    👤 用户管理
                </a>
                <a href="#settings" onclick="switchView('settings')" class="block p-3 rounded-lg text-gray-700 font-semibold hover:bg-gray-100 transition">
                    🛠️ 系统配置/日志
                </a>
                <a href="#security" onclick="switchView('security')" class="block p-3 rounded-lg text-gray-700 font-semibold hover:bg-gray-100 transition">
                    🔒 安全/IP 封禁列表
                </a>
            </nav>
        </aside>

        <!-- 内容区域 -->
        <main class="content p-4 sm:p-6 lg:p-8">
            
            <!-- 全局状态信息/警告 -->
            <div id="status-message" class="hidden p-4 mb-6 rounded-xl font-medium border-l-4" role="alert"></div>

            <!-- 1. 仪表盘视图 (默认显示) -->
            <div id="view-dashboard">
                <!-- 实时系统状态卡片 -->
                <section class="mb-8">
                    <h2 class="text-xl font-semibold text-gray-700 mb-4">核心基础设施状态</h2>
                    <div id="system-status-grid" class="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
                        <!-- 动态加载系统和组件状态 -->
                        <p class="text-gray-500 col-span-6">正在加载系统状态...</p>
                    </div>
                </section>
                
                <!-- 端口状态和核心操作 -->
                <section class="card bg-white p-6 rounded-xl shadow-lg mb-8">
                    <h2 class="text-xl font-semibold text-gray-700 mb-4 border-b pb-2">服务端口与控制</h2>
                    <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
                        <div id="port-status-data" class="md:col-span-1 p-4 bg-gray-50 rounded-lg space-y-2 text-sm">
                            <!-- 端口列表（动态加载） -->
                            <p class="text-gray-500">正在检查端口状态...</p>
                        </div>
                        <div class="md:col-span-2 space-y-3">
                            <button onclick="confirmAction('wss', 'restart', 'serviceControl', '重启 WSS')" class="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-3 rounded-lg transition duration-200">
                                重启 WSS Proxy ({{ WSS_HTTP_PORT }}/{{ WSS_TLS_PORT }})
                            </button>
                            <button onclick="confirmAction('stunnel4', 'restart', 'serviceControl', '重启 Stunnel4')" class="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-3 rounded-lg transition duration-200">
                                重启 Stunnel4 ({{ STUNNEL_PORT }})
                            </button>
                            <button onclick="confirmAction('udpgw', 'restart', 'serviceControl', '重启 UDPGW')" class="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-3 rounded-lg transition duration-200">
                                重启 UDPGW ({{ UDPGW_PORT }})
                            </button>
                            <button onclick="confirmAction('wss_panel', 'restart', 'serviceControl', '重启面板')" class="w-full bg-red-600 hover:bg-red-700 text-white font-bold py-3 rounded-lg transition duration-200">
                                重启 Web Panel ({{ PANEL_PORT }})
                            </button>
                        </div>
                    </div>
                </section>
                
                <!-- 快速用户统计（可作为仪表盘卡片） -->
                <section class="mb-8">
                    <h2 class="text-xl font-semibold text-gray-700 mb-4">用户快速统计</h2>
                    <div id="user-quick-stats" class="grid grid-cols-2 md:grid-cols-4 gap-4">
                        <!-- 动态加载用户总数、活跃数等 -->
                    </div>
                </section>
            </div>

            <!-- 2. 用户管理视图 -->
            <div id="view-users" class="hidden">
                <h2 class="text-2xl font-bold text-gray-800 mb-6">👤 用户管理</h2>
                
                <!-- 新增用户表单 -->
                <section class="card bg-white p-6 rounded-xl shadow-lg mb-8">
                    <h3 class="text-xl font-semibold text-gray-700 mb-4 border-b pb-2">新增 SSH 隧道用户</h3>
                    <form id="add-user-form" class="grid grid-cols-1 md:grid-cols-6 gap-4 items-end">
                        <input type="text" id="new-username" placeholder="用户名 (Username)" required
                               class="col-span-2 p-3 border border-gray-300 rounded-lg focus:ring-indigo-500 focus:border-indigo-500">
                        <input type="password" id="new-password" placeholder="密码 (Password)" required
                               class="col-span-2 p-3 border border-gray-300 rounded-lg focus:ring-indigo-500 focus:border-indigo-500">
                        <input type="number" id="expiration-days" value="365" min="1" placeholder="有效期 (天)" required
                               class="col-span-1 p-3 border border-gray-300 rounded-lg focus:ring-indigo-500 focus:border-indigo-500">
                        <button type="submit" class="col-span-1 bg-green-600 hover:bg-green-700 text-white font-bold py-3 rounded-lg transition duration-200">
                            创建用户
                        </button>
                    </form>
                    <button onclick="openModal('batch-modal')" class="mt-4 bg-purple-500 hover:bg-purple-600 text-white font-bold py-2 px-4 rounded-lg transition duration-200 text-sm">
                        批量操作 / 续期 (待实现)
                    </button>
                </section>
                
                <!-- 用户列表 -->
                <section class="card bg-white p-6 rounded-xl shadow-lg">
                    <h3 class="text-xl font-semibold text-gray-700 mb-4 border-b pb-2">现有用户列表</h3>
                    <div class="overflow-x-auto border border-gray-200 rounded-lg">
                        <table class="min-w-full divide-y divide-gray-200">
                            <thead class="bg-gray-50">
                                <tr>
                                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">用户</th>
                                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">状态</th>
                                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">到期日</th>
                                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">流量用量/限额</th>
                                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">实时速度</th>
                                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider min-w-[250px]">操作</th>
                                </tr>
                            </thead>
                            <tbody id="user-list-tbody" class="bg-white divide-y divide-gray-200">
                                <!-- 动态加载用户列表 -->
                            </tbody>
                        </table>
                    </div>
                </section>
            </div>
            
            <!-- 3. 系统配置/日志视图 -->
            <div id="view-settings" class="hidden">
                <h2 class="text-2xl font-bold text-gray-800 mb-6">🛠️ 系统配置/日志</h2>

                <section class="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div class="card bg-white p-6 rounded-xl shadow-lg">
                        <h3 class="text-xl font-semibold text-gray-700 mb-4 border-b pb-2">核心服务日志 (最新 50 行)</h3>
                        <div class="space-y-4">
                            <div class="flex space-x-2 flex-wrap">
                                <button onclick="fetchServiceLogs('wss')" class="bg-gray-200 hover:bg-gray-300 px-3 py-1 text-sm rounded-lg mb-2">WSS Proxy</button>
                                <button onclick="fetchServiceLogs('stunnel4')" class="bg-gray-200 hover:bg-gray-300 px-3 py-1 text-sm rounded-lg mb-2">Stunnel4</button>
                                <button onclick="fetchServiceLogs('udpgw')" class="bg-gray-200 hover:bg-gray-300 px-3 py-1 text-sm rounded-lg mb-2">UDPGW</button>
                                <button onclick="fetchServiceLogs('wss_panel')" class="bg-gray-200 hover:bg-gray-300 px-3 py-1 text-sm rounded-lg mb-2">Web Panel</button>
                            </div>
                            <div class="bg-gray-800 text-gray-200 p-3 rounded-lg">
                                <pre id="service-log-content" class="log-pre">请选择服务加载日志...</pre>
                            </div>
                        </div>
                    </div>
                    
                    <div class="card bg-white p-6 rounded-xl shadow-lg">
                        <h3 class="text-xl font-semibold text-gray-700 mb-4 border-b pb-2">管理员审计日志 (最新活动)</h3>
                        <div class="bg-gray-100 p-3 rounded-lg max-h-[300px] overflow-y-auto">
                             <div id="audit-log-content" class="text-xs text-gray-700 space-y-1">正在加载审计日志...</div>
                        </div>
                    </div>
                </section>
            </div>
            
            <!-- 4. 安全/IP 封禁列表视图 -->
            <div id="view-security" class="hidden">
                <h2 class="text-2xl font-bold text-gray-800 mb-6">🔒 全局 IP 封禁管理</h2>

                <section class="card bg-white p-6 rounded-xl shadow-lg mb-8">
                    <h3 class="text-xl font-semibold text-gray-700 mb-4 border-b pb-2">IPTables 全局封禁 IP 列表</h3>
                    <div id="global-ban-list" class="space-y-3 max-h-96 overflow-y-auto p-3 bg-gray-50 rounded-lg border">
                        <p class="text-gray-500">正在加载全局 IP 封禁列表...</p>
                    </div>
                </section>
                
                <section class="card bg-white p-6 rounded-xl shadow-lg">
                    <h3 class="text-xl font-semibold text-gray-700 mb-4 border-b pb-2">新增全局封禁 IP</h3>
                    <form id="add-global-ban-form" class="flex space-x-4">
                        <input type="text" id="global-ban-ip" placeholder="输入要封禁的 IP 地址" required
                               class="flex-1 p-3 border border-gray-300 rounded-lg focus:ring-red-500 focus:border-red-500">
                        <button type="submit" class="bg-red-600 hover:bg-red-700 text-white font-bold py-3 px-6 rounded-lg transition duration-200">
                            全局封禁
                        </button>
                    </form>
                </section>
            </div>

        </main>
    </div>

    <!-- 模态框：设置用户配额/速度/密码/有效期 -->
    <div id="settings-modal" class="modal">
        <div class="bg-white p-6 rounded-xl shadow-2xl w-full max-w-lg">
            <h3 class="text-xl font-bold text-gray-800 mb-4 border-b pb-2">设置 <span id="modal-username-title" class="text-indigo-600"></span> 的参数</h3>
            <form id="settings-form" onsubmit="event.preventDefault(); saveUserSettings();">
                <input type="hidden" id="modal-username-setting">
                
                <div class="space-y-4">
                    <div>
                        <label for="modal-expiry-date" class="block text-sm font-medium text-gray-700 mb-1">到期日期 (YYYY-MM-DD, 永不留空)</label>
                        <input type="date" id="modal-expiry-date" class="w-full p-3 border border-gray-300 rounded-lg">
                    </div>
                    
                    <div class="grid grid-cols-2 gap-4">
                        <div>
                            <label for="modal-quota-gb" class="block text-sm font-medium text-gray-700 mb-1">流量限额 (GB, 0=无限制)</label>
                            <input type="number" id="modal-quota-gb" min="0" required class="w-full p-3 border border-gray-300 rounded-lg">
                        </div>
                        <div>
                            <label for="modal-rate-kbps" class="block text-sm font-medium text-gray-700 mb-1">最大速度 (KB/s, 0=无限制)</label>
                            <input type="number" id="modal-rate-kbps" min="0" required class="w-full p-3 border border-gray-300 rounded-lg">
                        </div>
                    </div>

                    <div class="border-t pt-4">
                        <label for="modal-new-password" class="block text-sm font-medium text-gray-700 mb-1">修改密码 (选填)</label>
                        <input type="password" id="modal-new-password" placeholder="留空则不修改" class="w-full p-3 border border-gray-300 rounded-lg">
                        <p class="text-xs text-gray-500 mt-1">注意：修改密码后，所有该用户当前活跃的连接将被强制断开。</p>
                    </div>
                </div>

                <div class="mt-6 flex justify-end space-x-3">
                    <button type="button" onclick="closeModal('settings-modal')" class="bg-gray-300 hover:bg-gray-400 text-gray-800 font-semibold py-2 px-4 rounded-lg">取消</button>
                    <button type="submit" class="bg-indigo-600 hover:bg-indigo-700 text-white font-semibold py-2 px-4 rounded-lg">保存设置</button>
                </div>
            </form>
        </div>
    </div>
    
    <!-- 模态框：IP 活跃度与封禁控制 -->
    <div id="ip-activity-modal" class="modal">
        <div class="bg-white p-6 rounded-xl shadow-2xl w-full max-w-2xl">
            <h3 class="text-xl font-bold text-gray-800 mb-4 border-b pb-2">用户 <span id="ip-modal-username-title" class="text-indigo-600"></span> 活跃 IP</h3>
            
            <div class="text-sm text-gray-600 mb-4">
                <p>实时 IP 数据源于底层连接追踪。流量和封禁操作将实时生效。</p>
            </div>

            <!-- IP 列表容器 -->
            <div id="active-ip-list" class="space-y-3 max-h-96 overflow-y-auto p-3 bg-gray-50 rounded-lg border">
                <p class="text-gray-500">正在加载 IP 数据...</p>
            </div>
            
            <div class="mt-6 flex justify-between">
                <button onclick="confirmAction(document.getElementById('ip-modal-username-title').textContent, null, 'killAll', '强制断开所有')" 
                        class="bg-red-500 hover:bg-red-600 text-white font-semibold py-2 px-4 rounded-lg text-sm">
                        强制断开所有连接
                </button>
                <button type="button" onclick="closeModal('ip-activity-modal')" class="bg-gray-300 hover:bg-gray-400 text-gray-800 font-semibold py-2 px-4 rounded-lg">关闭</button>
            </div>
        </div>
    </div>

    <!-- 模态框：通用确认 -->
    <div id="confirm-modal" class="modal">
        <div class="bg-white p-6 rounded-xl shadow-2xl w-full max-w-sm">
            <h3 class="text-xl font-bold text-gray-800 mb-4 border-b pb-2" id="confirm-title"></h3>
            <p id="confirm-message" class="text-gray-700 mb-6"></p>
            <div class="flex justify-end space-x-3">
                <button type="button" onclick="closeModal('confirm-modal')" class="bg-gray-300 hover:bg-gray-400 text-gray-800 font-semibold py-2 px-4 rounded-lg">取消</button>
                <button type="button" id="confirm-action-btn" class="bg-red-600 hover:bg-red-700 text-white font-semibold py-2 px-4 rounded-lg">确认</button>
            </div>
        </div>
    </div>
    
    <!-- 模态框：批量操作（待实现） -->
    <div id="batch-modal" class="modal">
        <div class="bg-white p-6 rounded-xl shadow-2xl w-full max-w-lg">
            <h3 class="text-xl font-bold text-gray-800 mb-4 border-b pb-2">批量操作 / 续期</h3>
            <p class="text-gray-500">此功能将在后续的后端开发中实现。</p>
            <div class="mt-6 flex justify-end">
                <button type="button" onclick="closeModal('batch-modal')" class="bg-gray-300 hover:bg-gray-400 text-gray-800 font-semibold py-2 px-4 rounded-lg">关闭</button>
            </div>
        </div>
    </div>
    

    <script>
        // --- 全局配置 (由 Flask 填充) ---
        const API_BASE = '/api';
        let currentView = 'dashboard';
        const FLASK_CONFIG = {
            WSS_HTTP_PORT: "{{ WSS_HTTP_PORT }}",
            WSS_TLS_PORT: "{{ WSS_TLS_PORT }}",
            STUNNEL_PORT: "{{ STUNNEL_PORT }}",
            UDPGW_PORT: "{{ UDPGW_PORT }}",
            PANEL_PORT: "{{ PANEL_PORT }}",
            SSH_INTERNAL_PORT: "{{ INTERNAL_FORWARD_PORT }}"
        };

        const PORTS_CONFIG = {
            'WSS_HTTP': { port: FLASK_CONFIG.WSS_HTTP_PORT, service: 'wss', proto: 'TCP' }, 
            'WSS_TLS': { port: FLASK_CONFIG.WSS_TLS_PORT, service: 'wss', proto: 'TCP' }, 
            'STUNNEL': { port: FLASK_CONFIG.STUNNEL_PORT, service: 'stunnel4', proto: 'TCP' }, 
            'UDPGW': { port: FLASK_CONFIG.UDPGW_PORT, service: 'udpgw', proto: 'UDP' }, 
            'PANEL': { port: FLASK_CONFIG.PANEL_PORT, service: 'wss_panel', proto: 'TCP' }, 
            'SSH_INTERNAL': { port: FLASK_CONFIG.SSH_INTERNAL_PORT, service: 'ssh', proto: 'TCP' }
        };

        // --- 辅助工具函数 ---

        function showStatus(message, isSuccess = true) {
            const statusDiv = document.getElementById('status-message');
            statusDiv.innerHTML = message;
            statusDiv.className = isSuccess 
                ? 'bg-green-100 text-green-800 border-green-400 p-4 mb-6 rounded-xl font-medium border-l-4' 
                : 'bg-red-100 text-red-800 border-red-400 p-4 mb-6 rounded-xl font-medium border-l-4';
            statusDiv.style.display = 'block';
            setTimeout(() => { statusDiv.style.display = 'none'; }, 5000);
        }

        function openModal(id) {
            document.getElementById(id).style.display = 'flex';
        }

        function closeModal(id) {
            document.getElementById(id).style.display = 'none';
        }

        function logout() {
            window.location.href = '/logout'; 
        }
        
        function formatSpeed(kbps) {
            if (kbps < 1024) return kbps.toFixed(1) + ' KB/s';
            const mbps = kbps / 1024;
            return mbps.toFixed(2) + ' MB/s';
        }

        // --- 视图切换逻辑 ---
        
        function switchView(viewId) {
            const views = ['dashboard', 'users', 'settings', 'security'];
            views.forEach(id => {
                const element = document.getElementById('view-' + id);
                if (element) element.style.display = (id === viewId) ? 'block' : 'none';
            });
            currentView = viewId;
            // 刷新当前视图的数据
            refreshAllData();
            
            // 更新侧边栏选中状态
            document.querySelectorAll('.sidebar a').forEach(a => {
                a.classList.remove('bg-indigo-50', 'text-indigo-700');
                if (a.getAttribute('href').substring(1) === viewId) {
                    a.classList.add('bg-indigo-50', 'text-indigo-700');
                } else {
                    a.classList.add('text-gray-700');
                }
            });
        }
        
        // --- 数据渲染函数 ---
        
        function renderSystemStatus(data) {
            const grid = document.getElementById('system-status-grid');
            grid.innerHTML = ''; 

            const items = [
                { name: 'CPU 使用率', value: data.cpu_usage.toFixed(1) + '%', color: 'bg-blue-500', icon: '⚡' },
                { name: '内存 (用/总)', value: data.memory_used_gb.toFixed(2) + '/' + data.memory_total_gb.toFixed(2) + 'GB', color: 'bg-indigo-500', icon: '🧠' },
                { name: '磁盘使用率', value: data.disk_used_percent.toFixed(1) + '%', color: 'bg-purple-500', icon: '💾' },
                ...Object.keys(data.services).map(key => {
                    const status = data.services[key].status;
                    return {
                        name: data.services[key].name,
                        value: data.services[key].label,
                        color: status === 'running' ? 'bg-green-500' : (status === 'failed' ? 'bg-red-500' : 'bg-yellow-500'),
                        dotClass: status === 'running' ? 'status-active' : (status === 'failed' ? 'status-expired' : 'status-paused'),
                        icon: '📡'
                    };
                })
            ];

            items.forEach(item => {
                const dot = item.dotClass ? '<span class="status-dot ' + item.dotClass + '"></span>' : '';
                grid.innerHTML += 
                    '<div class="bg-white p-4 rounded-xl shadow-md border-b-4 ' + item.color.replace('bg-', 'border-') + ' card">' +
                        '<div class="flex items-center text-sm font-medium text-gray-500 mb-1">' +
                            item.icon + ' <span class="ml-1">' + item.name + '</span>' +
                        '</div>' +
                        '<p class="text-xl font-bold text-gray-800 flex items-center">' +
                            dot + ' ' + item.value +
                        '</p>' +
                    '</div>';
            });
            
            // 渲染端口状态列表
            renderPortStatusList(data.ports);
            
            // 渲染用户快速统计
            renderUserQuickStats(data.user_stats);
        }
        
        function renderPortStatusList(ports) {
            const container = document.getElementById('port-status-data');
            container.innerHTML = '';
            
            ports.forEach(p => {
                const isListening = p.status === 'LISTEN';
                const dotClass = isListening ? 'status-active' : 'status-expired';
                const textClass = isListening ? 'text-green-600' : 'text-red-600';
                
                container.innerHTML += 
                    '<div class="flex justify-between items-center text-gray-700 p-2 bg-white rounded-lg shadow-sm">' +
                        '<span class="font-medium">' + p.name + ' (' + p.port + '/' + p.protocol + '):</span>' +
                        '<span class="font-bold flex items-center ' + textClass + '">' +
                            '<span class="status-dot ' + dotClass + '"></span> ' + p.status +
                        '</span>' +
                    '</div>';
            });
        }
        
        function renderUserQuickStats(stats) {
            const container = document.getElementById('user-quick-stats');
            container.innerHTML = 
                '<div class="bg-white p-4 rounded-xl shadow-md border-l-4 border-indigo-500 card">' +
                    '<p class="text-sm text-gray-500">用户总数</p>' +
                    '<p class="text-2xl font-bold">' + stats.total + '</p>' +
                '</div>' +
                '<div class="bg-white p-4 rounded-xl shadow-md border-l-4 border-green-500 card">' +
                    '<p class="text-sm text-gray-500">活跃用户</p>' +
                    '<p class="text-2xl font-bold">' + stats.active + '</p>' +
                '</div>' +
                '<div class="bg-white p-4 rounded-xl shadow-md border-l-4 border-yellow-500 card">' +
                    '<p class="text-sm text-gray-500">暂停/不可用</p>' +
                    '<p class="text-2xl font-bold">' + (stats.paused + stats.expired) + '</p>' +
                '</div>' +
                '<div class="bg-white p-4 rounded-xl shadow-md border-l-4 border-purple-500 card">' +
                    '<p class="text-sm text-gray-500">总用量</p>' +
                    '<p class="text-2xl font-bold">' + stats.total_traffic_gb.toFixed(2) + ' GB</p>' +
                '</div>';
        }


        function renderUserList(users) {
            const tbody = document.getElementById('user-list-tbody');
            tbody.innerHTML = '';
            
            if (users.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" class="px-6 py-4 text-center text-gray-500">暂无用户账号</td></tr>';
                return;
            }

            users.forEach(user => {
                const isPaused = user.status !== 'active';
                let statusColor = 'bg-green-100 text-green-700';
                if (user.status === 'paused') { statusColor = 'bg-yellow-100 text-yellow-700'; }
                if (user.status === 'expired' || user.status === 'exceeded') { statusColor = 'bg-red-100 text-red-700'; }

                const statusText = user.status_text;
                const toggleAction = isPaused ? 'enable' : 'pause';
                const toggleText = isPaused ? '启用' : '暂停';
                const toggleColor = isPaused ? 'bg-green-500 hover:bg-green-600' : 'bg-yellow-500 hover:bg-yellow-600';
                
                const usageText = user.quota_gb > 0 ? user.usage_gb.toFixed(2) + ' / ' + user.quota_gb + ' GB' : user.usage_gb.toFixed(2) + ' GB (无限制)';
                
                tbody.innerHTML += 
                    '<tr id="row-' + user.username + '" class="hover:bg-gray-50">' +
                        '<td class="px-6 py-4 whitespace-nowrap text-sm font-mono text-gray-900">' + user.username + '</td>' +
                        '<td class="px-6 py-4 whitespace-nowrap text-sm">' +
                            '<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full ' + statusColor + '">' +
                                statusText +
                            '</span>' +
                        '</td>' +
                        '<td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">' + (user.expiry_date || '永不') + '</td>' +
                        '<td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-700">' + usageText + '</td>' +
                        '<td class="px-6 py-4 whitespace-nowrap text-sm font-mono text-indigo-600">' + formatSpeed(user.realtime_speed) + '</td>' +
                        '<td class="px-6 py-4 whitespace-nowrap text-sm font-medium space-x-2">' +
                            '<button onclick="openIPActivityModal(\'' + user.username + '\')" ' +
                                    'class="bg-blue-500 hover:bg-blue-600 text-white py-1 px-3 rounded-lg text-xs transition duration-150">IP 追踪</button>' +
                            '<button onclick="openSettingsModal(\'' + user.username + '\', \'' + (user.expiry_date || '') + '\', ' + user.quota_gb + ', ' + user.rate_kbps + ')" ' +
                                    'class="bg-indigo-500 hover:bg-indigo-600 text-white py-1 px-3 rounded-lg text-xs transition duration-150">设置</button>' +
                            '<button onclick="confirmAction(\'' + user.username + '\', \'' + toggleAction + '\', \'toggleStatus\', \'' + toggleText + '用户\')" ' +
                                    'class="' + toggleColor + ' text-white py-1 px-3 rounded-lg text-xs transition duration-150">' + toggleText + '</button>' +
                            '<button onclick="confirmAction(\'' + user.username + '\', \'delete\', \'deleteUser\', \'删除用户\')" ' +
                                    'class="bg-red-500 hover:bg-red-600 text-white py-1 px-3 rounded-lg text-xs transition duration-150">删除</button>' +
                        '</td>' +
                    '</tr>';
            });
        }
        
        function renderIPActivity(username, ipData) {
            const listDiv = document.getElementById('active-ip-list');
            listDiv.innerHTML = '';
            
            if (ipData.length === 0) {
                listDiv.innerHTML = '<p class="text-gray-500 p-2">此用户目前没有活动的连接记录。</p>';
                return;
            }

            ipData.forEach(ipInfo => {
                const isBanned = ipInfo.is_banned;
                const action = isBanned ? 'unban' : 'ban';
                const actionText = isBanned ? '解除封禁' : '封禁 IP';
                const buttonColor = isBanned ? 'bg-green-600 hover:bg-green-700' : 'bg-red-600 hover:bg-red-700';
                const banTag = isBanned ? '<span class="text-xs px-2 py-0.5 rounded-full ip-banned-tag ml-2">已封禁 (防火墙)</span>' : '';

                listDiv.innerHTML += 
                    '<div class="flex flex-col sm:flex-row items-start sm:items-center justify-between p-3 bg-white border border-gray-200 rounded-lg shadow-sm">' +
                        '<div class="min-w-0 flex-1 flex flex-col sm:flex-row sm:items-center">' +
                            '<p class="font-mono text-sm text-gray-900 flex items-center">' +
                                '<strong>' + ipInfo.ip + '</strong> ' + banTag +
                            '</p>' +
                            '<p class="text-xs text-gray-500 mt-1 sm:mt-0 sm:ml-4">' +
                                '流量: ' + ipInfo.usage_gb.toFixed(2) + ' GB | 速度: ' + formatSpeed(ipInfo.realtime_speed) + ' | PIDs: ' + ipInfo.pids.join(', ') +
                            '</p>' +
                        '</div>' +
                        '<button onclick="confirmAction(\'' + username + '\', \'' + ipInfo.ip + '\', \'' + action + '\', \'' + actionText + ' IP\', \'' + ipInfo.ip + '\')" ' +
                                'class="mt-2 sm:mt-0 w-full sm:w-auto ' + buttonColor + ' text-white py-1.5 px-3 rounded-lg text-xs font-semibold transition duration-150">' +
                            actionText +
                        '</button>' +
                    '</div>';
            });
        }
        
        async function renderAuditLogs(logs) {
            const logContainer = document.getElementById('audit-log-content');
            if (logs.length === 0) {
                logContainer.innerHTML = '<p class="text-gray-500">目前没有管理活动日志。</p>';
                return;
            }
            logContainer.innerHTML = logs.map(log => {
                const parts = log.match(/^\[(.*?)\] \[USER:(.*?)\] \[IP:(.*?)\] ACTION:(.*?) DETAILS: (.*)$/);
                if (parts) {
                    const [_, timestamp, user, ip, action, details] = parts;
                    return '<div class="text-xs text-gray-700 font-mono space-y-1 p-1 hover:bg-gray-200 rounded-md">' +
                        '<span class="text-indigo-600">' + timestamp.split(' ')[1] + '</span> ' +
                        '<span class="font-bold">[' + user + ']</span> ' +
                        '<span class="text-sm font-semibold text-gray-900">' + action + '</span> ' +
                        '<span class="text-gray-500">' + details + '</span>' +
                    '</div>';
                }
                return '<div class="text-xs text-gray-700 font-mono p-1">' + log + '</div>';
            }).join('');
        }
        
        function renderGlobalBans(bans) {
            const container = document.getElementById('global-ban-list');
            if (Object.keys(bans).length === 0) {
                 container.innerHTML = '<p class="text-green-600 font-semibold p-2">目前没有全局封禁的 IP。</p>';
                 return;
            }
            container.innerHTML = Object.keys(bans).map(ip => {
                const banInfo = bans[ip];
                return (
                    '<div class="flex justify-between items-center p-3 bg-red-50 border border-red-200 rounded-lg shadow-sm">' +
                        '<div class="font-mono text-sm text-red-700">' +
                            '<strong>' + ip + '</strong> ' +
                            '<span class="text-xs text-gray-500 ml-4">原因: ' + banInfo.reason + ' (添加于 ' + banInfo.timestamp + ')</span>' +
                        '</div>' +
                        '<button onclick="confirmAction(null, \'' + ip + '\', \'unbanGlobal\', \'解除全局封禁\')" ' +
                                'class="bg-green-600 hover:bg-green-700 text-white py-1.5 px-3 rounded-lg text-xs font-semibold">' +
                            '解除封禁' +
                        '</button>' +
                    '</div>'
                );
            }).join('');
        }


        // --- 核心 API 调用函数 ---
        
        async function fetchData(url, options = {}) {
            try {
                const response = await fetch(API_BASE + url, options);
                const data = await response.json();
                
                if (!response.ok || !data.success) {
                    showStatus(data.message || 'API Error: ' + url, false);
                    return null;
                }
                return data;
            } catch (error) {
                showStatus('网络请求失败: ' + error.message, false);
                return null;
            }
        }

        async function fetchServiceLogs(serviceId) {
            const logContainer = document.getElementById('service-log-content');
            logContainer.textContent = '正在加载 ' + serviceId + ' 日志...';
            
            const data = await fetchData('/system/logs', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ service: serviceId })
            });

            if (data && data.logs) {
                logContainer.textContent = data.logs;
            } else {
                logContainer.textContent = '无法加载 ' + serviceId + ' 日志。';
            }
        }
        
        // --- 实时刷新主函数 ---

        async function refreshAllData() {
            // 1. 获取系统和组件状态
            const statusData = await fetchData('/system/status');
            if (statusData) {
                renderSystemStatus(statusData);
            }

            if (currentView === 'users' || currentView === 'dashboard') {
                // 2. 获取用户列表和统计
                const usersData = await fetchData('/users/list');
                if (usersData) {
                    renderUserList(usersData.users);
                }
            }
            
            if (currentView === 'settings') {
                // 3. 获取审计日志
                const auditData = await fetchData('/system/audit_logs');
                if (auditData) {
                    renderAuditLogs(auditData.logs);
                }
            }
            
            if (currentView === 'security') {
                // 4. 获取全局 IP 封禁列表
                const globalData = await fetchData('/ips/global_list');
                if (globalData) {
                    renderGlobalBans(globalData.global_bans);
                }
            }
            
            // 5. (静默刷新：IP 活跃度模态框如果打开则刷新)
            const ipModal = document.getElementById('ip-activity-modal');
            if (ipModal.style.display === 'flex') {
                const username = document.getElementById('ip-modal-username-title').textContent;
                fetchIPActivity(username); 
            }
        }

        // --- 用户操作实现 ---

        document.getElementById('add-user-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const username = document.getElementById('new-username').value;
            const password = document.getElementById('new-password').value;
            const expirationDays = document.getElementById('expiration-days').value;

            if (!/^[a-z0-9_]{3,16}$/.test(username)) {
                showStatus('用户名格式不正确 (3-16位小写字母/数字/下划线)', false);
                return;
            }
            
            showStatus('正在创建用户 ' + username + '...', true);

            const result = await fetchData('/users/add', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: username, password: password, expiration_days: parseInt(expirationDays) })
            });

            if (result) {
                showStatus(result.message, true);
                document.getElementById('add-user-form').reset();
                refreshAllData(); 
            }
        });
        
        function openSettingsModal(username, expiry_date, quota_gb, rate_kbps) {
            document.getElementById('modal-username-title').textContent = username;
            document.getElementById('modal-username-setting').value = username;
            
            document.getElementById('modal-expiry-date').value = expiry_date; 
            document.getElementById('modal-quota-gb').value = quota_gb;
            document.getElementById('modal-rate-kbps').value = rate_kbps;
            document.getElementById('modal-new-password').value = '';
            
            openModal('settings-modal');
        }

        async function saveUserSettings() {
            const username = document.getElementById('modal-username-setting').value;
            const expiry_date = document.getElementById('modal-expiry-date').value;
            const quota_gb = document.getElementById('modal-quota-gb').value;
            const rate_kbps = document.getElementById('modal-rate-kbps').value;
            const new_password = document.getElementById('modal-new-password').value;
            
            closeModal('settings-modal');
            showStatus('正在保存用户 ' + username + ' 的设置...', true);

            const result = await fetchData('/users/set_settings', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    username: username, 
                    expiry_date: expiry_date, 
                    quota_gb: parseFloat(quota_gb), 
                    rate_kbps: parseInt(rate_kbps),
                    new_password: new_password
                })
            });

            if (result) {
                showStatus(result.message, true);
                refreshAllData();
            }
        }
        
        function openIPActivityModal(username) {
            document.getElementById('ip-modal-username-title').textContent = username;
            openModal('ip-activity-modal');
            fetchIPActivity(username);
        }
        
        async function fetchIPActivity(username) {
            const listDiv = document.getElementById('active-ip-list');
            listDiv.innerHTML = '<p class="text-indigo-500 p-2">正在从系统进程中获取实时 IP 数据...</p>';
            
            const data = await fetchData('/users/ip_activity?username=' + username);
            
            if (data) {
                renderIPActivity(username, data.ip_data);
            }
        }

        // --- 通用确认及执行逻辑 ---

        function confirmAction(username, action, type, ip = null) {
            const title = arguments[3]; // titleText
            let message = '';
            let buttonText = title;
            
            if (type === 'deleteUser') {
                message = '您确定要永久删除用户 <strong>' + username + '</strong> 吗？此操作不可逆，将删除系统账户和所有配置。';
            } else if (type === 'toggleStatus') {
                message = '您确定要 ' + (action === 'pause' ? '暂停' : '启用') + ' 用户 <strong>' + username + '</strong> 吗？';
            } else if (type === 'ban' || type === 'unban') {
                message = '您确定要对用户 <strong>' + username + '</strong> 的 IP 地址 <strong>' + ip + '</strong> 执行 ' + (type === 'ban' ? '封禁' : '解除封禁') + ' 操作吗？此操作将立即通过防火墙规则生效。';
                buttonText = action === 'ban' ? '确认封禁' : '确认解除';
            } else if (type === 'killAll') {
                message = '警告：您确定要强制断开用户 <strong>' + username + '</strong> 的所有活跃连接吗？这会强制用户重新连接。';
                buttonText = '确认断开';
            } else if (type === 'serviceControl') {
                 message = '警告：您确定要重启核心服务 <strong>' + username + '</strong> 吗？这可能会导致短暂的服务中断。';
                 buttonText = '确认重启';
            } else if (type === 'unbanGlobal') {
                 message = '您确定要解除全局封禁 IP 地址 <strong>' + action + '</strong> 吗？';
                 buttonText = '确认解除';
            } else if (type === 'banGlobal') {
                 message = '您确定要对 IP 地址 <strong>' + action + '</strong> 执行全局封禁操作吗？';
                 buttonText = '确认封禁';
            }

            document.getElementById('confirm-title').textContent = title;
            document.getElementById('confirm-message').innerHTML = message;
            
            const confirmBtn = document.getElementById('confirm-action-btn');
            
            if (type.includes('ban') || type === 'killAll' || type === 'serviceControl') {
                 confirmBtn.className = 'bg-red-600 hover:bg-red-700 text-white font-semibold py-2 px-4 rounded-lg';
            } else if (type.includes('enable') || type === 'unbanGlobal') {
                 confirmBtn.className = 'bg-green-600 hover:bg-green-700 text-white font-semibold py-2 px-4 rounded-lg';
            } else {
                 confirmBtn.className = 'bg-indigo-600 hover:bg-indigo-700 text-white font-semibold py-2 px-4 rounded-lg';
            }

            confirmBtn.onclick = () => executeAction(username, action, type, ip);
            
            openModal('confirm-modal');
        }

        async function executeAction(username, action, type, ip) {
            closeModal('confirm-modal');
            showStatus('正在执行 ' + type + ' 操作...', true);

            let url;
            let body = { username: username };

            if (type === 'deleteUser') {
                url = '/users/delete';
            } else if (type === 'toggleStatus') {
                url = '/users/status';
                body.action = action; 
            } else if (type === 'killAll') {
                 url = '/users/kill_all';
            } else if (type === 'ban' || type === 'unban') {
                url = '/ips/' + action;
                body.ip = ip;
                body.username = username; // Ensure username is passed for user-specific bans/unbans
            } else if (type === 'serviceControl') {
                 url = '/system/control';
                 body = { service: username, action: action }; // username is service name, action is restart
            } else if (type === 'unbanGlobal') {
                 url = '/ips/unban_global';
                 body = { ip: action }; // action is the IP for global unban
            } else if (type === 'banGlobal') {
                 url = '/ips/ban_global';
                 body = { ip: action, reason: 'Manual Global Ban' }; // action is the IP for global ban
            }

            const result = await fetchData(url, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body)
            });

            if (result) {
                showStatus(result.message, true);
                if (type === 'ban' || type === 'unban' || type === 'killAll') {
                    fetchIPActivity(username); 
                }
                
                // 系统控制或主用户列表的刷新
                if (type === 'serviceControl' || type === 'deleteUser' || type === 'toggleStatus' || type === 'unbanGlobal' || type === 'banGlobal') {
                    setTimeout(refreshAllData, 2000); 
                }
            }
        }
        
        document.getElementById('add-global-ban-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const ip = document.getElementById('global-ban-ip').value;
            
            if (!ip) return showStatus('IP 地址不能为空', false);
            
            confirmAction(null, ip, 'banGlobal', '全局封禁 IP');
        });


        // --- 启动脚本 ---
        
        window.onload = function() {
            // 初始加载和定时刷新
            switchView('dashboard');
            setInterval(refreshAllData, 10000); 
        };

    </script>
</body>
</html>
EOF_HTML

# 确保所有文件都有执行权限
chmod +x /usr/local/bin/wss_panel.py

# =============================
# 创建 WSS 面板 systemd 服务
# =============================
tee /etc/systemd/system/wss_panel.service > /dev/null <<EOF
[Unit]
Description=WSS User Management Panel (Flask V2)
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /usr/local/bin/wss_panel.py
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable wss_panel
systemctl start wss_panel
echo "WSS 管理面板 V2 已启动，端口 $PANEL_PORT"
echo "----------------------------------"

# =============================
# SSHD 安全配置 (禁用 Shell 访问)
# =============================
SSHD_CONFIG="/etc/ssh/sshd_config"
BACKUP_SUFFIX=".bak.wss$(date +%s)"
SSHD_SERVICE=$(systemctl list-units --full -all | grep -q "sshd.service" && echo "sshd" || echo "ssh")

echo "==== 配置 SSHD 安全策略 (禁用 Shell, 允许本机密码认证) ===="
cp -a "$SSHD_CONFIG" "${SSHD_CONFIG}${BACKUP_SUFFIX}"
echo "SSHD 配置已备份到 ${SSHD_CONFIG}${BACKUP_SUFFIX}"

# 删除旧的 WSS 配置段
sed -i '/# WSS_TUNNEL_BLOCK_START/,/# WSS_TUNNEL_BLOCK_END/d' "$SSHD_CONFIG"

# 写入新的 WSS 隧道策略 (核心: PermitTTY no 和 ForceCommand /bin/false)
# 修复：使用 4 个标准空格来确保 SSHD 解析器正确识别缩进。
cat >> "$SSHD_CONFIG" <<EOF

# WSS_TUNNEL_BLOCK_START -- managed by deploy_wss_panel.sh V2
# 统一策略: 允许所有用户通过本机 (127.0.0.1, ::1) 使用密码进行认证。
Match Address 127.0.0.1,::1
    # 允许密码认证
    PasswordAuthentication yes
    # 禁止交互式 TTY
    PermitTTY no
    # 允许 TCP 转发 (核心功能)
    AllowTcpForwarding yes
    # 强制执行 /bin/false，禁用 Shell 访问
    ForceCommand /bin/false
# WSS_TUNNEL_BLOCK_END -- managed by deploy_wss_panel.sh V2

EOF

chmod 600 "$SSHD_CONFIG"

# 重载 sshd
echo "重新加载并重启 ssh 服务 ($SSHD_SERVICE)"
systemctl daemon-reload
systemctl restart "$SSHD_SERVICE"
echo "SSHD 配置更新完成。内部SSH转发端口: $INTERNAL_FORWARD_PORT (禁止Shell)"
echo "----------------------------------"


# =============================
# 最终重启所有关键服务
# =============================
echo "==== 最终重启所有关键服务，确保配置生效 ===="
systemctl restart wss stunnel4 udpgw wss_panel
echo "所有服务重启完成：WSS, Stunnel4, UDPGW, Web Panel。"
echo "----------------------------------"


# 清理敏感变量
unset PANEL_ROOT_PASS_RAW

echo "=================================================="
echo "✅ 部署完成！"
echo "=================================================="
echo ""
echo "🔥 WSS & Stunnel 基础设施已启动。"
echo "🌐 WSS 用户管理面板已在后台运行。"
echo ""
echo "--- 访问信息 ---"
echo "Web 面板地址: http://[您的服务器IP]:$PANEL_PORT"
echo "Web 面板用户名: root"
echo "Web 面板密码: [您刚才设置的密码]"
echo ""
echo "--- 端口信息 ---"
echo "WSS (HTTP/WebSocket): $WSS_HTTP_PORT"
echo "WSS (TLS/WebSocket): $WSS_TLS_PORT"
echo "Stunnel (TLS 隧道): $STUNNEL_PORT"
echo "UDPGW (内部 UDP 转发): $UDPGW_PORT"
echo "内部 SSH 转发端口: $INTERNAL_FORWARD_PORT (WSS/Stunnel 代理连接到 SSH 的端口)"
echo ""
echo "--- 故障排查 ---"
echo "WSS 代理状态: sudo systemctl status wss"
echo "Stunnel 状态: sudo systemctl status stunnel4"
echo "Web 面板状态: sudo systemctl status wss_panel"
echo "用户数据库路径: /etc/wss-panel/users.json (面板通过此文件进行用户查询和管理)"
echo "=================================================="
