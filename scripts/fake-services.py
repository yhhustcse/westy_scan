#!/usr/bin/env python3
"""本地假服务集合：只监听 127.0.0.1，用于验证服务识别能力（M1 验收）。

刻意模仿真实服务的握手报文，让框架的协议探针有机会工作：

    2222   SSH        SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13
    3306   MySQL      MySQL 8.0.35 / caching_sha2_password
    5432   PostgreSQL SSLRequest -> 'S'
    6379   Redis      7.2.4（对 INFO 回 bulk string）
    11211  Memcached  1.6.17
    5900   VNC        RFB 003.008，安全类型 [None, VNC-Auth]
    53/udp DNS        对任意查询回一个 NS 应答（验证 UDP 探测链路）
    18081  HTTP       M3/M4 演示站点（robots/sitemap/JS/表单 + 一批典型暴露点）
    18082  CANARY     规则库金丝雀站点：严格按 scripts/rules-fixtures/*.json 返回响应

用法：
    python scripts/fake-services.py            # 前台运行，Ctrl-C 退出
    python scripts/fake-services.py --quiet    # 少打印

注意：这是**测试用**的假服务，不具备任何真实服务功能，也不接受任何输入命令。
"""

import argparse
import json
import os
import socket
import struct
import sys
import threading
import time

HOST = "127.0.0.1"

# 输出统一走 UTF-8：Windows 上 Python 重定向到文件时默认用 GBK，
# 中文日志会被 PowerShell 按 UTF-8 读成乱码（报错信息看不懂 = 白报错）。
try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

SERVICES = [
    (2222, "SSH"),
    (3306, "MySQL"),
    (5432, "PostgreSQL"),
    (6379, "Redis"),
    (11211, "Memcached"),
    (5900, "VNC"),
    (18081, "HTTP"),
    (18082, "CANARY"),
    (18099, "BLACKHOLE"),
]

# 一个最小 PNG（内容是任意的，favicon 指纹只关心字节的 mmh3 哈希）
FAVICON = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) + bytes(range(64))


def mysql_handshake(version=b"8.0.35", plugin=b"caching_sha2_password", caps=0x00080800):
    """构造 MySQL 服务端握手包（协议版本 10）。"""
    payload = b"\x0a" + version + b"\x00"
    payload += struct.pack("<I", 1)          # thread id
    payload += b"\x00" * 8                   # auth-plugin-data-1
    payload += b"\x00"                       # filler
    payload += struct.pack("<H", caps & 0xFFFF)
    payload += b"\x21"                       # charset utf8_general_ci
    payload += struct.pack("<H", 2)          # status flags
    payload += struct.pack("<H", (caps >> 16) & 0xFFFF)
    payload += bytes([21])                   # auth plugin data len
    payload += b"\x00" * 10                  # reserved
    payload += b"abcdefghijklm"              # auth-plugin-data-2
    payload += plugin + b"\x00"
    return struct.pack("<I", len(payload))[:3] + b"\x00" + payload


def handle_ssh(conn):
    conn.sendall(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n")


def handle_mysql(conn):
    conn.sendall(mysql_handshake())


def handle_postgres(conn):
    # 读 8 字节 SSLRequest，回 'S' 表示支持 SSL
    conn.recv(8)
    conn.sendall(b"S")


def handle_redis(conn):
    conn.recv(64)
    body = (
        b"# Server\r\n"
        b"redis_version:7.2.4\r\n"
        b"redis_mode:standalone\r\n"
        b"os:Linux 5.15.0 x86_64\r\n"
        b"tcp_port:6379\r\n"
        b"\r\n"
    )
    conn.sendall(b"$%d\r\n" % len(body) + body)


def handle_memcached(conn):
    conn.recv(64)
    conn.sendall(b"VERSION 1.6.17\r\n")


def handle_vnc(conn):
    conn.sendall(b"RFB 003.008\n")
    conn.recv(12)                # 客户端回送版本
    conn.sendall(bytes([2, 1, 2]))  # 安全类型数量 2 -> None, VNC-Auth


def handle_http(conn):
    """极简 HTTP 服务：带 CDN 特征头 + favicon，并用 robots/sitemap/JS/表单覆盖 M3 能力。"""
    data = b""
    while b"\r\n\r\n" not in data and len(data) < 8192:
        chunk = conn.recv(1024)
        if not chunk:
            break
        data += chunk
    path = b"/"
    parts = data.split(b" ")
    if len(parts) > 1:
        path = parts[1]

    ctype = "text/html; charset=utf-8"
    extra_headers = ""
    if path.startswith(b"/favicon.ico"):
        body, ctype = FAVICON, "image/x-icon"
    elif path.startswith(b"/robots.txt"):
        ctype = "text/plain"
        body = (b"User-agent: *\n"
                b"Disallow: /admin/\n"
                b"Disallow: /backup\n"
                b"Crawl-delay: 2\n"
                b"Sitemap: /sitemap.xml\n")
    elif path.startswith(b"/sitemap.xml"):
        ctype = "application/xml"
        body = (b'<?xml version="1.0" encoding="UTF-8"?>'
                b'<urlset><url><loc>/dup-a</loc></url><url><loc>/dup-b</loc></url>'
                b'<url><loc>/list?cat=1&amp;page=2</loc></url></urlset>')
    elif path.startswith(b"/app.js"):
        ctype = "application/javascript"
        body = (b'fetch("/api/js-users?page=1");\n'
                b'axios.post("/api/js-login", {});\n'
                b'const awsKey = "AKIAIOSFODNN7EXAMPLE";\n'
                b'const cfg = {password: "changeme"};\n')
    elif path.startswith(b"/dup-a") or path.startswith(b"/dup-b"):
        body = (b'<html><head><title>Template</title></head><body>'
                + b'<p>this is a long identical template body used for dedup detection</p>' * 20
                + b'</body></html>')
    elif path.startswith(b"/list"):
        body = b'<html><head><title>List</title></head><body>list page</body></html>'
    elif path.startswith(b"/admin/"):
        body = b'<html><head><title>Admin</title></head><body>admin area</body></html>'
    # ---- M4 靶点：常见暴露面（用于验证模板引擎，全部是只读 GET 可发现的）----
    elif path.startswith(b"/.git/config"):
        ctype = "text/plain"
        body = (b"[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n"
                b"[remote \"origin\"]\n\turl = https://git.example.com/app.git\n")
    elif path.startswith(b"/.env"):
        ctype = "text/plain"
        body = (b"APP_ENV=production\nDB_HOST=127.0.0.1\n"
                b"DB_PASSWORD=Sup3rSecretValue\nAPI_KEY=abcdef1234567890\n")
    elif path.startswith(b"/actuator/env"):
        ctype = "application/json"
        body = b'{"activeProfiles":[],"propertySources":[{"name":"systemProperties","properties":{}}]}'
    elif path.startswith(b"/nacos/v1/auth/users"):
        ctype = "application/json"
        body = b'{"totalCount":2,"pageNumber":1,"pageItems":[{"username":"nacos","password":"$2a$10$demo"}]}'
    elif path.startswith(b"/_cat/indices"):
        ctype = "text/plain"
        body = b"green open users  1 0 10 0 10kb 10kb\nyellow open logs  1 0  5 0  5kb  5kb\n"
    elif path.startswith(b"/version"):
        ctype = "application/json"
        body = (b'{"Platform":{"Name":"Docker Engine - Community"},"Version":"20.10.21",'
                b'"ApiVersion":"1.41","MinAPIVersion":"1.12","Os":"linux","Arch":"amd64"}')
    elif path.startswith(b"/phpinfo.php"):
        body = (b'<html><head><title>phpinfo()</title></head><body>'
                b'<h1>PHP Version 8.2.1</h1><p>Loaded Configuration File /etc/php.ini</p>'
                b'</body></html>')
    elif path.startswith(b"/metrics"):
        ctype = "text/plain"
        body = (b"# HELP go_gc_duration_seconds A summary of the GC invocation durations.\n"
                b"# TYPE go_gc_duration_seconds summary\n"
                b'go_gc_duration_seconds{quantile="0"} 1e-05\n')
    elif path.startswith(b"/swagger-ui.html"):
        body = (b'<html><head><title>Swagger UI</title></head><body>'
                b'<div id="swagger-ui"></div></body></html>')
    elif path.startswith(b"/api/json"):
        ctype = "application/json"
        body = b'{"_class":"hudson.model.Hudson","jobs":[]}'
    elif path.startswith(b"/cors/"):
        origin = b""
        for line in data.split(b"\r\n"):
            if line.lower().startswith(b"origin:"):
                origin = line.split(b":", 1)[1].strip()
        if origin:
            extra_headers = (f"Access-Control-Allow-Origin: {origin.decode(errors='ignore')}\r\n"
                             "Access-Control-Allow-Credentials: true\r\n")
        body = b"cors ok"
    elif path.startswith(b"/index.html") or path == b"/":
        # 注意：bytes 字面量只能是 ASCII，中文注释/文案要用普通字符串再 encode
        body = (b'<html><head><title>M4 Demo Site</title>'
                b'<link rel="icon" href="/favicon.ico"></head><body>'
                b'<p>A normal site: open services, paths listing, status UP wording.</p>'
                b'<form action="/login" method="post">'
                b'<input name="username"><input type="password" name="password"></form>'
                b'</body></html>')
    else:
        body = (b'<html><head><title>M3 Demo Site</title>'
                b'<link rel="icon" href="/favicon.ico">'
                b'<script>fetch("/api/inline-endpoint");</script>'
                b'<script src="/app.js"></script></head><body>'
                b'<form action="/login" method="post">'
                b'<input name="username"><input type="password" name="password"></form>'
                b'<a href="/list?cat=1&amp;page=2">list</a>'
                b'</body></html>')

    head = (
        "HTTP/1.1 200 OK\r\n"
        f"Content-Type: {ctype}\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Server: cloudflare\r\n"
        "CF-RAY: 7a1b2c3d4e5f-LAX\r\n"
        "Set-Cookie: __cfduid=demo; path=/\r\n"
        f"{extra_headers}"
        "Connection: close\r\n\r\n"
    )
    conn.sendall(head.encode() + body)


def handle_blackhole(conn):
    """接受连接但永不响应：用于模拟"慢目标"，让分布式演示能观察到租约重派。"""
    time.sleep(30)


# ---------------------------------------------------------------------------
# 金丝雀站点（18082）：规则库的"可执行契约"
#
# 为什么需要它：模板库最容易出现的失效模式不是"报错"，而是**写了却永远不命中**
# （路径写错、匹配器太严、正则用了引擎不支持的语法）。真跑一遍才发现得了。
# 这里把"每条模板命中时长什么样"固化成夹具文件（scripts/rules-fixtures/*.json），
# 靶站严格按夹具返回响应，于是三件事都能被自动验证：
#   1. 每个模板都能在自己的夹具上命中（不是死模板）；
#   2. 干净站点上误报为 0；
#   3. 夹具与模板一一对应（改路径忘了改夹具会被测试抓到）。
# ---------------------------------------------------------------------------

FIXTURE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules-fixtures")
CANARY_FIXTURES = {}


def load_fixtures(fixture_dir=None):
    """读取夹具：path -> fixture。path 为去掉查询串后的精确路径。

    路径重复一律**直接退出**而不是覆盖：金丝雀站点按精确路径分发，
    重复路径会让其中一条模板永远测不到 —— 这属于"静默失效"，
    宁可让演示当场失败，也不能让它悄悄少测一条模板。
    """
    fixture_dir = fixture_dir or FIXTURE_DIR
    table = {}
    origin = {}
    if not os.path.isdir(fixture_dir):
        print(f"[warn] 夹具目录不存在: {fixture_dir}", file=sys.stderr)
        return table
    for name in sorted(os.listdir(fixture_dir)):
        if not name.endswith(".json"):
            continue
        with open(os.path.join(fixture_dir, name), "r", encoding="utf-8-sig") as fh:
            items = json.load(fh)
        if not isinstance(items, list):
            print(f"[warn] 夹具文件 {name} 不是数组，已跳过", file=sys.stderr)
            continue
        for item in items:
            path = (item or {}).get("path")
            if not path:
                continue
            if path in table:
                raise SystemExit(
                    f"[fatal] 夹具路径重复: {path}"
                    f"（{name} 的 {item.get('template_id')} 与 {origin[path]} 的 {table[path].get('template_id')}）"
                    f" —— 金丝雀站点按精确路径分发，重复会让其中一条模板永远测不到。"
                    f"请用 also_serves 合并，或换一个路径。")
            table[path] = item
            origin[path] = name
    return table


def canary_response(fixture, origin=None):
    body = (fixture.get("body") or "").encode("utf-8")
    status = int(fixture.get("status", 200))
    reason = {200: "OK", 301: "Moved Permanently", 302: "Found", 400: "Bad Request",
              401: "Unauthorized", 403: "Forbidden", 500: "Internal Server Error"}.get(status, "OK")
    headers = [("Content-Type", fixture.get("content_type") or "text/html; charset=utf-8"),
               ("Content-Length", str(len(body))),
               ("Connection", "close")]
    for k, v in (fixture.get("headers") or {}).items():
        headers.append((str(k), str(v)))
    # 回显 Origin：真实的"CORS 配置错误"服务就是把请求里的 Origin 原样放回
    # Access-Control-Allow-Origin，并允许携带凭据。金丝雀站点照做，
    # 否则 CORS 类模板（用 wor-{{randstr}}.example.com 做回显验证）永远测不到。
    if origin:
        headers = [(k, v) for k, v in headers if k.lower() != "access-control-allow-origin"]
        headers.append(("Access-Control-Allow-Origin", origin))
    head = f"HTTP/1.1 {status} {reason}\r\n" + "".join(f"{k}: {v}\r\n" for k, v in headers) + "\r\n"
    return head.encode() + body


def request_headers(data):
    """从原始请求里取出 header（小写键）。"""
    out = {}
    head = data.split(b"\r\n\r\n", 1)[0]
    for line in head.split(b"\r\n")[1:]:
        if b":" in line:
            k, v = line.split(b":", 1)
            out[k.strip().decode("latin-1").lower()] = v.strip().decode("latin-1")
    return out


def handle_canary(conn):
    """金丝雀站点：严格按夹具返回；未声明的路径一律 404。"""
    data = b""
    while b"\r\n\r\n" not in data and len(data) < 8192:
        chunk = conn.recv(1024)
        if not chunk:
            break
        data += chunk
    parts = data.split(b" ")
    raw = parts[1].decode("latin-1") if len(parts) > 1 else "/"
    path = raw.split("?", 1)[0]
    fixture = CANARY_FIXTURES.get(path)
    if fixture is None:
        body = b"not found"
        conn.sendall(("HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n"
                      f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + body)
        return
    conn.sendall(canary_response(fixture, origin=request_headers(data).get("origin")))


HANDLERS = {
    "SSH": handle_ssh,
    "MySQL": handle_mysql,
    "PostgreSQL": handle_postgres,
    "Redis": handle_redis,
    "Memcached": handle_memcached,
    "VNC": handle_vnc,
    "HTTP": handle_http,
    "CANARY": handle_canary,
    "BLACKHOLE": handle_blackhole,
}


def build_dns_response(query):
    """极简 DNS 应答：回显 ID，设置 QR/RA，给问题名一个 NS 记录（用压缩指针）。"""
    if len(query) < 12:
        return None
    tid = query[0:2]
    qdcount = query[4:6]
    # 定位问题段结束：QNAME 以 0x00 结尾，后面是 QTYPE(2)+QCLASS(2)
    i = 12
    while i < len(query) and query[i] != 0:
        i += query[i] + 1
    if i + 5 > len(query):
        return None
    question = query[12 : i + 5]
    flags = b"\x81\x80"                      # QR=1 AA=1 RD=1 RA=1 RCODE=0
    header = tid + flags + qdcount + struct.pack(">H", 1) + b"\x00\x00" + b"\x00\x00"
    rdata = b"\x02ns\x05local\x00"
    answer = b"\xc0\x0c" + struct.pack(">HHIH", 2, 1, 300, len(rdata)) + rdata
    return header + question + answer


def serve_udp_dns(port, quiet):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((HOST, port))
    except OSError as exc:
        print(f"[skip] DNS 端口 {port} 绑定失败: {exc}", file=sys.stderr)
        sock.close()
        return
    if not quiet:
        print(f"[ok]   {'DNS(udp)':11s} 监听 {HOST}:{port}")
    while True:
        try:
            data, addr = sock.recvfrom(4096)
        except OSError:
            return
        resp = build_dns_response(data)
        if resp:
            sock.sendto(resp, addr)


def serve(port, name, handler, quiet):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind((HOST, port))
    except OSError as exc:
        print(f"[skip] {name} 端口 {port} 绑定失败: {exc}", file=sys.stderr)
        srv.close()
        return
    srv.listen(16)
    if not quiet:
        print(f"[ok]   {name:11s} 监听 {HOST}:{port}")

    while True:
        try:
            conn, _ = srv.accept()
        except OSError:
            return
        threading.Thread(target=run_handler, args=(conn, name, handler, quiet), daemon=True).start()


def run_handler(conn, name, handler, quiet):
    conn.settimeout(5)
    try:
        handler(conn)
    except Exception as exc:  # 探针可能提前断开，属正常
        if not quiet:
            print(f"[info] {name} 处理结束: {exc}")
    finally:
        try:
            conn.close()
        except OSError:
            pass


def main():
    parser = argparse.ArgumentParser(description="本地假服务集合（仅 127.0.0.1）")
    parser.add_argument("--quiet", action="store_true", help="减少输出")
    parser.add_argument("--fixtures", default=FIXTURE_DIR, help="金丝雀夹具目录（默认 scripts/rules-fixtures）")
    args = parser.parse_args()

    global CANARY_FIXTURES
    CANARY_FIXTURES = load_fixtures(args.fixtures)
    if not args.quiet:
        print(f"[ok]   {'CANARY':11s} 夹具 {len(CANARY_FIXTURES)} 条 -> {HOST}:18082")

    threads = []
    for port, name in SERVICES:
        t = threading.Thread(target=serve, args=(port, name, HANDLERS[name], args.quiet), daemon=True)
        t.start()
        threads.append(t)
    # UDP：DNS 应答器（用于验证 UDP 探测链路）
    udp = threading.Thread(target=serve_udp_dns, args=(53, args.quiet), daemon=True)
    udp.start()
    threads.append(udp)

    if not args.quiet:
        print("假服务已启动，Ctrl-C 退出。这些服务仅用于本机识别测试，不提供任何真实功能。")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("\n退出。")


if __name__ == "__main__":
    main()
