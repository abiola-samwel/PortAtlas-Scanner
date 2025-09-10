import socket
import asyncio
import struct
import time
from contextlib import closing

# ==========================
# Constants
# ==========================
CONNECT_TIMEOUT = 3
READ_TIMEOUT = 3
BANNER_SIZE = 1024

# ==========================
# Known Protocol Probes
# ==========================

async def probe_http(sock):
    try:
        sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        data = sock.recv(BANNER_SIZE).decode(errors="ignore")
        if "Server:" in data:
            return data.split("Server:")[1].split("\r\n")[0].strip()
        return data.strip() or "HTTP"
    except Exception:
        return "HTTP"

async def probe_redis(sock):
    try:
        sock.sendall(b"PING\r\n")
        data = sock.recv(BANNER_SIZE).decode(errors="ignore")
        if "+PONG" in data:
            return "Redis (PONG)"
        return "Redis"
    except Exception:
        return "Redis"

async def probe_postgres(sock):
    try:
        # PostgreSQL SSLRequest packet
        packet = struct.pack("!IIB", 8, 1234, 5678)[:-1] + b"\x04\xd2"
        sock.sendall(packet)
        data = sock.recv(1)
        if data in (b"S", b"N"):
            return "PostgreSQL"
        return "PostgreSQL"
    except Exception:
        return "PostgreSQL"

async def probe_mysql(sock):
    try:
        data = sock.recv(BANNER_SIZE).decode(errors="ignore")
        if "mysql" in data.lower():
            return "MySQL"
        return data.strip() or "MySQL"
    except Exception:
        return "MySQL"

async def probe_mongo(sock):
    try:
        # MongoDB is binary protocol, so handshake parsing is complex
        # Here we just check if connection is accepted and not immediately closed
        sock.sendall(b"\x3a\x00\x00\x00" + b"\x00" * 54)
        data = sock.recv(BANNER_SIZE)
        if data:
            return "MongoDB"
        return "MongoDB"
    except Exception:
        return "MongoDB"

async def probe_snmp_udp(ip, port):
    try:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as sock:
            sock.settimeout(READ_TIMEOUT)
            # Minimal SNMPv1 GET request for sysDescr
            packet = bytes.fromhex(
                "302602010004067075626c6963a01902044a5b0f59020100020100300b300906052b06010201010100"
            )
            sock.sendto(packet, (ip, port))
            data, _ = sock.recvfrom(BANNER_SIZE)
            if data:
                return "SNMP"
        return None
    except Exception:
        return None

# ==========================
# Service Detection Dispatcher
# ==========================

async def detect_service(ip, port, sock, proto="tcp"):
    if proto == "udp" and port == 161:
        return await probe_snmp_udp(ip, port)

    if proto == "tcp":
        if port in (80, 8080, 8000, 443):
            return await probe_http(sock)
        elif port == 6379:
            return await probe_redis(sock)
        elif port == 5432:
            return await probe_postgres(sock)
        elif port == 3306:
            return await probe_mysql(sock)
        elif port == 27017:
            return await probe_mongo(sock)

    # Fallback: generic banner grab
    try:
        sock.settimeout(READ_TIMEOUT)
        data = sock.recv(BANNER_SIZE).decode(errors="ignore").strip()
        return data if data else "unknown"
    except Exception:
        return "unknown"

# ==========================
# Main Port Scan Logic
# ==========================

async def tcp_connect_scan(ip, port, banner_grab=False):
    result = {"port": port, "status": "closed", "service": "unknown"}
    try:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
            sock.settimeout(CONNECT_TIMEOUT)
            sock.connect((ip, port))
            result["status"] = "open"
            if banner_grab:
                service = await detect_service(ip, port, sock, proto="tcp")
                result["service"] = service
    except (socket.timeout, ConnectionRefusedError):
        result["status"] = "closed"
    except Exception:
        result["status"] = "filtered"
    return result

async def udp_scan(ip, port, banner_grab=False):
    result = {"port": port, "status": "closed", "service": "unknown"}
    try:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as sock:
            sock.settimeout(CONNECT_TIMEOUT)
            sock.sendto(b"\x00", (ip, port))
            data, _ = sock.recvfrom(BANNER_SIZE)
            result["status"] = "open"
            if banner_grab:
                if port == 161:  # SNMP
                    service = await probe_snmp_udp(ip, port)
                    result["service"] = service or "SNMP"
                else:
                    result["service"] = data.decode(errors="ignore") or "unknown"
    except socket.timeout:
        result["status"] = "filtered"
    except Exception:
        result["status"] = "error"
    return result

# ==========================
# Entry Point
# ==========================

def run_port_scan(target, ports, scan_type="tcp_connect", banner_grab=False, all_ports=False):
    ip = socket.gethostbyname(target)
    results = []
    start = time.time()

    async def runner():
        tasks = []
        for port in ports:
            if scan_type == "udp":
                tasks.append(udp_scan(ip, port, banner_grab))
            else:
                tasks.append(tcp_connect_scan(ip, port, banner_grab))
        return await asyncio.gather(*tasks)

    results = asyncio.run(runner())
    end = time.time()

    open_count = sum(1 for r in results if r["status"] == "open")
    closed_count = sum(1 for r in results if r["status"] == "closed")
    filtered_count = sum(1 for r in results if r["status"] == "filtered")

    return {
        "target": target,
        "resolved_ip": ip,
        "scan_type": scan_type,
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(start)),
        "finished_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(end)),
        "duration_ms": int((end - start) * 1000),
        "total_scanned": len(ports),
        "open_count": open_count,
        "closed_count": closed_count,
        "filtered_count": filtered_count,
        "results": results,
    }
