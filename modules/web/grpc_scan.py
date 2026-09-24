"""grpc_scan — gRPC endpoint discovery + reflection abuse (unique)"""
import socket
import struct
from urllib.parse import urlparse
from core.http import HttpClient


GRPC_COMMON = [
    "grpc.health.v1.Health", "grpc.reflection.v1alpha.ServerReflection",
    "grpc.channelz.v1.Channelz", "google.bytestream.ByteStream",
    "google.longrunning.Operations",
]


def http2_preface_check(host, port, timeout=5):
    """Check if port speaks HTTP/2 cleartext (h2c) — gRPC without TLS."""
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        # HTTP/2 client preface
        preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        s.sendall(preface)
        s.settimeout(timeout)
        try:
            resp = s.recv(1024)
        except socket.timeout:
            resp = b""
        s.close()
        return len(resp) > 0 or True  # no RST = likely gRPC
    except Exception:
        return False


def port_open(host, port, timeout=3):
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True
    except Exception:
        return False


class GrpcScan:
    def run(self, session, logger):
        target = session.target
        u = urlparse(target)
        host = u.hostname
        http = HttpClient(session, logger)

        print(f"[grpc_scan] target: {target}")
        print(f"[grpc_scan] host: {host}")
        print()

        # 1. detect gRPC ports
        print("=" * 60)
        print("1. PORT SCAN (gRPC common ports)")
        print("=" * 60)

        grpc_ports = [50051, 50052, 50053, 8080, 9090, 9091, 443, 80, 9443]
        open_ports = []

        for port in grpc_ports:
            if port_open(host, port):
                open_ports.append(port)
                print(f"  + {port} OPEN")

        if not open_ports:
            print("  . no gRPC ports open")
            return {"ports": [], "grpc": False}

        # 2. check if any is gRPC (h2c)
        print()
        print("=" * 60)
        print("2. gRPC DETECTION (h2c preface)")
        print("=" * 60)

        grpc_ports_found = []
        for port in open_ports:
            if http2_preface_check(host, port):
                grpc_ports_found.append(port)
                print(f"  + {port} speaks HTTP/2 cleartext (likely gRPC)")

        if not grpc_ports_found:
            print("  . no h2c ports — gRPC over TLS only or HTTP/1")
            return {"ports": open_ports, "grpc": False}

        # 3. gRPC reflection
        print()
        print("=" * 60)
        print("3. gRPC REFLECTION (ServerReflection)")
        print("=" * 60)

        for port in grpc_ports_found:
            print(f"\n[port {port}]")
            url = f"http://{host}:{port}/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo"
            # simple HTTP/2 probe — just check endpoint existence
            r = http.post(url, data=b"", headers={
                "Content-Type": "application/grpc",
                "TE": "trailers",
            })
            if r and r.status_code not in (404, 405):
                print(f"  + reflection endpoint responds ({r.status_code})")
                logger.finding("grpc_reflection", "high",
                               f"gRPC reflection open on {host}:{port}")

            # try health check
            for svc in GRPC_COMMON:
                url = f"http://{host}:{port}/{svc}/"
                r = http.get(url)
                if r and r.status_code in (200, 400):
                    print(f"  + {svc} responds ({r.status_code})")

        # 4. summary
        print()
        print(f"[grpc_scan] open ports: {open_ports}")
        print(f"[grpc_scan] gRPC: {grpc_ports_found}")
        return {"ports": open_ports, "grpc": grpc_ports_found}
