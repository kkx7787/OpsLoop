import socket, struct, time, json, os, sys
def tcp(host, port, t=4):
    s0 = time.time()
    try:
        socket.create_connection((host, port), timeout=t).close(); r = "연결됨"
    except socket.timeout: r = "시간 초과"
    except OSError as e: r = f"거부·오류({e.errno})"
    return r, round(time.time() - s0, 1)
def dns(server, name="example.com", t=4):
    q = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0" + struct.pack(">HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(t)
    try:
        s.sendto(q, (server, 53)); d, _ = s.recvfrom(512); return f"응답 {len(d)}바이트"
    except socket.timeout: return "시간 초과"
    except OSError as e: return f"오류({e.errno})"
def resolve(name):
    try: return socket.gethostbyname(name)
    except OSError as e: return f"이름 해석 실패({e})"
targets = json.loads(sys.argv[1])
out = {"host": socket.gethostname(), "at": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
for label, kind, a, b in targets:
    if kind == "tcp": out[label] = tcp(a, b)
    elif kind == "dns": out[label] = dns(a)
    elif kind == "resolve": out[label] = resolve(a)
print(json.dumps(out, ensure_ascii=False))
