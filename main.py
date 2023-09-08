import socket, json, sqlite3, time, threading, subprocess, os, signal

handshake_payload = bytes([
    0x3c,       # length
    0x00,       # packet id
    0x00,       # protocol version
    0x36,       # server name
    ]) + b"NOT A MALWARE!!! https://github.com/jakiki6/serverscan" + bytes([
    0x63, 0xdd, # port
    0x01        # next state
])

status_payload = bytes([
    0x01,       # length
    0x00        # packet id
])

ping_payload = handshake_payload + status_payload

cmd = "masscan -p 25565 --rate 1000 --exclude-file exclude.conf 0.0.0.0/0 --resume paused.conf".split(" ")

def ping(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    sock.connect((host, port))

    sock.send(ping_payload)
    time.sleep(0.1)

    response = sock.recv(2097152)

    for i in range(0, 3):
        while response[0] & 0x80:
            response = response[1:]

        response = response[1:]

    return response.decode()

con = sqlite3.connect("servers.db")
cur = con.cursor()

try:
    cur.execute("CREATE TABLE servers(ip, port, status, version, online, forge)")
except:
    pass


def check(ip, port):
    data = ping(ip, port)

    forge = 0
    if data[0] != "{" or "FML" in data or "modpack" in data or "forge" in data:
        forge = 1

    jdata = json.loads(data)
    cur.execute(f"INSERT INTO servers VALUES (\"{ip}\", 25565, {repr(data)}, {jdata['version']['protocol']}, {jdata['players']['online']}, {forge})")
    con.commit()

    print(f"Hit at {ip}: {data}")

p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

try:
    while p.poll() is None:
        line = p.stdout.readline().decode()
        if line.startswith("#"):
            continue

        line = line.split(" ")

        try:
            host = line[5]
            port = int(line[3].split("/")[0])

            check(host, port)
        except Exception as e:
            pass
except KeyboardInterrupt:
    pass
finally:
    print("saving progress ...")
    os.kill(p.pid, signal.SIGINT)
    p.wait()
