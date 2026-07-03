"""
NBASecurity DNS Server
- DNS-over-TLS (DoT) Port 853  ← Phone Private DNS
- Plain UDP DNS   Port 53
- Ad/Tracker blocking (150k+ domains)
- Web Dashboard   Port 8080
"""
import socket, ssl, struct, threading, logging, time, json, urllib.request
from datetime import datetime
from collections import defaultdict, deque
DOMAIN                 = "nbasecurity.duckdns.org"   
LISTEN_HOST            = "0.0.0.0"
DOT_PORT               = 853
UDP_PORT               = 53
DASHBOARD_PORT         = 8080
UPSTREAM_DNS           = ("1.1.1.1", 53)
CERT_FILE              = f"/etc/letsencrypt/live/{DOMAIN}/fullchain.pem"
KEY_FILE               = f"/etc/letsencrypt/live/{DOMAIN}/privkey.pem"
BLOCKLIST_UPDATE_HOURS = 24
LOG_MAX                = 1000
BLOCKLIST_URLS = ["https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts","https://adaway.org/hosts.txt",
]
shared = {"stats": {
  "total":0,"blocked":0,"allowed":0,"cached":0,"start_time": datetime.now().isoformat()},"log": deque(maxlen=LOG_MAX),"top_blocked": defaultdict(int),"blocklist_size": 0,"cache_size": 0,
}
lock = threading.Lock()
logging.basicConfig(level=logging.INFO,format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")
log = logging.getLogger("NBASecurity")
class Cache:
    def __init__(self):
        self._d = {}
        self._l = threading.Lock()
    def get(self, k):
        with self._l:
            e = self._d.get(k)
            if e and time.time() < e[1]: return e[0]
            if e: del self._d[k]
        return None
    def set(self, k, v, ttl=300):
        with self._l:
            if len(self._d) > 10000:
                old = min(self.d, key=lambda x: self._d[x][1])
                del self.d[old]
            self.d[k] = (v, time.time() + ttl)
    def size(self):
      with self.l: return len(self.d)
    def clear(self):with self.l: self.d.clear()
class Blocklist:
DEFAULT = {"doubleclick.net","googleadservices.com","googlesyndication.com","adservice.google.com","pagead2.googlesyndication.com","ads.google.com","googleads.g.doubleclick.net","connect.facebook.net","ads.facebook.com","an.facebook.com","amazon-adsystem.com","aax.amazon-adsystem.com","scorecardresearch.com","quantserve.com","moatads.com","adsrvr.org","adnxs.com","outbrain.com","taboola.com","revcontent.com","criteo.com","criteo.net","pubmatic.com","rubiconproject.com","openx.net","appnexus.com","advertising.com","casalemedia.com","bidswitch.net","smaato.net","inmobi.com","bat.bing.com","hotjar.com","mouseflow.com","fullstory.com","segment.io","mixpanel.com",}
def init(self):self.domains = set(self.DEFAULT)
self.l = threading.Lock()
def update(self):
   log.info("🔄 Updating blocklist..")
    new = set(self.DEFAULT)
      for url in BLOCKLIST_URLS:
       count = 0
          try:req = urllib.request.Request(url, headers={"User-Agent":"NBASecurity/1.0"})
            with urllib.request.urlopen(req, timeout=20) as r:
              for raw in r:
                 line = raw.decode("utf-8", errors="ignore").strip()
                  if not line or line.startswith("#"): continue
                     parts = line.split()
                      if len(parts)>=2 and parts[0] in ("0.0.0.0","127.0.0.1"):
                        d = parts[1].lower().rstrip(".")
                          if d and "." in d and d != "localhost":
                            new.add(d); count += 1
       log.info(f"+{count:,} ← {url.split('/')[-1]}")
        except Exception as e:
        log.warning(f"⚠️ {e}")
        with self._l: self.domains = new
        with lock: shared["blocklist_size"] = len(new)
        log.info(f"✅ Blocklist updated successfully: {len(new):,} domain")
    def is blocked(self, domain):
        d = domain.lower().rstrip(".")
        with self.l:
            if d in self.domains: return True
            parts = d.split(".")
            for i in range(1, len(parts)):
                if ".".join(parts[i:]) in self.domains: return True
        return False
    def auto update(self):
        self.update()
        while True:
            time.sleep(BLOCKLIST UPDATE HOURS * 3600)
            self.update()
class CustomRules:
    FILE = "custom rules.json"
    def init (self):
        self.blocked = set()
        self.allowed = set()
        self._l = threading.Lock()
        self._load()
    def load(self):
        try:
            with open(self.FILE) as f:
                d = json.load(f)
                self.blocked = set(d.get("blocked",[]))
                self.allowed = set(d.get("allowed",[]))
        except FileNotFoundError:
            self.save()
def _save(self):
        with open(self.FILE,"w") as f:
            json.dump({"blocked":list(self.blocked),"allowed":list(self.allowed)},f,indent=2)
    def add_block(self, d):
        with self._l: self.blocked.add(d.lower())
        self._save()
    def add_allow(self, d):
        with self._l: self.allowed.add(d.lower())
        self._save()
    def remove(self, d):
        d = d.lower()
        with self._l: self.blocked.discard(d); self.allowed.discard(d)
        self._save()
    def is_whitelisted(self, d):
        with self._l: return d.lower() in self.allowed
    def is_blocked(self, d):
        with self._l: return d.lower() in self.blocked
def parse_query(data):
    txid = struct.unpack("!H", data[:2])[0]
    offset, labels = 12, []
    while offset < len(data):
        l = data[offset]
        if l == 0: offset += 1; break
        labels.append(data[offset+1:offset+1+l].decode("ascii", errors="ignore"))
        offset += 1 + l
    domain = ".".join(labels)
    qtype = struct.unpack("!H", data[offset:offset+2])[0] if offset+2 <= len(data) else 1
    return txid, domain, qtype
def nxdomain(data, txid):
    return struct.pack("!HHHHHH", txid, 0x8183, 1, 0, 0, 0) + data[12:]
def forward(data):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(5)
            s.sendto(data, UPSTREAM_DNS)
            resp, _ = s.recvfrom(4096)
            return resp
    except Exception:
        return None
def log_query(domain, action, client):
    with lock:
        s = shared["stats"]
        s["total"] += 1
        if action in ("blocked","allowed","cached"): s[action] += 1
        shared["log"].appendleft({
            "time": datetime.now().strftime("%H:%M:%S"),
            "domain": domain, "action": action, "client": client
        })
      if action == "blocked": shared["top_blocked"][domain] += 1
        shared["cache_size"] = cache.size()
def handle(data, client_ip, send_fn):
    try:
        txid, domain, qtype = parse_query(data)
        key = f"{domain.lower()}:{qtype}"
        if rules.is_whitelisted(domain):
            pass
        elif rules.is_blocked(domain) or blocklist.is_blocked(domain):
            send_fn(nxdomain(data, txid))
            log_query(domain, "blocked", client_ip)
            log.info(f"🚫 {domain:<50} ← {client_ip}")
            return
        cached = cache.get(key)
        if cached:
            send_fn(struct.pack("!H", txid) + cached[2:])
            log_query(domain, "cached", client_ip)
            return
        resp = forward(data)
if resp:
send_fn(resp); cache.set(key, resp)
log_query(domain, "allowed", client_ip)
else:
log_query(domain, "error", client_ip)
except Exception as e:
log.error(f"Handle error: {e}")
def dot_server():
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
try:
ctx.load_cert_chain(CERT_FILE, KEY_FILE)
except FileNotFoundError:
log.warning("⚠️ No SSL cert — DoT disabled. Run setup.sh.")
return
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as raw:
raw.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
raw.bind((LISTEN_HOST, DOT_PORT))
raw.listen(100)
log.info(f"🔒 DNS-over-TLS run — Port {DOT_PORT}")
with ctx.wrap_socket(raw, server_side=True) as tls:
while True:
try:
conn, addr = tls.accept()
threading.Thread(target=_dot_conn, args=(conn, addr[0]), daemon=True).start()
except Exception as e:log.error(f"DoT error: {e}")
def recvexact(conn, n):
buf = b""
while len(buf) < n:
try:
chunk = conn.recv(n - len(buf))
if not chunk: return None
buf += chunk
except Exception: return None
return buf
defdotconn(conn, client_ip):
try:
with conn:conn.settimeout(10)
while True: lb = recvexact(conn, 2)
if not lb: break
length = struct.unpack("!H", lb)[0]
data = recvexact(conn, length)
if not data: break
handle(data, client_ip,lambda r: conn.sendall(struct.pack("!H", len(r)) + r))
except Exception:pass
def udp_server():
try:
with socket.socket(socket.AFINET, socket.SOCKDGRAM) as s:
s.setsockopt(socket.SOLSOCKET, socket.SOREUSEADDR, 1)
s.bind((LISTENHOST, UDPPORT))
log.info(f"📡 Plain DNS RUN Port {UDPPORT}")
while True:data, addr = s.recvfrom(512)
threading.Thread(target=handle,args=(data,addr[0],lambda r,a=addr,sock=s:sock.sendto(r,a)),daemon=True).
start()
except PermissionError:log.error("❌ Sudo required for Port 53")
except Exception as e:log.error(f"UDP error: {e}")
cache = Cache()
blocklist = Blocklist()
rules = CustomRules()
def start():
    threading.Thread(target=blocklist.auto_update, daemon=True).start()
    threading.Thread(target=dotserver, daemon=True).start()
    threading.Thread(target=udpserver, daemon=True).start()
    log.info(f"🚀 NBASecurity DNS RUN! Domain: {DOMAIN}")
if name== "main":
    start()
    while True: time.sleep(60)

