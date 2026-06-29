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
                old = min(self._d, key=lambda x: self._d[x][1])
                del self._d[old]
            self._d[k] = (v, time.time() + ttl)
    def size(self):
        with self._l: return len(self._d)
    def clear(self):
        with self._l: self._d.clear()
class Blocklist:
    DEFAULT = {"doubleclick.net","googleadservices.com","googlesyndication.com","adservice.google.com","pagead2.googlesyndication.com","ads.google.com","googleads.g.doubleclick.net","connect.facebook.net","ads.facebook.com","an.facebook.com","amazon-adsystem.com","aax.amazon-adsystem.com","scorecardresearch.com","quantserve.com","moatads.com","adsrvr.org","adnxs.com","outbrain.com","taboola.com","revcontent.com","criteo.com","criteo.net","pubmatic.com","rubiconproject.com","openx.net","appnexus.com","advertising.com","casalemedia.com","bidswitch.net","smaato.net","inmobi.com","bat.bing.com","hotjar.com","mouseflow.com","fullstory.com","segment.io","mixpanel.com",}
