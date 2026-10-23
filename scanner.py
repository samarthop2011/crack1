"""scanner.py - continuous, keyless, aggressive. Only reports verified hosts."""
from __future__ import annotations
import asyncio, ipaddress, time
import aiohttp
from sources import discover
from verify import is_megarac
from mcve import check_ip as cve_check
import config

UA = {"User-Agent": "Mozilla/5.0 (compatible; MegaRAC-Hunter)"}

def _conn():
    return aiohttp.TCPConnector(limit=0, ttl_dns_cache=300, ssl=False)

async def _geo(session, ip):
    try:
        async with session.get(f"http://ip-api.com/json/{ip}", timeout=5) as r:
            d = await r.json()
        if d.get("status") == "success":
            return f"{d.get('country','?')} · {d.get('city','?')} · {d.get('isp','?')}"
    except Exception:
        pass
    return "Unknown"

class Scanner:
    def __init__(self, seen, vulns, emit):
        self.seen, self.vulns, self.emit = seen, vulns, emit
        self.running = False
        self.cycle = 0
        self.stats = {"cycles": 0, "candidates": 0, "confirmed": 0, "vulns": len(vulns),
                      "started": time.time(), "last": None, "phase": "idle"}
        self._session = None

    async def start(self):
        self.running = True
        self._session = aiohttp.ClientSession(connector=_conn(), headers=UA,
                                              timeout=aiohttp.ClientTimeout(total=25))
        try:
            while self.running:
                try:
                    await self._cycle()
                except Exception as e:
                    await self.emit("log", f"cycle error: {e}")
                self.stats["cycles"] += 1
                self.stats["phase"] = "sleeping"
                await asyncio.sleep(config.CYCLE_SLEEP)
        finally:
            await self._session.close()

    async def _cycle(self):
        self.cycle += 1
        self.stats["phase"] = "discovering"
        cand = await asyncio.to_thread(discover, config.DISCOVERY_WORKERS)
        todo = [ip for ip in cand if ip not in self.seen]
        self.seen.update(cand.keys())
        self.stats["candidates"] += len(todo)
        self.stats["last"] = time.time()

        self.stats["phase"] = f"verifying {len(todo)}"
        confirmed = await self._verify_batch(todo)

        if config.EXPAND and confirmed:
            self.stats["phase"] = "expanding /24"
            extra = set()
            for ip in confirmed:
                net = ipaddress.ip_network(f"{ip}/24", strict=False)
                extra.update(str(h) for h in net.hosts())
            extra -= set(confirmed)
            extra -= self.seen
            self.seen.update(extra)
            confirmed += await self._verify_batch(list(extra))

        confirmed = list(dict.fromkeys(confirmed))
        self.stats["confirmed"] += len(confirmed)

        if config.ANNOUNCE_CONFIRMED:
            for ip in confirmed:
                await self.emit("confirmed", ip)

        self.stats["phase"] = f"cve {len(confirmed)}"
        await self._cve_batch(confirmed)

        if config.RECHECK_EVERY and self.cycle % config.RECHECK_EVERY == 0 and self.vulns:
            self.stats["phase"] = "rechecking vulns"
            await self._cve_batch(list(self.vulns), recheck=True)

    async def _verify_batch(self, ips):
        if not ips:
            return []
        sem = asyncio.Semaphore(config.VERIFY_CONCURRENCY)
        out = []
        async def one(ip):
            async with sem:
                ok, _ = await is_megarac(self._session, ip, config.HTTP_TIMEOUT)
            if ok:
                out.append(ip)
        await asyncio.gather(*(one(ip) for ip in ips))
        return out

    async def _cve_batch(self, ips, recheck=False):
        if not ips:
            return
        sem = asyncio.Semaphore(config.CVE_CONCURRENCY)
        async def one(ip):
            async with sem:
                r = await cve_check(self._session, ip, timeout=config.TLS_TIMEOUT)
            if r.get("vulnerable"):
                new = ip not in self.vulns
                self.vulns.add(ip)
                self.stats["vulns"] = len(self.vulns)
                r["new"] = new
                r["geo"] = await _geo(self._session, ip)
                await self.emit("vuln", r)
        await asyncio.gather(*(one(ip) for ip in ips))

    def stop(self):
        self.running = False
