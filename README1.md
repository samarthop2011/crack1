---

## ✨ Features

- **Zero keys** — every source is anonymous. Nothing to sign up for.
- **40 sources** — search engines, CT logs, passive DNS, archives, and open datasets.
- **Verified only** — nothing is reported unless the TLS cert says `megarac.com` or the host serves the MegaRAC fingerprint.
- **Real exploitation** — CVE-2024-54085 is confirmed by *creating an admin account and logging in*, not by guessing.
- **Runs 24/7** — self-starting engine, auto-reconnect, persistent state across restarts.
- **Scans hard** — 1000 concurrent TLS checks, 300 concurrent CVE probes, `/24` neighbour sweep around every hit.
- **Aesthetic alerts** — colour-coded embeds, thumbnails, timestamps, live status bar, `@here` ping on new hits.
- **No false positives** — dedup cache means each host is verified once and each vuln announced once.

---

## 🔒 Zero keys

The bot never asks for a Shodan, Censys, FOFA or ZoomEye key. Where an engine's API needs a
key, the bot scrapes its **public web UI** instead. The only credential you need is your
Discord bot token.

---

## 🧠 How it works

```mermaid
flowchart LR
    A["40 discovery sources<br/>(keyless)"] --> B["candidate pool"]
    B --> C{"verify<br/>cert CN = megarac.com<br/>OR lighttpd + MegaRAC body"}
    C -->|reject| D["discard"]
    C -->|confirm| E["/24 neighbour sweep"]
    E --> F{"CVE-2024-54085<br/>create admin + login 201"}
    F -->|exploitable| G["announce to Discord"]
    F -->|not| H["cache as live MegaRAC"]
