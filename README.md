<div align="center">

# MegaRAC Hunter

**A 24/7, keyless Discord bot that hunts internet-exposed AMI MegaRAC BMCs and confirms CVE-2024-54085.**

No API keys. No tokens. No login. Just working IPs.

[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![discord.py](https://img.shields.io/badge/discord.py-2.3%2B-5865F2.svg)](https://github.com/Rapptz/discord.py)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![No API Key](https://img.shields.io/badge/API%20keys-none-brightgreen.svg)](#-zero-keys)

</div>

---

## What it does

MegaRAC Hunter scrapes **40 anonymous sources**, filters every candidate through a hard
verification gate, and then attempts a real authentication bypass on each confirmed host.
Only hosts that are *actually exploitable* get announced — with credentials, in a clean embed.

It runs forever on its own. Point it at a channel and walk away.
