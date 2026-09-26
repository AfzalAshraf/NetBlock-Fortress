# 🛡️ NetBlock Fortress

**Network-wide ad blocker & threat intelligence DNS server in a single Python file.**

Replaces Pi-hole with Brave-Shield style analytics, 50 blocklists across 10 categories,
YouTube ad stripping, AI-powered domain classification, and a dark-themed web dashboard.

![Version](https://img.shields.io/badge/version-18.0-brightgreen)
![Python](https://img.shields.io/badge/python-3.8+-blue)
![License](https://img.shields.io/badge/license-MIT-yellow)

---

## ✨ Features

| Feature | Description |
|---|---|
| 🎯 **50 Blocklists** | Ads, Trackers, Malware, Phishing, Spam, Social, Adult, Gambling, Crypto, Security |
| 🎬 **YouTube Ad Blocking** | 250+ hardcoded YT ad domains + Oiyay blocklist + googlevideo pattern matching |
| 🤖 **AI Classification** | OpenRouter free-tier AI classifies unknown domains in real-time |
| 🔄 **CNAME Uncloaking** | Resolves canonical aliases to catch cloaked trackers |
| 🛡️ **DNS Rebinding Protection** | Blocks public domains resolving to private IPs |
| 🧠 **DGA Detection** | Entropy analysis blocks algorithm-generated malware domains |
| ⚡ **Rate Limiting** | Configurable per-client queries/second with abuse logging |
| 🚫 **Amplification Defense** | Refuses DNS ANY queries used in DDoS attacks |
| 📊 **Threat Dashboard** | Brave-Shield style stats: bandwidth saved, time saved, threat breakdown |
| 🌐 **Multi-Page UI** | Dark theme, real href navigation, no JS SPA freezing |
| 🔐 **Login Auth** | SHA-256 password hashing, customizable username |
| 📦 **Single File** | Everything in one `app.py` — no complex dependencies |

---

## 🚀 Quick Install (Linux VPS / Local PC)

### One-Command Install

```bash
curl -fsSL https://raw.githubusercontent.com/YOUR_USERNAME/netblock-fortress/main/install.sh | sudo bash
