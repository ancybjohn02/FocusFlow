<div align="center">

# FocusFlow

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=20&pause=1000&color=2ECC71&center=true&vCenter=true&width=600&lines=It's+not+where+you+are+online...;it's+what+you're+actually+looking+at.;Content+over+platform.+Always." alt="Typing SVG" />

[![Platform](https://img.shields.io/badge/platform-Windows-0078D6?logo=windows&logoColor=white)](#platform)
[![Status](https://img.shields.io/badge/status-v1%20live-2ECC71)](#where-v1-stands)
[![Architecture](https://img.shields.io/badge/architecture-agent%20%2B%20extension-4285F4?logo=googlechrome&logoColor=white)](#the-system)
[![Storage](https://img.shields.io/badge/storage-local--first-orange)](#what-makes-this-different-from-just-call-gpt-on-every-url)
[![Made by](https://img.shields.io/badge/made%20by-Ancy%20B.%20John-8A2BE2)](https://github.com/ancybjohn02)

</div>

---

## Why this exists

Every "focus tracker" I've come across runs on the same lazy shortcut: it looks at the *domain*, not the *content*. YouTube gets stamped "entertainment." Twitter gets stamped "distraction." Wikipedia gets a free pass. Medium is either "research" or "not," depending on the tool's mood.

That's broken. A 3Blue1Brown video on backpropagation and a gaming highlight reel are both "YouTube," but they are not the same activity, and no tool that treats them the same is telling you anything true about your own focus. And it gets worse the moment you stop looking only at browsers — reading documentation in VS Code, or having a synth loop open in Spotify while you code, are both part of a real focus session too, and no browser-only tool can see either one.

I kept running into this personally — trying to study deep learning, drifting into a Wikipedia rabbit hole on quantum computing, and every tracker I tried either didn't notice or flagged Wikipedia itself as the problem, when the actual problem was *that specific tangent, at that specific moment*. So I started building the tool I actually wanted: something that reads what's actually on screen — in a browser tab or any other app — checks it against what I said I'm trying to do, and only then decides whether I've drifted.

> The rule underneath the whole project: **content over platform.** Not *where* it's from — *what* it is.

## What it does

- **Takes your goal in plain language** — "studying deep learning," not a dropdown category.
- **Reads the content, not the window title** — for browser tabs: title, description, tags, extracted text, video metadata. For everything else: which app, which window — and scores it against that goal.
- **Grades relevance on a gradient**, not a pass/fail:
  - 🟢 Direct — squarely on-topic
  - 🟡 Peripheral — adjacent groundwork (linear algebra while you're studying deep learning, say)
  - 🟠 Indirect — a tangent worth a nudge
  - 🔴 Distraction — off-topic
- **Cares about continuity, not just content** — a 90-second scroll through Twitter and a 20-minute derail are not the same failure, and the system is built to know the difference.
- **Learns *your* definition of relevant.** "Research" means something different to you than to the next person. Every time it asks "this looks off-topic, still want to continue?" and you answer, that's a data point that makes it fit you better next week than it did today.
- **Doesn't stop tracking the second you close a browser tab** — a session that moves from reading docs, into an editor, into a video, and back is still one continuous session, not three disconnected ones.
- **Turns all of that into something you'd actually look at** — a live session view instead of a spreadsheet nobody opens.

## The system

Two components, split along a real constraint rather than a convenience: **a browser extension physically cannot see outside the browser.** There's no permission that reveals "the user just alt-tabbed into VS Code" or "Spotify is now the foreground app" — that's OS-level information, sandboxed away from web extensions by design. So the system is built as two halves that each do the one thing they're actually capable of:

**A native background agent** — lives outside the browser entirely, polls the OS for the current foreground window (which app, which window title), and keeps running independent of whether any browser is open at all. This is what lets a session that's entirely inside VS Code, or Spotify, or Notepad still get tracked.

**The browser extension** — stays exactly where it's useful: the only thing that can see *inside* a tab. The native agent can tell you "Chrome is focused." Only the extension can tell you *and it's a 3Blue1Brown video on backpropagation, not a gaming livestream.*

**How they talk to each other.** The agent runs a tiny **localhost-only server**, not a native-messaging pipe — deliberately, because native messaging ties the agent's lifecycle to the browser being open (the browser spawns and kills it), which would mean closing every browser tab kills OS-level tracking too. A standalone local server keeps the agent's uptime decoupled from the browser's — it starts at login, runs continuously, and the extension is just one of several clients that can talk to it over `127.0.0.1` whenever a browser happens to be open.

```
      ┌─────────────────────────────────────────────┐
      │      NATIVE AGENT  (always running)         │
      │  polls OS for foreground window/app         │
      │  → SQLite, written incrementally            │
      │  → exposes a localhost-only local server    │
      └───────────────────────┬─────────────────────┘
                               │  127.0.0.1
        ┌──────────────────────┼──────────────────────┐
        ▼                      ▼                       ▼
┌───────────────┐     ┌──────────────────┐      ┌────────────────┐
│ Tray icon /   │     │ Browser          │      │ CLI (debug/    │
│ control UI    │     │ extension        │      │  optional)     │
│ start/stop,   │     │ pushes tab       │      │                │
│ view status   │     │ metadata when    │      │                │
│               │     │ a browser is open│      │                │
└───────────────┘     └──────────────────┘      └────────────────┘
```

**Why a local server instead of nothing at all:** the agent has no UI of its own (it's a silent background process), so the only way anything — the tray icon, the extension, a future dashboard — can start a session, stop one, or hand it richer tab context is by talking to it over that local API. Independence, no-UI, and the local server aren't three separate design choices; they're one decision with three consequences.

**On multiple browsers.** The native agent can already tell *which* browser is in the foreground (Chrome vs. Firefox vs. Brave, same mechanism as detecting VS Code), but it still can't see *inside* whichever one is focused — so the extension has to be installed in every browser the user actually uses, not just once. Chromium-based browsers (Chrome, Edge, Brave, Opera) share the same Manifest V3 platform, so the same extension codebase covers all of them with minimal change — closer to "install twice" than "build twice." Firefox uses the WebExtensions standard too, but with its own manifest format and native-messaging registration, so it's a real port rather than a straight reuse. If a browser is open that doesn't have the extension installed, the agent still knows "a browser is focused" from the window title, but that stretch of the session gets logged honestly as unclassified browser activity rather than guessed at.

## A session, mid-flow

```
🎯 GOAL: Studying Deep Learning
📊 Session: 2h 45m

🟢 Direct 56%   🟡 Peripheral 13%   🟠 Indirect 3%   🔴 Distraction 1%

15:45  🟢 0.92  YouTube — "Neural Networks Explained, 3Blue1Brown"
15:38  🟡 0.73  Medium  — "Linear Algebra for Machine Learning"
15:34  🟠 0.42  Wikipedia — "Quantum Computing Basics"

⚠ drift detected: Deep Learning → Astrophysics — still want to continue?

🧠 you focus best 14:30–15:00. drift tends to hit right after dense math.
```

## What makes this different from "just call GPT on every URL"

Anyone can point an LLM at a URL and get a category back. That's not the interesting part, and it's not what I'm building toward. The actual bet here is:

1. **Local-first relevance scoring** — cheap enough to run on every single page or window switch, not just the ones you can afford to send to an API.
2. **Personalization as the real product** — a generic prompt doesn't know that *your* version of "research" includes half-finished Wikipedia tangents that always lead somewhere useful. A model trained on *your* feedback, over weeks, does.
3. **Privacy by construction, not by policy** — everything is analyzed on your machine. If sync ever exists, it syncs aggregated stats, not your history.

## Stack

<div align="left">

![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?logo=javascript&logoColor=black)
![Manifest V3](https://img.shields.io/badge/Manifest-V3-4285F4?logo=googlechrome&logoColor=white)
![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-Local%20Storage-003B57?logo=sqlite&logoColor=white)

</div>

**Browser extension** (Manifest V3) reading in-tab content, talking to → **native agent** (Python, OS window polling + a localhost-only local server) → SQLite for local, incremental storage → LLM calls reserved for ambiguous content and plain-language summaries, never the hot path.

## Platform

Built and running on **Windows** first — that's my daily driver, so that's where it's been developed and tested. Both halves of the system are meant to be cross-platform by design (Chromium extension APIs work the same everywhere; the native agent's window-polling is the only OS-specific layer) — **Linux support** means swapping that one platform-specific piece, not a rebuild.

## Where v1 stands

The version running today is the first real slice of this, not the whole design above: a **Chrome extension on Windows**, tracking a **single browser on a single device**. It reads in-tab content and scores it against a stated goal — the part of the system that was buildable first and provable fastest.

The native agent, the local server, and multi-browser support are the parts of the architecture that exist because of a constraint I ran into honestly while building this — a browser extension cannot see outside itself — not because they were on a checklist from day one. They're documented here as the actual design, because that's what the project is: v1 is the part of it that's shipped so far.

---

<div align="center">

## About

Built by **Ancy B. John**

[![GitHub](https://img.shields.io/badge/GitHub-ancybjohn02-181717?logo=github&logoColor=white)](https://github.com/ancybjohn02)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-0A66C2?logo=linkedin&logoColor=white)](https://linkedin.com/in/ancy-b-john-05258031a)
[![Portfolio](https://img.shields.io/badge/Portfolio-ancyb.lovable.app-FF5A5F?logo=vercel&logoColor=white)](https://ancyb.lovable.app)

</div>
