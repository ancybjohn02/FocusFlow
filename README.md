# FocusLens

**It's not where you are online — it's what you're actually looking at.**

*(Working title — easy to swap for whatever you land on.)*

---

## Why this exists

Every "focus tracker" I've come across runs on the same lazy shortcut: it looks at the *domain*, not the *content*. YouTube gets stamped "entertainment." Twitter gets stamped "distraction." Wikipedia gets a free pass. Medium is either "research" or "not," depending on the tool's mood.

That's broken. A 3Blue1Brown video on backpropagation and a gaming highlight reel are both "YouTube," but they are not the same activity, and no tool that treats them the same is telling you anything true about your own focus.

I kept running into this personally — trying to study deep learning, drifting into a Wikipedia rabbit hole on quantum computing, and every tracker I tried either didn't notice or flagged Wikipedia itself as the problem, when the actual problem was *that specific tangent, at that specific moment*. So I started building the tool I actually wanted: something that reads what a page or video is actually about, checks it against what I said I'm trying to do, and only then decides whether I've drifted.

The rule underneath the whole project: **content over platform.** Not *where* it's from — *what* it is.

## What it does

- **Takes your goal in plain language** — "studying deep learning," not a dropdown category.
- **Reads the content, not the URL** — title, description, tags, extracted text, video metadata — and scores it against that goal.
- **Grades relevance on a gradient**, not a pass/fail:
  - 🟢 Direct — squarely on-topic
  - 🟡 Peripheral — adjacent groundwork (linear algebra while you're studying deep learning, say)
  - 🟠 Indirect — a tangent worth a nudge
  - 🔴 Distraction — off-topic
- **Cares about continuity, not just content** — a 90-second scroll through Twitter and a 20-minute derail are not the same failure, and the system is built to know the difference.
- **Learns *your* definition of relevant.** "Research" means something different to you than to the next person. Every time it asks "this looks off-topic, still want to continue?" and you answer, that's a data point that makes it fit you better next week than it did today.
- **Turns all of that into something you'd actually look at** — a live session view instead of a spreadsheet nobody opens.

## How it's built

```
        browser activity (tab switch, navigation, idle, scroll)
                              │
                     debounced event queue
                    (background service worker)
                              │
                 metadata + content extraction
          (title, tags, description, video API for YouTube)
                              │
                 local embedding model on-device
              (goal embedded once, page embedded per visit)
                              │
                  cosine similarity → relevance tier
                              │
             per-user adaptive layer (learns from your
                  answers to "still want to continue?")
                              │
                    session state → IndexedDB
                              │
                         live dashboard

   ── LLM used sparingly, off the hot path ──
   → resolving genuinely ambiguous content
   → writing the plain-language session summary
```

The part I actually care about here is the embedding step. It would be trivial to fire an LLM call at every tab switch and call it a day — slow, expensive, and it doesn't scale past a demo. Instead, the goal gets embedded once, every page gets embedded locally as you visit it, and relevance is just a cosine similarity check running in milliseconds, offline, for free. The LLM is reserved for the genuinely hard 5%: ambiguous content, and turning raw session data into something readable ("you tend to drift right after dense math sections").

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

1. **Local-first relevance scoring** — cheap enough to run on every single page visit, not just the ones you can afford to send to an API.
2. **Personalization as the real product** — a generic prompt doesn't know that *your* version of "research" includes half-finished Wikipedia tangents that always lead somewhere useful. A model trained on *your* feedback, over weeks, does.
3. **Privacy by construction, not by policy** — your browsing content is analyzed on your machine. If sync ever exists, it syncs aggregated stats, not your history.

## Stack

Browser extension (Manifest V3) → on-device embedding model (transformers.js / ONNX Runtime Web) → lightweight per-user classifier trained incrementally → IndexedDB for local storage → LLM calls reserved for edge cases and summaries.

## Platform

Built and running on **Windows** first — that's my daily driver, so that's where it's been developed and tested. It's a browser extension underneath, so most of the code doesn't actually care what OS it's on; **Linux support** is the natural next step once the core is solid, not a rebuild.

## About

Built by **Ancy B. John** — [GitHub](https://github.com/ancybjohn02) · [LinkedIn](https://linkedin.com/in/ancy-b-john-05258031a) · [Portfolio](https://ancyb.lovable.app)
