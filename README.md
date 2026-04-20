# Ticket Bot Detection System

AI-powered behavioral analysis that detects scalper bots on ticketing
websites — zero user friction, no CAPTCHA, <30ms scoring at checkout.

## Quick Start

```bash
git clone https://github.com/yourname/ticket-bot-detector
cd ticket-bot-detector

# Add your Anthropic key for LLM explanations (optional)
echo "ANTHROPIC_API_KEY=sk-ant-..." > .env

# Start all services
docker compose up -d

# API available at http://localhost:8000
# Docs at http://localhost:8000/docs
```

## Add to Your Website

Drop the collector script into your checkout page, just before `</body>`:

```html
<script src="https://yourcdn.com/collector.min.js"></script>
```

Then gate your checkout endpoint:

```python
import httpx

async def checkout(request):
    token = request.cookies.get("session_token")
    r = await httpx.post("http://api:8000/api/session/signal", json={
        "session_token": token,
        "trigger": "checkout",
    })
    action = r.json()["action"]

    if action == "block":
        return {"error": "Sorry, tickets are sold out."}  # fake sold-out
    if action == "queue":
        await enqueue_for_review(token, request)          # silent queue
        return {"success": True}                          # bot thinks it worked
    # action == "pass"
    return await process_real_checkout(request)
```

## Project Structure

```
client/src/collector.js     Invisible browser signal collector
server/api/main.py          FastAPI risk scoring engine
server/db/schema.sql        PostgreSQL schema
server/ml/model.py          XGBoost classifier
docker-compose.yml          Full stack (API + Postgres + Redis + ClickHouse)
requirements.txt            Python dependencies
docs/IMPLEMENTATION_PLAN.md Complete technical plan
```

## How It Works

1. **Collector** silently captures 10 behavioral signals (mouse entropy,
   hover duration, time-to-select, keystroke regularity, DOM injection
   detection, scroll events, canvas fingerprint, etc.)

2. **Risk Engine** (FastAPI + XGBoost) receives an encrypted beacon at
   checkout and returns a risk score in <30ms.

3. **Response Router** applies graduated actions:
   - Score < 0.35 → **Pass** (legitimate user)
   - Score 0.35–0.70 → **Silent queue** (bot thinks it succeeded)
   - Score > 0.70 → **Block** with fake "sold out" response

4. **LLM Explainer** (Claude API) generates plain-English audit trail
   entries for borderline sessions — useful for human review.

## Tech Stack

Python · FastAPI · XGBoost · SHAP · Redis · PostgreSQL · ClickHouse ·
Claude API · Docker · Vanilla JS

## Training the Model

After collecting ~2,000 labeled sessions via the rule-based scorer:

```bash
pip install -r requirements.txt
python -m server.ml.train
```

Target metrics: ~94% precision, ~91% recall, <0.5% false positive rate.
