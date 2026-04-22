# Ticket Bot Detection System

AI-powered behavioral analysis that detects scalper bots on ticketing websites.
**Zero user friction. No CAPTCHA. No API key required.**

## To see ALL users including real bots, the website needs the script tag:
      ```bash
      <script src="YOUR-API-URL/static/collector.js" defer></script>
      ```
**Once this is on the website's checkout page, collector.js runs inside EVERY visitor's browser — yours, other users, and bots. Now your API sees all of them and can detect which ones are bots.**

## Quick start (Codespace)

1. Open this repo in GitHub Codespace
2. In the terminal:
   ```bash
   docker compose up -d
   uvicorn server.api.main:app --reload --host 0.0.0.0 --port 8000
   ```
3. Codespace auto-opens port 8000 — click "Open in Browser"
4. Go to `/docs` to see the full API

## Quick start (local Windows)

```bash
pip install -r requirements.txt
docker compose up -d
uvicorn server.api.main:app --reload --host 0.0.0.0 --port 8000
```

Open: http://localhost:8000/docs

## Tech stack
Python · FastAPI · XGBoost · Redis · PostgreSQL · Docker · Vanilla JS
