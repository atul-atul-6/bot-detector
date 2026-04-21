"""
Ticket Bot Detection System - FastAPI Server
No API key required. Run with:
  uvicorn server.api.main:app --reload --host 0.0.0.0 --port 8000
"""

from fastapi import FastAPI, Request, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing import Optional
import time

app = FastAPI(
    title="Ticket Bot Detection API",
    description="AI-powered bot detection for ticketing websites. No API key required.",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory stores (works without Redis/Postgres for local/UAT testing)
_sessions: dict = {}
_ip_counts: dict = {}
_audit_log: list = []


class SignalPayload(BaseModel):
    session_token: str
    trigger: str
    time_to_select: Optional[float] = None
    time_to_checkout: Optional[float] = None
    mouse_entropy: Optional[float] = None
    mouse_path_length: Optional[int] = None
    scroll_events: Optional[int] = None
    focus_events: Optional[int] = None
    hover_duration: Optional[float] = None
    keystroke_regularity: Optional[float] = None
    selection_method: Optional[str] = None
    canvas_fp: Optional[str] = None
    viewport: Optional[str] = None
    tz_offset: Optional[int] = None


def compute_risk_score(signals: dict, ip: str) -> tuple[float, str]:
    score = 0.0
    reasons = []

    t_sel   = signals.get("time_to_select")       or 999
    t_check = signals.get("time_to_checkout")     or 999
    entropy = signals.get("mouse_entropy")        or 0
    scroll  = signals.get("scroll_events")        or 0
    hover   = signals.get("hover_duration")       or 0
    key_reg = signals.get("keystroke_regularity") or 0
    sel_m   = signals.get("selection_method")     or "click"

    if t_sel < 2:
        score += 0.35; reasons.append(f"selected in {t_sel:.2f}s (bot: <2s)")
    elif t_sel < 6:
        score += 0.15; reasons.append(f"selected in {t_sel:.2f}s (borderline)")

    if t_check < 0.3:
        score += 0.25; reasons.append(f"checkout in {t_check:.2f}s (near-instant)")
    elif t_check < 1.0:
        score += 0.10; reasons.append(f"checkout in {t_check:.2f}s (fast)")

    if entropy < 0.05:
        score += 0.20; reasons.append(f"mouse entropy {entropy:.2f} (near-zero)")
    elif entropy < 0.25:
        score += 0.10; reasons.append(f"mouse entropy {entropy:.2f} (low)")

    if scroll == 0:
        score += 0.08; reasons.append("zero scroll events")

    if hover < 0.5:
        score += 0.06; reasons.append("no hover on tickets")

    if key_reg > 0.90:
        score += 0.10; reasons.append(f"keystroke regularity {key_reg:.2f} (robotic)")

    if sel_m == "dom_inject":
        score += 0.20; reasons.append("DOM injection — not a real click")

    subnet = ".".join(ip.split(".")[:3])
    count  = _ip_counts.get(subnet, 0)
    if count > 15:
        score += 0.20; reasons.append(f"{count} sessions from same subnet")
    elif count > 5:
        score += 0.08; reasons.append(f"{count} sessions from subnet")

    score  = round(min(score, 1.0), 4)
    reason = "; ".join(reasons) if reasons else "Behaviour consistent with human user."
    return score, reason


def decide_action(score: float) -> str:
    if score < 0.35: return "pass"
    if score < 0.70: return "queue"
    return "block"


@app.get("/", response_class=HTMLResponse, tags=["Info"])
async def root():
    return """
    <html><body style="font-family:sans-serif;max-width:600px;margin:60px auto;padding:20px">
    <h2>Ticket Bot Detector API</h2>
    <p>Status: <strong style="color:green">Running</strong></p>
    <p>No API key required.</p>
    <ul>
      <li><a href="/docs">Swagger API Docs</a></li>
      <li><a href="/api/admin/stats">Live Stats</a></li>
      <li><a href="/health">Health Check</a></li>
    </ul>
    </body></html>
    """


@app.get("/health", tags=["Info"])
async def health():
    return {"status": "ok", "sessions_tracked": len(_sessions), "api_key_required": False}


@app.post("/api/session/signal", tags=["Detection"])
async def receive_signal(payload: SignalPayload, request: Request, background_tasks: BackgroundTasks):
    ip     = request.client.host
    subnet = ".".join(ip.split(".")[:3])
    _ip_counts[subnet] = _ip_counts.get(subnet, 0) + 1

    key = payload.session_token
    _sessions.setdefault(key, {}).update({k: v for k, v in payload.dict().items() if v is not None})

    if payload.trigger != "checkout":
        return {"status": "received", "trigger": payload.trigger}

    t0 = time.perf_counter()
    score, reason = compute_risk_score(_sessions.get(key, {}), ip)
    action = decide_action(score)
    latency_ms = round((time.perf_counter() - t0) * 1000, 2)
    verdict = "bot" if score > 0.70 else "suspicious" if score > 0.35 else "human"

    background_tasks.add_task(_log_session, key, ip, score, verdict, action, reason)

    return {"action": action, "score": score, "verdict": verdict, "reason": reason, "latency_ms": latency_ms}


async def _log_session(token, ip, score, verdict, action, reason):
    entry = {"token": token[:12]+"...", "ip": ip, "score": score,
             "verdict": verdict, "action": action, "reason": reason,
             "time": time.strftime("%Y-%m-%d %H:%M:%S")}
    _audit_log.append(entry)
    if len(_audit_log) > 500:
        _audit_log.pop(0)
    print(f"[{verdict.upper():10}] score={score:.3f} action={action:6} | {reason[:80]}")


@app.get("/api/admin/stats", tags=["Admin"])
async def admin_stats():
    total  = len(_sessions)
    bots   = sum(1 for s in _sessions.values() if (s.get("risk_score") or 0) > 0.70)
    sus    = sum(1 for s in _sessions.values() if 0.35 < (s.get("risk_score") or 0) <= 0.70)
    return {
        "total_sessions": total, "bot_sessions": bots,
        "suspicious_sessions": sus, "human_sessions": total - bots - sus,
        "top_subnets": sorted(_ip_counts.items(), key=lambda x: x[1], reverse=True)[:5],
        "recent_log": _audit_log[-10:],
    }


@app.get("/api/admin/log", tags=["Admin"])
async def audit_log():
    return {"log": list(reversed(_audit_log)), "total": len(_audit_log)}


@app.delete("/api/admin/reset", tags=["Admin"])
async def reset():
    _sessions.clear(); _ip_counts.clear(); _audit_log.clear()
    return {"status": "reset complete"}
