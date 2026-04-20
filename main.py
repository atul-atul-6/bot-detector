"""
Ticket Bot Detection System — FastAPI Server
Run: uvicorn server.api.main:app --reload
"""

from fastapi import FastAPI, Request, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional
import time
import hashlib

app = FastAPI(title="Bot Detection API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://yourticketingsite.com"],
    allow_methods=["POST"],
    allow_headers=["*"],
)

# ── In-memory session store (replace with Redis in production) ──
_sessions: dict = {}
_ip_counts: dict = {}


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
    """
    Rule-based scorer — replace with trained XGBoost model in production.
    Returns (score 0.0–1.0, plain-English reason).
    """
    score = 0.0
    reasons = []

    t_sel = signals.get("time_to_select") or 999
    t_check = signals.get("time_to_checkout") or 999
    entropy = signals.get("mouse_entropy") or 0
    scroll = signals.get("scroll_events") or 0
    hover = signals.get("hover_duration") or 0
    key_reg = signals.get("keystroke_regularity") or 0
    sel_method = signals.get("selection_method") or "click"

    # Time signals (highest weight)
    if t_sel < 2:
        score += 0.35; reasons.append(f"selected in {t_sel:.1f}s (bot threshold: <2s)")
    elif t_sel < 6:
        score += 0.15; reasons.append(f"selected in {t_sel:.1f}s (borderline)")

    if t_check < 0.3:
        score += 0.25; reasons.append(f"checkout in {t_check:.2f}s")
    elif t_check < 1.0:
        score += 0.10

    # Behavioral entropy
    if entropy < 0.05:
        score += 0.20; reasons.append(f"mouse entropy {entropy:.2f} (near-zero)")
    elif entropy < 0.25:
        score += 0.10

    if scroll == 0:
        score += 0.08; reasons.append("no scroll events")

    if hover < 0.5:
        score += 0.06; reasons.append("no hover on tickets")

    if key_reg > 0.90:
        score += 0.10; reasons.append(f"robotic keystroke regularity {key_reg:.2f}")

    if sel_method == "dom_inject":
        score += 0.20; reasons.append("selection via DOM injection (not user click)")

    # IP velocity
    subnet = ".".join(ip.split(".")[:3])
    count = _ip_counts.get(subnet, 0)
    if count > 15:
        score += 0.20; reasons.append(f"{count} sessions from subnet /{subnet}")
    elif count > 5:
        score += 0.08

    score = round(min(score, 1.0), 4)
    reason = "; ".join(reasons) if reasons else "Behaviour consistent with human user."
    return score, reason


def decide_action(score: float) -> str:
    if score < 0.35:
        return "pass"
    if score < 0.70:
        return "queue"   # silent queue
    return "block"


@app.post("/api/session/signal")
async def receive_signal(
    payload: SignalPayload,
    request: Request,
    background_tasks: BackgroundTasks,
):
    ip = request.client.host
    subnet = ".".join(ip.split(".")[:3])

    # Update IP velocity counter
    _ip_counts[subnet] = _ip_counts.get(subnet, 0) + 1

    # Cache session signals
    key = payload.session_token
    _sessions.setdefault(key, {}).update(payload.dict(exclude_none=True))

    if payload.trigger != "checkout":
        return {"status": "received"}

    # Score at checkout
    t_start = time.perf_counter()
    session_signals = _sessions.get(key, {})
    score, reason = compute_risk_score(session_signals, ip)
    action = decide_action(score)
    latency_ms = round((time.perf_counter() - t_start) * 1000, 2)

    # Persist in background
    background_tasks.add_task(
        log_session, key, ip, score, reason, action, session_signals
    )

    return {
        "action": action,
        "score": score,
        "latency_ms": latency_ms,
    }


async def log_session(token, ip, score, reason, action, signals):
    """Background task — save to DB in production."""
    verdict = "bot" if score > 0.70 else "suspicious" if score > 0.35 else "human"
    print(f"[{verdict.upper()}] ip={ip} score={score} action={action} reason={reason}")


@app.get("/api/admin/stats")
async def admin_stats():
    """Returns live stats for the admin dashboard."""
    sessions = list(_sessions.values())
    total = len(sessions)
    bot_count = sum(1 for s in sessions if s.get("risk_score", 0) > 0.70)
    sus_count = sum(1 for s in sessions if 0.35 < s.get("risk_score", 0) <= 0.70)
    return {
        "total_sessions": total,
        "bot_sessions": bot_count,
        "suspicious_sessions": sus_count,
        "human_sessions": total - bot_count - sus_count,
        "top_subnets": sorted(
            _ip_counts.items(), key=lambda x: x[1], reverse=True
        )[:5],
    }


@app.get("/health")
async def health():
    return {"status": "ok"}
