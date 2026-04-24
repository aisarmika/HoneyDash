"""ML anomaly detection using Isolation Forest (scikit-learn)."""
import asyncio

import numpy as np
from sqlalchemy import select, update

from ..database import AsyncSessionLocal
from ..models import Session


async def extract_features(db):
    """Query all sessions and build a 6-column feature matrix.

    Features:
        0 - login_attempts
        1 - login_success (0/1)
        2 - commands_run
        3 - files_downloaded
        4 - duration_secs
        5 - login_fail_ratio = (attempts - success) / max(attempts, 1)
    """
    result = await db.execute(
        select(
            Session.session_id,
            Session.login_attempts,
            Session.login_success,
            Session.commands_run,
            Session.files_downloaded,
            Session.duration_secs,
        )
    )
    rows = result.fetchall()
    if not rows:
        return [], np.empty((0, 6))

    session_ids = [r.session_id for r in rows]
    X = np.array(
        [
            [
                float(r.login_attempts or 0),
                1.0 if r.login_success else 0.0,
                float(r.commands_run or 0),
                float(r.files_downloaded or 0),
                float(r.duration_secs or 0),
                float(
                    (r.login_attempts or 0) - (1 if r.login_success else 0)
                ) / max(float(r.login_attempts or 1), 1.0),
            ]
            for r in rows
        ],
        dtype=float,
    )
    return session_ids, X


async def run_ml_detection():
    """Train Isolation Forest on all sessions, then update is_anomaly / anomaly_score."""
    try:
        from sklearn.ensemble import IsolationForest  # noqa: PLC0415
    except ImportError:
        print("[ML] scikit-learn not installed — ML detection disabled", flush=True)
        return

    async with AsyncSessionLocal() as db:
        try:
            session_ids, X = await extract_features(db)
            n = len(session_ids)
            if n < 10:
                print(f"[ML] Only {n} sessions — need ≥10. Skipping.")
                return

            print(f"[ML] Training Isolation Forest on {n} sessions …", flush=True)
            model = IsolationForest(
                n_estimators=100, contamination=0.05, random_state=42
            )
            model.fit(X)
            predictions = model.predict(X)   # -1 = anomaly, 1 = normal
            scores = model.score_samples(X)  # lower = more anomalous

            flagged = 0
            for sid, pred, score in zip(session_ids, predictions, scores):
                is_anomaly = bool(pred == -1)
                if is_anomaly:
                    flagged += 1
                await db.execute(
                    update(Session)
                    .where(Session.session_id == sid)
                    .values(is_anomaly=is_anomaly, anomaly_score=float(score))
                )
            await db.commit()
            print(f"[ML] Done. {flagged}/{n} sessions flagged as anomalous.", flush=True)
        except Exception as exc:
            print(f"[ML] Detection error: {exc}")
            await db.rollback()


async def score_single_session(session_id: str) -> None:
    """Heuristic instant-score for a newly closed session (no full retrain required)."""
    async with AsyncSessionLocal() as db:
        try:
            result = await db.execute(
                select(Session).where(Session.session_id == session_id)
            )
            sess = result.scalar_one_or_none()
            if not sess:
                return

            is_anomaly = bool(
                (sess.login_attempts or 0) > 20
                or sess.login_success
                or (sess.files_downloaded or 0) > 0
                or (sess.commands_run or 0) > 5
            )
            await db.execute(
                update(Session)
                .where(Session.session_id == session_id)
                .values(
                    is_anomaly=is_anomaly,
                    anomaly_score=-0.5 if is_anomaly else 0.1,
                )
            )
            await db.commit()
        except Exception as exc:
            print(f"[ML] score_single_session error: {exc}")
            await db.rollback()


async def start_ml_scheduler() -> None:
    """Background task: run full ML detection every 10 minutes."""
    print("[ML] Scheduler started — first run in 30s", flush=True)
    await asyncio.sleep(30)   # wait for initial data ingestion
    while True:
        await run_ml_detection()
        await asyncio.sleep(600)  # 10 minutes
