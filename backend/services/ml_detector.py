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
    """Heuristic instant-score for a newly closed session (no full retrain required).

    Uses a weighted suspicion model rather than flat thresholds so that
    routine honeypot noise (low-attempt brute-force, login-only sessions)
    doesn't flood the anomaly feed before the Isolation Forest has trained.

    Suspicion weights (0.0 – normal, ≥0.5 = anomaly):
      - Mass brute-force (>200 attempts): +0.5
      - Heavy brute-force (>80 attempts): +0.3
      - Light brute-force (>30 attempts): +0.1
      - Successful login + post-exploitation commands (>3): +0.6
      - Successful login + any commands: +0.3
      - Successful login alone: +0.1 (honeypots accept logins by design)
      - File downloaded: +0.5 (strong signal regardless of login status)
      - High command count without login (>30): +0.3 (worm/scanner probing)
      - Moderate command count without login (>15): +0.1
    """
    async with AsyncSessionLocal() as db:
        try:
            result = await db.execute(
                select(Session).where(Session.session_id == session_id)
            )
            sess = result.scalar_one_or_none()
            if not sess:
                return

            login_att = sess.login_attempts or 0
            cmds      = sess.commands_run   or 0
            files     = sess.files_downloaded or 0
            success   = bool(sess.login_success)

            suspicion = 0.0

            # Brute-force volume
            if login_att > 200:
                suspicion += 0.5
            elif login_att > 80:
                suspicion += 0.3
            elif login_att > 30:
                suspicion += 0.1

            # Post-exploitation after successful login
            if success and cmds > 3:
                suspicion += 0.6
            elif success and cmds > 0:
                suspicion += 0.3
            elif success:
                suspicion += 0.1  # login accepted but no follow-up commands

            # File download — strongest single indicator
            if files > 0:
                suspicion += 0.5

            # High command volume without ever logging in (worm/scanner)
            if not success:
                if cmds > 30:
                    suspicion += 0.3
                elif cmds > 15:
                    suspicion += 0.1

            is_anomaly = suspicion >= 0.5
            # Match Isolation Forest convention: 0 = normal, -1 = highly anomalous
            anomaly_score = max(-1.0, -suspicion)

            await db.execute(
                update(Session)
                .where(Session.session_id == session_id)
                .values(is_anomaly=is_anomaly, anomaly_score=anomaly_score)
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
