import json
import os
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from flask import Flask, flash, redirect, render_template, request, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import desc, text

from detector import detect_activity

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "local-development-key-change-me")

# Render supplies DATABASE_URL. The SQLite fallback makes local testing easier.
database_url = os.environ.get("DATABASE_URL", "sqlite:///cloudshield.db")
# Some providers still supply postgres://; SQLAlchemy expects postgresql://.
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"pool_pre_ping": True}

db = SQLAlchemy(app)


class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), index=True)
    modified = db.Column(db.Integer, nullable=False)
    renamed = db.Column(db.Integer, nullable=False)
    entropy = db.Column(db.Integer, nullable=False)
    score = db.Column(db.Integer, nullable=False)
    level = db.Column(db.String(10), nullable=False, index=True)
    status = db.Column(db.String(80), nullable=False)
    reasons = db.Column(db.JSON, nullable=False)
    baseline_used = db.Column(db.Boolean, nullable=False, default=False)


def get_baseline():
    """Build a baseline from up to 30 previous LOW-risk scans only."""
    rows = (
        Scan.query.filter_by(level="LOW")
        .order_by(desc(Scan.created_at))
        .limit(30)
        .all()
    )
    if len(rows) < 5:
        return None

    # The detector uses averages of previous low-risk activity.
    return {
        "count": len(rows),
        "modified": sum(row.modified for row in rows) / len(rows),
        "renamed": sum(row.renamed for row in rows) / len(rows),
        "entropy": sum(row.entropy for row in rows) / len(rows),
    }


def make_dashboard_data():
    total_scans = Scan.query.count()
    high_count = Scan.query.filter_by(level="HIGH").count()
    medium_count = Scan.query.filter_by(level="MEDIUM").count()
    low_count = Scan.query.filter_by(level="LOW").count()

    recent = Scan.query.order_by(desc(Scan.created_at)).limit(8).all()
    chart_rows = Scan.query.order_by(desc(Scan.created_at)).limit(100).all()
    chart_rows.reverse()

    # Group scan counts by UTC calendar date for the most recent seven days.
    today = datetime.now(timezone.utc).date()
    dates = [today - timedelta(days=offset) for offset in range(6, -1, -1)]
    counts_by_date = Counter()
    for row in chart_rows:
        stamp = row.created_at
        if stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=timezone.utc)
        counts_by_date[stamp.astimezone(timezone.utc).date()] += 1

    trend_labels = [day.strftime("%d %b") for day in dates]
    trend_values = [counts_by_date[day] for day in dates]

    return {
        "total_scans": total_scans,
        "high_count": high_count,
        "medium_count": medium_count,
        "low_count": low_count,
        "recent": recent,
        "risk_labels": ["High", "Medium", "Low"],
        "risk_values": [high_count, medium_count, low_count],
        "trend_labels": trend_labels,
        "trend_values": trend_values,
        "baseline": get_baseline(),
    }


@app.route("/", methods=["GET", "POST"])
def dashboard():
    result = None
    error = None
    values = {"modified": "5", "renamed": "1", "entropy": "5"}

    if request.method == "POST":
        try:
            modified = int(request.form.get("modified", ""))
            renamed = int(request.form.get("renamed", ""))
            entropy = int(request.form.get("entropy", ""))

            if not 0 <= modified <= 100000:
                raise ValueError("Files modified must be between 0 and 100000.")
            if not 0 <= renamed <= 100000:
                raise ValueError("Files renamed must be between 0 and 100000.")
            if not 0 <= entropy <= 100:
                raise ValueError("Entropy percentage must be between 0 and 100.")

            values = {
                "modified": str(modified),
                "renamed": str(renamed),
                "entropy": str(entropy),
            }

            baseline = get_baseline()
            result = detect_activity(modified, renamed, entropy, baseline)

            scan = Scan(
                modified=modified,
                renamed=renamed,
                entropy=entropy,
                score=result["score"],
                level=result["level"],
                status=result["status"],
                reasons=result["reasons"],
                baseline_used=result["baseline_used"],
            )
            db.session.add(scan)
            db.session.commit()
            flash("Analysis saved to the database.", "success")

        except ValueError as exc:
            error = str(exc) if str(exc) else "Enter valid whole numbers."
        except Exception:
            db.session.rollback()
            app.logger.exception("Could not save the scan")
            error = "The scan could not be saved. Check the database connection and Render logs."

    data = make_dashboard_data()
    return render_template(
        "index.html",
        result=result,
        error=error,
        values=values,
        data=data,
    )


@app.route("/history")
def history():
    scans = Scan.query.order_by(desc(Scan.created_at)).limit(200).all()
    return render_template("history.html", scans=scans)


@app.route("/health")
def health():
    # Simple deployment health check. It also verifies that the database responds.
    try:
        db.session.execute(text("SELECT 1"))
        return {"status": "ok", "database": "connected"}, 200
    except Exception:
        app.logger.exception("Health check database query failed")
        return {"status": "error", "database": "unavailable"}, 503


# Create the initial table automatically. For a larger production system,
# use Flask-Migrate/Alembic to manage schema changes.
with app.app_context():
    db.create_all()


if __name__ == "__main__":
    app.run(debug=True)
