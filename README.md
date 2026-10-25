# CloudShield v2

CloudShield is an educational Flask project that analyzes manually entered file-activity metrics using explainable heuristic rules and a baseline built from earlier LOW-risk scans.

## Features
- Dark dashboard with KPI cards and Chart.js visualizations
- PostgreSQL persistence on Render
- Local SQLite fallback for beginner-friendly development
- Scan history
- Explainable risk scoring with optional baseline comparison
- Health endpoint at `/health`

## Run locally
1. Install Python 3.10 or newer.
2. Create and activate a virtual environment (optional but recommended).
3. Install dependencies: `pip install -r requirements.txt`
4. Run: `python app.py`
5. Open `http://127.0.0.1:5000`.

When `DATABASE_URL` is not set, the app uses a local SQLite database file.

## Deploy to Render
- Create a Render PostgreSQL database.
- Copy its **Internal Database URL** into your web service's `DATABASE_URL` environment variable. Keep the database and web service in the same Render region.
- Set `SECRET_KEY` to a long random secret.
- Build command: `pip install -r requirements.txt`
- Start command: `gunicorn app:app`

## Detection notes
The score is a teaching-oriented heuristic, not a validated ransomware classifier. Baseline comparisons begin after five LOW-risk scans. Results should not be interpreted as proof that a device is safe or infected. The current app does not monitor your computer's filesystem; it evaluates metrics submitted through the web form.

## Dependencies
See `requirements.txt`.
