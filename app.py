
from flask import Flask, request, render_template_string
from datetime import datetime, timezone

app = Flask(__name__)
alerts = []

HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CloudShield | Ransomware Detection</title>
<style>
* { box-sizing: border-box; }
body {
    margin: 0; font-family: Arial, sans-serif;
    background: #0b1220; color: #e5edf8;
}
header {
    padding: 24px 7%; background: #111c30;
    border-bottom: 1px solid #26364f;
}
header h1 { margin: 0; color: #65d6ad; }
header p { color: #a9b9ce; }
main { max-width: 1000px; margin: 30px auto; padding: 0 18px; }
.card {
    background: #142137; border: 1px solid #2b3b55;
    padding: 22px; border-radius: 14px; margin-bottom: 20px;
}
button {
    border: 0; border-radius: 8px; padding: 12px 16px;
    margin: 5px 5px 5px 0; cursor: pointer; font-weight: bold;
}
.normal { background: #65d6ad; color: #08251c; }
.suspicious { background: #ff7979; color: #361010; }
.result { border-left: 5px solid #65d6ad; }
.danger { border-left-color: #ff7979; }
.muted { color: #a9b9ce; }
table { width: 100%; border-collapse: collapse; }
th, td { padding: 12px 8px; text-align: left; border-bottom: 1px solid #2b3b55; }
footer { text-align: center; padding: 24px; color: #8fa2bb; }
</style>
</head>
<body>
<header>
    <h1>🛡️ CloudShield</h1>
    <p>Cloud-Based Ransomware Detection System</p>
</header>
<main>
    <section class="card">
        <h2>Detection Dashboard</h2>
        <p class="muted">Run safe simulations to test suspicious file activity detection.</p>
        <form method="post">
            <button class="normal" name="scenario" value="normal">
                Test Normal Activity
            </button>
            <button class="suspicious" name="scenario" value="suspicious">
                Test Suspicious Activity
            </button>
        </form>
    </section>

    {% if result %}
    <section class="card result {{ 'danger' if result.level == 'HIGH' else '' }}">
        <h2>{{ result.status }}</h2>
        <p><b>Risk level:</b> {{ result.level }}</p>
        <p><b>Reason:</b> {{ result.reason }}</p>
        <p class="muted">Detection time: {{ result.time }}</p>
    </section>
    {% endif %}

    <section class="card">
        <h2>Detection History</h2>
        {% if alerts %}
        <table>
            <tr><th>Time (UTC)</th><th>Scenario</th><th>Result</th><th>Risk</th></tr>
            {% for a in alerts %}
            <tr>
                <td>{{ a.time }}</td>
                <td>{{ a.scenario }}</td>
                <td>{{ a.status }}</td>
                <td>{{ a.level }}</td>
            </tr>
            {% endfor %}
        </table>
        {% else %}
        <p class="muted">No tests run yet. Try a simulation above.</p>
        {% endif %}
    </section>
    <p class="muted">Educational prototype — results are simulated, not proof of real malware.</p>
</main>
<footer>CloudShield · Cloud Computing Semester Project</footer>
</body>
</html>
"""


@app.route("/", methods=["GET", "POST"])
def dashboard():
    result = None

    if request.method == "POST":
        scenario = request.form.get("scenario", "")

        if scenario == "suspicious":
            result = {
                "scenario": "Suspicious simulation",
                "status": "Suspicious Activity Detected",
                "level": "HIGH",
                "reason": (
                    "The simulated activity contains a high rate of file "
                    "renames and unusual file modifications."
                ),
            }
        elif scenario == "normal":
            result = {
                "scenario": "Normal simulation",
                "status": "Normal Activity",
                "level": "LOW",
                "reason": (
                    "The simulated activity matches an ordinary "
                    "low-volume file operation pattern."
                ),
            }

        if result:
            result["time"] = datetime.now(timezone.utc).strftime(
                "%Y-%m-%d %H:%M:%S"
            )
            alerts.insert(0, result.copy())
            del alerts[50:]
    
    return render_template_string(
        HTML, result=result, alerts=alerts
    )


if __name__ == "__main__":
    app.run()
