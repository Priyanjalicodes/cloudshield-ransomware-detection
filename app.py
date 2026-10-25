
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
header p, .muted { color: #a9b9ce; }
main { max-width: 1000px; margin: 30px auto; padding: 0 18px; }
.card {
    background: #142137; border: 1px solid #2b3b55;
    padding: 22px; border-radius: 14px; margin-bottom: 20px;
}
form { display: grid; gap: 17px; }
label { display: block; font-weight: bold; margin-bottom: 7px; }
input {
    width: 100%; padding: 12px; border-radius: 8px;
    border: 1px solid #455873; background: #0b1220;
    color: white; font-size: 16px;
}
small { display: block; color: #a9b9ce; margin-top: 6px; }
button {
    border: 0; border-radius: 8px; padding: 13px 18px;
    cursor: pointer; font-weight: bold; font-size: 15px;
    background: #65d6ad; color: #08251c;
}
.result { border-left: 5px solid #65d6ad; }
.danger { border-left-color: #ff7979; }
.warning { border-left-color: #ffc66d; }
.score { font-size: 30px; font-weight: bold; }
table { width: 100%; border-collapse: collapse; }
th, td {
    padding: 12px 8px; text-align: left;
    border-bottom: 1px solid #2b3b55;
}
footer { text-align: center; padding: 24px; color: #8fa2bb; }
@media(max-width: 600px) {
    th, td { font-size: 12px; padding: 8px 3px; }
}
</style>
</head>
<body>
<header>
    <h1>🛡️ CloudShield</h1>
    <p>Cloud-Based Ransomware Detection System</p>
</header>

<main>
<section class="card">
    <h2>Activity Analysis</h2>
    <p class="muted">
        Enter simulated file activity from a one-minute observation window.
    </p>

    <form method="post">
        <div>
            <label for="modified">Files modified in one minute</label>
            <input id="modified" type="number" name="modified"
                   min="0" max="100000" value="{{ values.modified }}"
                   required>
            <small>Number of files changed during the observation window.</small>
        </div>

        <div>
            <label for="renamed">Files renamed in one minute</label>
            <input id="renamed" type="number" name="renamed"
                   min="0" max="100000" value="{{ values.renamed }}"
                   required>
            <small>Large bursts of renaming can be a warning sign.</small>
        </div>

        <div>
            <label for="entropy">Files with unusual entropy changes (%)</label>
            <input id="entropy" type="number" name="entropy"
                   min="0" max="100" value="{{ values.entropy }}"
                   required>
            <small>Estimated percentage of files showing unusual
            changes in data randomness.</small>
        </div>

        <button type="submit">Analyze Activity</button>
    </form>
</section>

{% if error %}
<section class="card warning">
    <h3>Invalid Input</h3>
    <p>{{ error }}</p>
</section>
{% endif %}

{% if result %}
<section class="card {{ 'danger' if result.level == 'HIGH'
    else 'warning' if result.level == 'MEDIUM' else 'result' }}">
    <h2>{{ result.status }}</h2>
    <p class="score">{{ result.score }} / 7</p>
    <p><b>Risk level:</b> {{ result.level }}</p>
    <p><b>Reasoning:</b></p>
    <ul>
    {% for reason in result.reasons %}
        <li>{{ reason }}</li>
    {% endfor %}
    </ul>
    <p class="muted">Analyzed at {{ result.time }} UTC</p>
</section>
{% endif %}

<section class="card">
    <h2>Detection History</h2>
    {% if alerts %}
    <table>
        <tr><th>Time (UTC)</th><th>Score</th><th>Result</th><th>Risk</th></tr>
        {% for a in alerts %}
        <tr>
            <td>{{ a.time }}</td>
            <td>{{ a.score }}/7</td>
            <td>{{ a.status }}</td>
            <td>{{ a.level }}</td>
        </tr>
        {% endfor %}
    </table>
    {% else %}
    <p class="muted">No analyses yet.</p>
    {% endif %}
</section>

<p class="muted">
Educational prototype. Uses manually entered simulated metrics and
heuristic rules. It is not a validated antivirus or a substitute for
endpoint security software.
</p>
</main>
<footer>CloudShield · Cloud Computing Semester Project</footer>
</body>
</html>
"""


def detect_activity(modified, renamed, entropy):
    score = 0
    reasons = []

    if modified >= 30:
        score += 2
        reasons.append("Very high file modification volume (+2).")
    elif modified >= 15:
        score += 1
        reasons.append("Elevated file modification volume (+1).")
    else:
        reasons.append("File modification volume is below the elevated threshold.")

    if renamed >= 10:
        score += 2
        reasons.append("Very high file renaming volume (+2).")
    elif renamed >= 5:
        score += 1
        reasons.append("Elevated file renaming volume (+1).")
    else:
        reasons.append("File renaming volume is below the elevated threshold.")

    if entropy >= 50:
        score += 3
        reasons.append("Many files show unusual entropy changes (+3).")
    elif entropy >= 25:
        score += 2
        reasons.append("Some files show unusual entropy changes (+2).")
    else:
        reasons.append("Unusual entropy changes are below the alert threshold.")

    if score >= 5:
        level = "HIGH"
        status = "Suspicious Activity Detected"
    elif score >= 3:
        level = "MEDIUM"
        status = "Potentially Suspicious Activity"
    else:
        level = "LOW"
        status = "Normal-Looking Activity"

    return {
        "score": score,
        "level": level,
        "status": status,
        "reasons": reasons,
        "time": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
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

            if not (0 <= modified <= 100000):
                raise ValueError("Modified files must be between 0 and 100000.")
            if not (0 <= renamed <= 100000):
                raise ValueError("Renamed files must be between 0 and 100000.")
            if not (0 <= entropy <= 100):
                raise ValueError("Entropy percentage must be between 0 and 100.")

            values = {
                "modified": str(modified),
                "renamed": str(renamed),
                "entropy": str(entropy)
            }

            result = detect_activity(modified, renamed, entropy)
            alerts.insert(0, {
                **result,
                "scenario": "Custom activity"
            })
            del alerts[50:]

        except (ValueError, TypeError):
            error = "Enter valid whole numbers within the specified ranges."

    return render_template_string(
        HTML, result=result, alerts=alerts, values=values, error=error
    )


if __name__ == "__main__":
    app.run()
