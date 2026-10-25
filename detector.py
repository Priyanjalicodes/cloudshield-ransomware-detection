def detect_activity(modified, renamed, entropy, baseline=None):
    """
    Explainable heuristic detector for an academic prototype.

    Base rule score: up to 7 points.
    Baseline deviation: up to 3 additional points.
    Maximum score: 10.
    """
    score = 0
    reasons = []
    baseline_used = baseline is not None

    # Rule 1: file modification volume (0-2 points)
    if modified >= 30:
        score += 2
        reasons.append("Very high file modification volume (+2).")
    elif modified >= 15:
        score += 1
        reasons.append("Elevated file modification volume (+1).")
    else:
        reasons.append("File modification volume is below the elevated threshold.")

    # Rule 2: file rename volume (0-2 points)
    if renamed >= 10:
        score += 2
        reasons.append("Very high file renaming volume (+2).")
    elif renamed >= 5:
        score += 1
        reasons.append("Elevated file renaming volume (+1).")
    else:
        reasons.append("File renaming volume is below the elevated threshold.")

    # Rule 3: percentage of files with unusual entropy changes (0-3 points)
    if entropy >= 50:
        score += 3
        reasons.append("Many files show unusual entropy changes (+3).")
    elif entropy >= 25:
        score += 2
        reasons.append("Some files show unusual entropy changes (+2).")
    else:
        reasons.append("Unusual entropy changes are below the alert threshold.")

    # Baseline comparison starts only after five previous LOW-risk scans.
    if baseline:
        modified_limit = max(baseline["modified"] * 3, baseline["modified"] + 10)
        renamed_limit = max(baseline["renamed"] * 3, baseline["renamed"] + 3)
        entropy_limit = min(100, baseline["entropy"] + 20)

        if modified > modified_limit:
            score += 1
            reasons.append(
                f"File modifications are unusually high compared with the baseline (+1; baseline average {baseline['modified']:.1f})."
            )
        if renamed > renamed_limit:
            score += 1
            reasons.append(
                f"File renaming is unusually high compared with the baseline (+1; baseline average {baseline['renamed']:.1f})."
            )
        if entropy > entropy_limit:
            score += 1
            reasons.append(
                f"Entropy changes exceed the baseline by more than 20 percentage points (+1; baseline average {baseline['entropy']:.1f}%)."
            )
    else:
        reasons.append(
            "Baseline not available yet: complete at least 5 LOW-risk scans to enable baseline comparison."
        )

    if score >= 7:
        level = "HIGH"
        status = "Suspicious Activity Detected"
    elif score >= 4:
        level = "MEDIUM"
        status = "Potentially Suspicious Activity"
    else:
        level = "LOW"
        status = "Normal-Looking Activity"

    return {
        "score": score,
        "max_score": 10,
        "level": level,
        "status": status,
        "reasons": reasons,
        "baseline_used": baseline_used,
    }
