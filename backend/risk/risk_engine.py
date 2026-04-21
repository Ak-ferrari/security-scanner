def calculate_risk(issues):
    total_score = 0

    breakdown = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
    }

    # Assign score based on severity
    for issue in issues:
        severity = issue.get("severity", "Low")

        if severity == "Critical":
            weight = 35
        elif severity == "High":
            weight = 25
        elif severity == "Medium":
            weight = 15
        else:
            weight = 5

        total_score += weight
        breakdown[severity] += 1

    # Determine overall risk level
    if total_score >= 80:
        risk_level = "Critical"
    elif total_score >= 50:
        risk_level = "High"
    elif total_score >= 20:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return {
        "total_score": total_score,
        "risk_level": risk_level,
        "breakdown": breakdown,
    }