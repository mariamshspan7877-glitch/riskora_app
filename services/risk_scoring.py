from collections import OrderedDict

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_WEIGHT = {"low": 10, "medium": 22, "high": 38, "critical": 62}


def deduplicate_findings(findings):
    ordered = OrderedDict()
    for item in findings:
        key = item.get("title") or item.get("id") or "unknown"
        existing = ordered.get(key)
        if existing is None:
            ordered[key] = item
        else:
            current_level = SEVERITY_ORDER.get(item.get("severity", "low"), 0)
            existing_level = SEVERITY_ORDER.get(existing.get("severity", "low"), 0)
            if current_level > existing_level:
                ordered[key] = item
    return list(ordered.values())


def calculate_risk_score(findings):
    total = 0
    for finding in deduplicate_findings(findings):
        total += SEVERITY_WEIGHT.get(str(finding.get("severity", "low")).lower(), 10)
    return max(0, min(100, total))


def get_risk_label(score):
    if score >= 75:
        return "Critical"
    if score >= 50:
        return "High"
    if score >= 25:
        return "Medium"
    return "Low"
