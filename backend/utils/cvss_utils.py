CVSS_METRICS = {
    "AttackVector": {
        "Network": 0.85,
        "Adjacent": 0.62,
        "Local": 0.55,
        "Physical": 0.2
    },
    "AttackComplexity": {
        "Low": 0.77,
        "High": 0.44
    },
    "PrivilegesRequired": {
        "None": 0.85,
        "Low Changed": 0.68,
        "Low Unchanged": 0.62,
        "High Changed": 0.5,
        "High Unchanged": 0.27
    },
    "UserInteraction": {
        "None": 0.85,
        "Required": 0.62
    },
    "Confidentiality": {
        "High": 0.56,
        "Low": 0.22,
        "None": 0
    },
    "Integrity": {
        "High": 0.56,
        "Low": 0.22,
        "None": 0
    },
    "Availability": {
        "High": 0.56,
        "Low": 0.22,
        "None": 0
    }
}

# Reverse mappings for numerical to categorical
REVERSE_METRICS = {
    "AttackVector": {v: k for k, v in CVSS_METRICS["AttackVector"].items()},
    "AttackComplexity": {v: k for k, v in CVSS_METRICS["AttackComplexity"].items()},
    "PrivilegesRequired": {v: k for k, v in CVSS_METRICS["PrivilegesRequired"].items()},
    "UserInteraction": {v: k for k, v in CVSS_METRICS["UserInteraction"].items()},
    "Confidentiality": {v: k for k, v in CVSS_METRICS["Confidentiality"].items()},
    "Integrity": {v: k for k, v in CVSS_METRICS["Integrity"].items()},
    "Availability": {v: k for k, v in CVSS_METRICS["Availability"].items()}
}

def parse_ollama_result(result_str):
    """
    Parse the Ollama result string into a dictionary of metrics.
    """
    result_dict = {}
    lines = result_str.strip().split('\n')
    for line in lines:
        key, value = line.split(': ')
        result_dict[key] = value
    return result_dict

def calculate_iss(confidentiality, integrity, availability):
    """
    Calculate the Impact Subscore (ISS).
    """
    iss = 1 - ((1 - confidentiality) * (1 - integrity) * (1 - availability))
    return iss

def calculate_impact(iss, scope):
    """
    Calculate the Impact based on the scope.
    """
    if scope == "Unchanged":
        impact = 6.42 * iss
    elif scope == "Changed":
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 0  # Invalid scope
    return impact

def calculate_exploitability(av, ac, pr, ui):
    """
    Calculate the Exploitability Subscore (ES).
    """
    exploitability = 8.22 * av * ac * pr * ui
    return exploitability

def calculate_base_score(impact, exploitability, scope):
    """
    Calculate the Base Score.
    """
    if impact <= 0:
        return 0

    total = impact + exploitability

    if scope == "Unchanged":
        base_score = min(total, 10)
    elif scope == "Changed":
        base_score = min(1.08 * total, 10)
    else:
        base_score = 0  # Invalid scope

    base_score = round(base_score, 1)
    if base_score < 0:
        base_score = 0

    return base_score

def map_metric_value(metric_type, value):
    """
    Map numerical metric value back to categorical string.
    """
    if metric_type in REVERSE_METRICS:
        return REVERSE_METRICS[metric_type].get(value, "Unknown")
    return "Unknown"

def calculate_cvss_score(metrics):
    """
    Calculate the CVSS v3.1 Base Score based on the provided metrics.
    """
    # Parse metrics from the analysis results
    parsed_metrics = parse_ollama_result(metrics)

    # Get metric values
    av = CVSS_METRICS["AttackVector"].get(parsed_metrics.get("AttackOrigin"), 0)
    ac = CVSS_METRICS["AttackComplexity"].get(parsed_metrics.get("Complexity", "Low"), 0)
    pr = CVSS_METRICS["PrivilegesRequired"].get(parsed_metrics.get("PrivilegesRequired", "None"), 0.85)
    ui = CVSS_METRICS["UserInteraction"].get(parsed_metrics.get("UserInteraction", "None"), 0)
    c = CVSS_METRICS["Confidentiality"].get(parsed_metrics.get("Confidentiality", "None"), 0)
    i = CVSS_METRICS["Integrity"].get(parsed_metrics.get("Integrity", "None"), 0)
    a = CVSS_METRICS["Availability"].get(parsed_metrics.get("Availability", "None"), 0)
    scope = parsed_metrics.get("Scope", "Unchanged")

    # Calculate Impact Subscore (ISS)
    iss = calculate_iss(c, i, a)

    # Calculate Impact
    impact = calculate_impact(iss, scope)

    # Calculate Exploitability
    exploitability = calculate_exploitability(av, ac, pr, ui)

    # Calculate Base Score
    base_score = calculate_base_score(impact, exploitability, scope)

    # Create CVSS metrics dictionary with categorical values
    cvss = {
        "AttackVector": map_metric_value("AttackVector", av),
        "AttackComplexity": map_metric_value("AttackComplexity", ac),
        "PrivilegesRequired": map_metric_value("PrivilegesRequired", pr),
        "UserInteraction": map_metric_value("UserInteraction", ui),
        "Confidentiality": map_metric_value("Confidentiality", c),
        "Integrity": map_metric_value("Integrity", i),
        "Availability": map_metric_value("Availability", a),
        "Scope": scope
    }

    return {
        "base_score": base_score,
        "metrics": cvss
    }