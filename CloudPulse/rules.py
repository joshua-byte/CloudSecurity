
"""CloudPulse rule engine: validate CloudTrail events and write outputs/alerts.csv."""

import json
from pathlib import Path

import pandas as pd


BASE = Path(__file__).resolve().parent
RULES_FILE = BASE / "rules.json"
ALL_FILE = BASE / "logged" / "normalized_events.csv"
SUSPICIOUS_FILE = BASE / "logged" / "suspicious_events.csv"
WINDOWS_FILE = BASE / "logged" / "anomaly_windows.csv"
OUTPUT_FILE = BASE / "outputs" / "alerts.csv"

COLUMNS = [
    "alert_id", "time", "status", "severity", "user", "sourceIP",
    "eventName", "rule_id", "rule_name", "mitre", "z_peak",
    "window_id", "evidence_count", "description"
]

SEVERITIES = ["Low", "Medium", "High", "Critical"]


def read_csv(path):
    """Read a CSV, returning an empty DataFrame if absent or empty."""
    if not path.exists():
        return pd.DataFrame()

    try:
        frame = pd.read_csv(path, low_memory=False)
    except pd.errors.EmptyDataError:
        return pd.DataFrame()

    # The detector names these fields differently from the rule engine.
    # Normalize them here so statistical evidence can be correlated reliably.
    if path.resolve() == SUSPICIOUS_FILE.resolve():
        if "z_peak" not in frame.columns and "anomaly_peak_z" in frame.columns:
            frame["z_peak"] = frame["anomaly_peak_z"]
        if "window_id" not in frame.columns and "anomaly_window_ids" in frame.columns:
            frame["window_id"] = frame["anomaly_window_ids"].fillna("").astype(str).str.split(";").str[0].str.strip()

    return frame


def load_rules():
    """Load the selected rule definitions from rules.json."""
    if not RULES_FILE.exists():
        raise FileNotFoundError(
            f"Save the combined rules file here: {RULES_FILE}"
        )

    with RULES_FILE.open(encoding="utf-8") as file:
        data = json.load(file)

    rules = data.get("rules", [])
    if not rules:
        raise ValueError("rules.json has no rules in its 'rules' list.")

    return rules


def text(value):
    """Convert a value to a safe string, treating missing values as blank."""
    if value is None:
        return ""

    if not isinstance(value, (dict, list)):
        try:
            if pd.isna(value):
                return ""
        except (TypeError, ValueError):
            pass

    return str(value).strip()


def truthy(value):
    """Interpret common CSV boolean values consistently."""
    return text(value).lower() in {"true", "1", "yes"}


def parse_params(value):
    """Parse requestParameters JSON from the normalized CSV."""
    if isinstance(value, dict):
        return value

    try:
        result = json.loads(text(value))
        return result if isinstance(result, dict) else {}
    except (json.JSONDecodeError, TypeError):
        return {}


def get_nested(data, path):
    """Read a nested dictionary value using a dotted path."""
    for part in path.split("."):
        if not isinstance(data, dict):
            return None
        data = data.get(part)

    return data


def find_values(value, key):
    """Find all occurrences of a key in nested request parameters."""
    found = []

    if isinstance(value, dict):
        for name, child in value.items():
            if name == key:
                found.append(child)
            found.extend(find_values(child, key))

    elif isinstance(value, list):
        for child in value:
            found.extend(find_values(child, key))

    return found


def actor_name(row):
    """Extract a principal name from the normalized user field."""
    user = text(row.get("user"))

    if text(row.get("userType")).lower() == "root" or user == "Root":
        return "Root"

    return user.rsplit("/", 1)[-1] if user else ""


def event_name_matches(actual, expected):
    """Match eventName against a rule's event-name definition."""
    if expected is None or expected == "any":
        return True

    if isinstance(expected, str):
        if expected.lower().startswith("any except "):
            excluded = expected[len("any except "):].strip()
            return text(actual) != excluded

        return text(actual) == expected

    return text(actual) in [text(item) for item in expected]


def has_wildcard_policy(policy):
    """
    Detect Action='*' or Action='iam:*' in an IAM policy.

    CloudTrail may store policyDocument as a JSON string inside
    requestParameters, so parse that inner JSON before inspecting it.
    """
    if isinstance(policy, str):
        try:
            policy = json.loads(policy)
        except (json.JSONDecodeError, TypeError):
            return False

    if not isinstance(policy, dict):
        return False

    statements = policy.get("Statement", [])

    if isinstance(statements, dict):
        statements = [statements]

    if not isinstance(statements, list):
        return False

    for statement in statements:
        if not isinstance(statement, dict):
            continue

        actions = statement.get("Action", [])

        if isinstance(actions, str):
            actions = [actions]

        if not isinstance(actions, list):
            continue

        for action in actions:
            if isinstance(action, str) and action.lower() in {"*", "iam:*"}:
                return True

    return False


def matches_rule(row, rule):
    """Evaluate one event against a single-event rule."""
    rid = rule.get("id", "")

    source = text(row.get("eventSource"))
    name = text(row.get("eventName"))
    user_type = text(row.get("userType")).lower()
    mfa = text(row.get("mfaUsed")).lower()

    params = parse_params(row.get("requestParameters"))
    actor = actor_name(row)
    target = text(get_nested(params, "userName"))
    policy_arn = text(get_nested(params, "policyArn"))

    detection = rule.get("detection", {})
    expected_source = detection.get("eventSource", "any")

    if expected_source not in (None, "any") and source != expected_source:
        return False

    if not event_name_matches(name, detection.get("eventName", "any")):
        return False

    # Unusual access
    if rid == "ACCESS-001":
        return user_type == "root" and name != "ConsoleLogin"

    if rid == "ACCESS-002":
        return (
            source == "signin.amazonaws.com"
            and name == "ConsoleLogin"
            and mfa == "no"
            and not truthy(row.get("is_failure"))
        )

    if rid == "ACCESS-003":
        return (
            source == "signin.amazonaws.com"
            and name == "ConsoleLogin"
            and user_type == "root"
        )

    if rid in {"ACCESS-004", "ACCESS-005"}:
        # These rules are evaluated using time-window counts below.
        return False

    # IAM privilege escalation
    if rid == "IAM-001":
        return (
            source == "iam.amazonaws.com"
            and name in {"PutUserPolicy", "PutRolePolicy"}
            and bool(actor and target)
            and actor == target
            and has_wildcard_policy(
                get_nested(params, "policyDocument")
            )
        )

    if rid == "IAM-002":
        return (
            source == "iam.amazonaws.com"
            and name == "CreateAccessKey"
            and bool(actor and target)
            and actor != target
        )

    if rid == "IAM-003":
        privileged_policies = (
            "AdministratorAccess",
            "IAMFullAccess",
            "PowerUserAccess"
        )

        return (
            source == "iam.amazonaws.com"
            and name in {
                "AttachUserPolicy",
                "AttachRolePolicy",
                "AttachGroupPolicy"
            }
            and any(policy in policy_arn for policy in privileged_policies)
        )

    if rid == "IAM-004":
        set_default = get_nested(params, "setAsDefault")

        return (
            source == "iam.amazonaws.com"
            and name == "CreatePolicyVersion"
            and truthy(set_default)
        )

    if rid == "IAM-005":
        return (
            source == "iam.amazonaws.com"
            and name == "CreateLoginProfile"
        )

    # Logging tampering
    if rid == "LOG-001":
        return (
            source == "cloudtrail.amazonaws.com"
            and name == "StopLogging"
        )

    if rid == "LOG-002":
        return (
            source == "cloudtrail.amazonaws.com"
            and name == "DeleteTrail"
        )

    if rid == "LOG-003":
        return (
            source == "cloudtrail.amazonaws.com"
            and name == "UpdateTrail"
        )

    if rid == "LOG-004":
        return (
            source == "guardduty.amazonaws.com"
            and name == "DeleteDetector"
        )

    # Security-group changes
    if rid == "SG-001":
        public = "0.0.0.0/0" in {
            text(value) for value in find_values(params, "cidrIp")
        }

        sensitive_ports = {
            22, 3389, 3306, 5432, 1433,
            27017, 6379, 9200, 5601
        }

        port_values = find_values(params, "fromPort")

        sensitive_port = any(
            str(value).isdigit() and int(value) in sensitive_ports
            for value in port_values
        )

        return (
            source == "ec2.amazonaws.com"
            and name == "AuthorizeSecurityGroupIngress"
            and public
            and sensitive_port
        )

    if rid == "SG-002":
        public = "0.0.0.0/0" in {
            text(value) for value in find_values(params, "cidrIp")
        }

        all_protocols = "-1" in {
            text(value) for value in find_values(params, "ipProtocol")
        }

        return (
            source == "ec2.amazonaws.com"
            and name == "AuthorizeSecurityGroupIngress"
            and public
            and all_protocols
        )

    if rid == "SG-003":
        return (
            source == "ec2.amazonaws.com"
            and name == "DeleteSecurityGroup"
        )

    return False


def threshold_matches(events, rule):
    """Find failed-login or access-denied bursts exceeding their thresholds."""
    rid = rule.get("id")

    if events.empty or "time" not in events:
        return []

    data = events.copy()
    data["time"] = pd.to_datetime(
        data["time"], utc=True, errors="coerce"
    )
    data = data.dropna(subset=["time"]).sort_values("time")

    if rid == "ACCESS-004":
        failures = data.get(
            "is_failure", pd.Series(False, index=data.index)
        ).map(truthy)

        data = data[
            (data["eventName"] == "ConsoleLogin") & failures
        ]

        groups = ["sourceIP", "user"]
        threshold = 5
        minutes = 10

    elif rid == "ACCESS-005":
        errors = data.get(
            "errorCode", pd.Series("", index=data.index)
        ).fillna("").astype(str)

        data = data[
            errors.str.contains(
                r"UnauthorizedAccess|AccessDenied",
                case=False,
                regex=True
            )
        ]

        groups = ["user"]
        threshold = 10
        minutes = 5

    else:
        return []

    matches = []

    for column in groups:
        if column not in data.columns:
            continue

        valid = data[data[column].fillna("").astype(str).ne("")]

        for group_value, group in valid.groupby(column, sort=False):
            group = group.sort_values("time").reset_index(drop=True)
            start = 0

            while start < len(group):
                end = start + 1

                while (
                    end < len(group)
                    and (
                        group.loc[end, "time"] - group.loc[start, "time"]
                    ).total_seconds() <= minutes * 60
                ):
                    end += 1

                if end - start > threshold:
                    cluster = group.iloc[start:end]

                    matches.append({
                        "rule": rule,
                        "rows": cluster,
                        "time": cluster.iloc[-1]["time"],
                        "user": text(cluster.iloc[-1].get("user")),
                        "sourceIP": text(cluster.iloc[-1].get("sourceIP")),
                        "eventName": text(cluster.iloc[-1].get("eventName")),
                        "count": len(cluster),
                        "group_value": text(group_value),
                        "start_time": cluster.iloc[0]["time"]
                    })

                    start = end
                else:
                    start += 1

    return matches


def mitre_id(rule):
    """Get the MITRE ATT&CK technique ID from a rule definition."""
    return text(rule.get("mitre_attack", {}).get("technique_id", ""))


def raised_severity(severity):
    """Raise severity one level for a strong statistical anomaly."""
    try:
        index = SEVERITIES.index(severity)
        return SEVERITIES[min(index + 1, len(SEVERITIES) - 1)]
    except ValueError:
        return severity or "Medium"


def build_alerts(all_events, suspicious, windows, rules):
    """Build Confirmed, Rule-only, and Needs review alerts."""
    alerts = []
    seen = set()
    suspicious_by_id = {}

    if not suspicious.empty and "eventID" in suspicious.columns:
        for _, row in suspicious.iterrows():
            event_id = text(row.get("eventID"))

            if event_id:
                suspicious_by_id[event_id] = row

    suspicious_ids = set(suspicious_by_id)

    def add(
        row, status, severity, rule, z_peak="", window_id="",
        count=1, description=None, key=None
    ):
        """Append an alert once per user, rule, and evidence window."""
        dedupe = key or (
            text(row.get("user")),
            text(rule.get("id")),
            text(window_id)
        )

        if dedupe in seen:
            return

        seen.add(dedupe)

        alerts.append({
            "alert_id": "",
            "time": text(row.get("time")),
            "status": status,
            "severity": severity,
            "user": text(row.get("user")),
            "sourceIP": text(row.get("sourceIP")),
            "eventName": text(row.get("eventName")),
            "rule_id": text(rule.get("id")),
            "rule_name": text(rule.get("name")),
            "mitre": mitre_id(rule),
            "z_peak": z_peak,
            "window_id": text(window_id),
            "evidence_count": int(count or 1),
            "description": description or text(rule.get("description"))
        })

    # Threshold rules use all events to calculate counts.
    # They are Confirmed only if evidence overlaps the suspicious-event log.
    for rule in rules:
        if rule.get("id") not in {"ACCESS-004", "ACCESS-005"}:
            continue

        for match in threshold_matches(all_events, rule):
            ids = set(
                match["rows"].get(
                    "eventID", pd.Series(dtype=str)
                ).dropna().astype(str)
            )

            overlap = ids & suspicious_ids

            if not overlap:
                continue

            evidence = suspicious_by_id[next(iter(overlap))]
            z = text(evidence.get("z_peak"))
            window_id = text(evidence.get("window_id"))
            severity = rule.get("severity", "Medium")

            try:
                if float(z) > 8:
                    severity = raised_severity(severity)
            except (ValueError, TypeError):
                pass

            minutes = 10 if rule["id"] == "ACCESS-004" else 5

            description = (
                f"{rule.get('description', '')} "
                f"Evidence: {match['count']} matching events for "
                f"{match['group_value']} within {minutes} minutes."
            )

            add(
                {
                    "time": match["time"],
                    "user": match["user"],
                    "sourceIP": match["sourceIP"],
                    "eventName": match["eventName"]
                },
                "Confirmed",
                severity,
                rule,
                z,
                window_id,
                match["count"],
                description,
                key=(
                    match["user"],
                    rule["id"],
                    window_id or str(match["start_time"])
                )
            )

    # Single-event rules run on all events, including events without
    # statistical anomalies, so one-off actions are not missed.
    for _, row in all_events.iterrows():
        event_id = text(row.get("eventID"))

        for rule in rules:
            if rule.get("id") in {"ACCESS-004", "ACCESS-005"}:
                continue

            if not matches_rule(row, rule):
                continue

            suspicious_row = suspicious_by_id.get(event_id)

            if suspicious_row is not None:
                status = "Confirmed"
                z = text(suspicious_row.get("z_peak"))
                window_id = text(suspicious_row.get("window_id"))
                severity = rule.get("severity", "Medium")

                try:
                    if float(z) > 8:
                        severity = raised_severity(severity)
                except (ValueError, TypeError):
                    pass

            else:
                status = "Rule-only"
                z = ""
                window_id = (
                    f"event:{event_id}"
                    if event_id
                    else f"event:{text(row.get('time'))}"
                )
                severity = rule.get("severity", "Medium")

            add(
                row,
                status,
                severity,
                rule,
                z,
                window_id,
                1,
                key=(
                    text(row.get("user")),
                    rule.get("id"),
                    window_id
                )
            )

    # Keep statistical anomalies visible when no rule explains them.
    if not windows.empty:
        for _, window in windows.iterrows():
            window_id = text(window.get("window_id"))

            already_confirmed = any(
                alert["window_id"] == window_id
                and alert["status"] == "Confirmed"
                for alert in alerts
            )

            if already_confirmed:
                continue

            try:
                z = float(window.get("z_peak", 0))
            except (ValueError, TypeError):
                z = 0

            alerts.append({
                "alert_id": "",
                "time": text(
                    window.get("peak_time", window.get("start", ""))
                ),
                "status": "Needs review",
                "severity": "Low" if z < 6 else "Medium",
                "user": "",
                "sourceIP": "",
                "eventName": text(window.get("signal")),
                "rule_id": "",
                "rule_name": "Unmatched statistical anomaly",
                "mitre": "",
                "z_peak": window.get("z_peak", ""),
                "window_id": window_id,
                "evidence_count": int(window.get("peak_count", 1) or 1),
                "description": (
                    f"Statistical anomaly in the "
                    f"{text(window.get('signal'))} signal. "
                    "No selected security rule matched this window; "
                    "review the underlying events."
                )
            })

    result = pd.DataFrame(alerts, columns=COLUMNS)

    if not result.empty:
        result["_rank"] = result["severity"].map(
            {severity: index for index, severity in enumerate(SEVERITIES)}
        ).fillna(0)

        result = (
            result.sort_values(
                ["_rank", "time"],
                ascending=[False, True]
            )
            .drop(columns="_rank")
            .reset_index(drop=True)
        )

        result["alert_id"] = [
            f"CP-{index:04d}"
            for index in range(1, len(result) + 1)
        ]

    return result


def run_rules():
    """Run the rules and save alerts for the dashboard."""
    rules = load_rules()
    all_events = read_csv(ALL_FILE)
    suspicious = read_csv(SUSPICIOUS_FILE)
    windows = read_csv(WINDOWS_FILE)

    if all_events.empty:
        raise FileNotFoundError(
            f"No normalized events found at {ALL_FILE}. "
            "Run the parser and detector first."
        )

    alerts = build_alerts(all_events, suspicious, windows, rules)

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    alerts.to_csv(OUTPUT_FILE, index=False)

    print("CLOUDPULSE RULE ENGINE")
    print(f"Rules loaded: {len(rules)}")
    print(f"Events analysed: {len(all_events):,}")
    print(f"Statistically suspicious events: {len(suspicious):,}")
    print(f"Alerts created: {len(alerts):,}")

    if not alerts.empty:
        print("\nAlerts by status:")
        print(alerts["status"].value_counts().to_string())

        print("\nAlerts by severity:")
        print(alerts["severity"].value_counts().to_string())

    print(f"\nSaved: {OUTPUT_FILE}")
    print("Rule matches are indicators for investigation, not proof of an attack.")

    return alerts


if __name__ == "__main__":
    run_rules()
