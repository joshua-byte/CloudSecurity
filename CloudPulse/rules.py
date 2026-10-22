
"""
CloudPulse rule engine.

Responsibilities:
- Validate and load rules.json.
- Evaluate individual CloudTrail events.
- Detect threshold-based activity bursts.
- Correlate rule matches with statistical evidence.
- Produce explainable, deduplicated alerts.
- Optionally persist alerts to outputs/alerts.csv.

A rule match is not proof of a security incident.
Human confirmation must be supplied separately.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pandas as pd


# ============================================================
# CONFIGURATION
# ============================================================

BASE = Path(__file__).resolve().parent

RULES_FILE = BASE / "rules.json"
ALL_FILE = BASE / "logged" / "normalized_events.csv"
SUSPICIOUS_FILE = BASE / "logged" / "suspicious_events.csv"
WINDOWS_FILE = BASE / "logged" / "anomaly_windows.csv"
OUTPUT_FILE = BASE / "outputs" / "alerts.csv"

SEVERITIES = ["Low", "Medium", "High", "Critical"]

# Preserve the existing output schema for downstream compatibility.
COLUMNS = [
    "alert_id",
    "time",
    "status",
    "severity",
    "user",
    "sourceIP",
    "eventName",
    "rule_id",
    "rule_name",
    "mitre",
    "z_peak",
    "window_id",
    "evidence_count",
    "description",
]

THRESHOLD_RULES = {"ACCESS-004", "ACCESS-005"}

# Preserve the original thresholds: a match requires MORE than
# the specified number of events within the configured period.
DEFAULT_THRESHOLDS = {
    "ACCESS-004": {"count": 5, "minutes": 10},
    "ACCESS-005": {"count": 10, "minutes": 5},
}


# ============================================================
# SAFE VALUE HELPERS
# ============================================================

def text(value: Any) -> str:
    """Convert a scalar to a normalized string."""

    if value is None:
        return ""

    if isinstance(value, (dict, list, tuple, set)):
        return str(value).strip()

    try:
        if pd.isna(value):
            return ""
    except (TypeError, ValueError):
        pass

    result = str(value).strip()

    if result.lower() in {
        "", "none", "null", "nan", "nat", "n/a"
    }:
        return ""

    return result


def truthy(value: Any) -> bool:
    """Interpret common boolean representations."""

    if isinstance(value, bool):
        return value

    return text(value).lower() in {
        "true", "1", "yes", "y"
    }


def parse_params(value: Any) -> dict:
    """Parse requestParameters JSON into a dictionary."""

    if isinstance(value, dict):
        return value

    if not text(value):
        return {}

    try:
        result = json.loads(text(value))
    except (json.JSONDecodeError, TypeError):
        return {}

    return result if isinstance(result, dict) else {}


def get_nested(data: Any, path: str) -> Any:
    """Read a nested dictionary value using a dotted path."""

    current = data

    for part in path.split("."):
        if not isinstance(current, dict):
            return None

        current = current.get(part)

    return current


def find_values(value: Any, key: str) -> list:
    """Find all occurrences of a key in nested dictionaries/lists."""

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


def normalize_event_frame(frame: pd.DataFrame) -> pd.DataFrame:
    """
    Normalize columns used by the rule engine.

    Does not discard events or infer missing event identities.
    """

    if frame is None:
        return pd.DataFrame()

    if not isinstance(frame, pd.DataFrame):
        raise TypeError("Expected a pandas DataFrame.")

    result = frame.copy()

    if not result.columns.is_unique:
        raise ValueError(
            "Input contains duplicate column names."
        )

    aliases = {
        "eventName": ["event_name"],
        "eventSource": ["event_source"],
        "eventID": ["eventId", "event_id"],
        "sourceIP": ["sourceIp", "source_ip", "sourceIPAddress"],
        "userType": ["user_type"],
        "mfaUsed": ["mfa_used"],
        "errorCode": ["error_code"],
        "errorMessage": ["error_message"],
        "requestParameters": ["request_parameters"],
        "is_failure": ["isFailure", "failed"],
    }

    lower_map = {
        str(column).strip().lower(): column
        for column in result.columns
    }

    for canonical, alternatives in aliases.items():
        if canonical in result.columns:
            continue

        for alias in alternatives:
            original = lower_map.get(alias.lower())

            if original is not None:
                result[canonical] = result[original]
                break

    # Fill common optional fields without assuming their values.
    for column in [
        "user",
        "eventName",
        "eventSource",
        "eventID",
        "sourceIP",
        "userType",
        "mfaUsed",
        "errorCode",
        "errorMessage",
        "requestParameters",
    ]:
        if column not in result.columns:
            result[column] = ""

    if "is_failure" not in result.columns:
        result["is_failure"] = False

    result["time"] = pd.to_datetime(
        result["time"] if "time" in result.columns
        else pd.Series(pd.NaT, index=result.index),
        utc=True,
        errors="coerce",
    )

    for column in [
        "user",
        "eventName",
        "eventSource",
        "eventID",
        "sourceIP",
        "userType",
        "mfaUsed",
        "errorCode",
        "errorMessage",
    ]:
        result[column] = result[column].map(text)

    result["is_failure"] = result["is_failure"].map(truthy)

    return result


def read_csv(path: str | Path) -> pd.DataFrame:
    """Read a CSV; return an empty DataFrame if it is absent."""

    path = Path(path)

    if not path.exists():
        return pd.DataFrame()

    try:
        return pd.read_csv(
            path,
            low_memory=False,
        )
    except pd.errors.EmptyDataError:
        return pd.DataFrame()


# ============================================================
# RULE LOADING AND VALIDATION
# ============================================================

def validate_rules(rules: list[dict]) -> list[dict]:
    """Validate the structural integrity of rule definitions."""

    if not isinstance(rules, list) or not rules:
        raise ValueError(
            "rules.json must contain a non-empty 'rules' list."
        )

    seen_ids = set()
    valid_rules = []

    for index, rule in enumerate(rules):
        location = f"rules[{index}]"

        if not isinstance(rule, dict):
            raise ValueError(
                f"{location} must be a JSON object."
            )

        rule_id = text(rule.get("id"))
        rule_name = text(rule.get("name"))

        if not rule_id:
            raise ValueError(
                f"{location} is missing its 'id'."
            )

        if rule_id in seen_ids:
            raise ValueError(
                f"Duplicate rule ID: {rule_id}"
            )

        seen_ids.add(rule_id)

        if not rule_name:
            raise ValueError(
                f"Rule {rule_id} is missing its 'name'."
            )

        severity = text(
            rule.get("severity", "Medium")
        ).title()

        if severity not in SEVERITIES:
            raise ValueError(
                f"Rule {rule_id} has invalid severity "
                f"{severity!r}. Expected one of {SEVERITIES}."
            )

        detection = rule.get("detection", {})

        if detection is None:
            detection = {}

        if not isinstance(detection, dict):
            raise ValueError(
                f"Rule {rule_id}: 'detection' must be an object."
            )

        normalized = dict(rule)
        normalized["id"] = rule_id
        normalized["name"] = rule_name
        normalized["severity"] = severity
        normalized["detection"] = detection

        valid_rules.append(normalized)

    return valid_rules


def load_rules(
    rules_file: str | Path = RULES_FILE,
) -> list[dict]:
    """Load and validate the selected rules from JSON."""

    path = Path(rules_file)

    if not path.is_file():
        raise FileNotFoundError(
            f"Rules file not found: {path}"
        )

    try:
        with path.open(encoding="utf-8") as file:
            data = json.load(file)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"Invalid JSON in {path}: {exc}"
        ) from exc

    if not isinstance(data, dict):
        raise ValueError(
            "rules.json must contain a top-level JSON object."
        )

    return validate_rules(data.get("rules"))


# ============================================================
# EVENT MATCHING HELPERS
# ============================================================

def actor_name(row: Any) -> str:
    """Extract a principal name from a row-like object."""

    user = text(row.get("user"))

    if text(row.get("userType")).lower() == "root":
        return "Root"

    if user.lower() == "root":
        return "Root"

    return user.rsplit("/", 1)[-1] if user else ""


def event_name_matches(
    actual: Any,
    expected: Any,
) -> bool:
    """Match an event name against a rule definition."""

    actual_name = text(actual)

    if expected is None:
        return True

    if isinstance(expected, str):
        if expected.lower() == "any":
            return True

        prefix = "any except "

        if expected.lower().startswith(prefix):
            excluded = expected[len(prefix):].strip()
            return actual_name != excluded

        return actual_name == expected

    if isinstance(expected, list):
        return actual_name in {
            text(item) for item in expected
        }

    return False


def has_wildcard_policy(policy: Any) -> bool:
    """
    Detect Action='*' or Action='iam:*' in a policy document.

    Policy documents may be JSON strings nested inside request
    parameters. Only explicit wildcard actions are matched here.
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
            if (
                isinstance(action, str)
                and action.strip().lower() in {"*", "iam:*"}
            ):
                return True

    return False


def rule_event_source_matches(
    source: str,
    expected: Any,
) -> bool:
    """Match the configured source or allow any source."""

    if expected is None:
        return True

    if isinstance(expected, str) and expected.lower() == "any":
        return True

    if isinstance(expected, list):
        return source in {text(item) for item in expected}

    return source == text(expected)


# ============================================================
# INDIVIDUAL SECURITY RULES
# ============================================================

def matches_rule(
    row: Any,
    rule: dict,
) -> bool:
    """Evaluate one event against a single-event rule."""

    rid = text(rule.get("id"))

    source = text(row.get("eventSource"))
    name = text(row.get("eventName"))
    user_type = text(row.get("userType")).lower()
    mfa = text(row.get("mfaUsed")).lower()

    params = parse_params(row.get("requestParameters"))

    actor = actor_name(row)
    target = text(get_nested(params, "userName"))
    policy_arn = text(get_nested(params, "policyArn"))

    detection = rule.get("detection", {})

    if not rule_event_source_matches(
        source,
        detection.get("eventSource", "any"),
    ):
        return False

    if not event_name_matches(
        name,
        detection.get("eventName", "any"),
    ):
        return False

    # ACCESS: root and authentication activity.
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

    # Evaluated by the threshold engine, not per event.
    if rid in THRESHOLD_RULES:
        return False

    # IAM: privilege escalation and credential changes.
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
        privileged_policies = {
            "AdministratorAccess",
            "IAMFullAccess",
            "PowerUserAccess",
        }

        return (
            source == "iam.amazonaws.com"
            and name in {
                "AttachUserPolicy",
                "AttachRolePolicy",
                "AttachGroupPolicy",
            }
            and any(
                policy in policy_arn
                for policy in privileged_policies
            )
        )

    if rid == "IAM-004":
        return (
            source == "iam.amazonaws.com"
            and name == "CreatePolicyVersion"
            and truthy(get_nested(params, "setAsDefault"))
        )

    if rid == "IAM-005":
        return (
            source == "iam.amazonaws.com"
            and name == "CreateLoginProfile"
        )

    # LOGGING: changes that can reduce visibility.
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

    # SECURITY GROUPS.
    if rid in {"SG-001", "SG-002"}:
        if (
            source != "ec2.amazonaws.com"
            or name != "AuthorizeSecurityGroupIngress"
        ):
            return False

        public_ipv4 = "0.0.0.0/0" in {
            text(value)
            for value in find_values(params, "cidrIp")
        }

        public_ipv6 = "::/0" in {
            text(value)
            for value in find_values(params, "cidrIpv6")
        }

        if rid == "SG-002":
            all_protocols = "-1" in {
                text(value)
                for value in find_values(params, "ipProtocol")
            }

            return (
                (public_ipv4 or public_ipv6)
                and all_protocols
            )

        sensitive_ports = {
            22, 3389, 3306, 5432, 1433,
            27017, 6379, 9200, 5601,
        }

        port_values = find_values(params, "fromPort")

        sensitive_port = any(
            str(value).strip().isdigit()
            and int(str(value).strip()) in sensitive_ports
            for value in port_values
        )

        return (
            (public_ipv4 or public_ipv6)
            and sensitive_port
        )

    if rid == "SG-003":
        return (
            source == "ec2.amazonaws.com"
            and name == "DeleteSecurityGroup"
        )

    # Unknown IDs must not silently match.
    return False


# ============================================================
# THRESHOLD-BASED DETECTION
# ============================================================

def threshold_matches(
    events: pd.DataFrame,
    rule: dict,
) -> list[dict]:
    """
    Find failed-login or access-denied bursts.

    Uses sliding windows. Missing grouping identities are not
    replaced with a shared empty-string identity.

    Existing threshold semantics are preserved:
    ACCESS-004: more than 5 events in 10 minutes.
    ACCESS-005: more than 10 events in 5 minutes.
    """

    rid = text(rule.get("id"))

    if rid not in THRESHOLD_RULES or events.empty:
        return []

    data = normalize_event_frame(events)

    data = data.dropna(subset=["time"]).copy()

    if data.empty:
        return []

    defaults = DEFAULT_THRESHOLDS[rid]

    config = rule.get("threshold", {})

    if not isinstance(config, dict):
        config = {}

    count_threshold = int(
        config.get("count", defaults["count"])
    )

    minutes = int(
        config.get("minutes", defaults["minutes"])
    )

    if count_threshold < 1 or minutes < 1:
        raise ValueError(
            f"Invalid threshold configuration for {rid}."
        )

    if rid == "ACCESS-004":
        data = data[
            data["eventName"].eq("ConsoleLogin")
            & data["is_failure"]
        ].copy()

        # Group by the composite identity, not separately by
        # user and IP, which can produce ambiguous duplicate bursts.
        data["_identity"] = list(zip(
            data["sourceIP"],
            data["user"],
        ))

        data = data[
            data["sourceIP"].ne("")
            & data["user"].ne("")
        ].copy()

        identity_column = "_identity"

    else:
        data["_error"] = (
            data["errorCode"].fillna("").astype(str)
        )

        data = data[
            data["_error"].str.contains(
                r"UnauthorizedAccess|AccessDenied",
                case=False,
                regex=True,
                na=False,
            )
        ].copy()

        data = data[data["user"].ne("")].copy()
        identity_column = "user"

    if data.empty:
        return []

    data = data.sort_values("time", kind="stable")
    matches = []

    duration = pd.Timedelta(minutes=minutes)

    for identity, group in data.groupby(
        identity_column,
        sort=False,
    ):
        group = group.sort_values(
            "time",
            kind="stable",
        ).reset_index(drop=True)

        times = group["time"]

        left = 0

        for right in range(len(group)):
            while (
                left <= right
                and times.iloc[right] - times.iloc[left] > duration
            ):
                left += 1

            count = right - left + 1

            if count <= count_threshold:
                continue

            cluster = group.iloc[left:right + 1]

            # Emit one alert per distinct event set. This prevents
            # one large burst from generating a row per event.
            event_ids = sorted({
                text(value)
                for value in cluster["eventID"]
                if text(value)
            })

            identity_key = repr(identity)

            matches.append({
                "rule": rule,
                "rows": cluster.copy(),
                "time": cluster.iloc[-1]["time"],
                "user": text(cluster.iloc[-1].get("user")),
                "sourceIP": text(cluster.iloc[-1].get("sourceIP")),
                "eventName": text(cluster.iloc[-1].get("eventName")),
                "count": len(cluster),
                "group_value": identity_key,
                "start_time": cluster.iloc[0]["time"],
                "event_ids": event_ids,
            })

            # Advance to the end of this emitted cluster so the
            # same burst is not repeatedly emitted for every row.
            left = right + 1

    return matches


# ============================================================
# STATISTICAL EVIDENCE CORRELATION
# ============================================================

def mitre_id(rule: dict) -> str:
    """Return the ATT&CK technique ID if present."""

    attack = rule.get("mitre_attack", {})

    if not isinstance(attack, dict):
        return ""

    return text(attack.get("technique_id"))


def raised_severity(severity: str) -> str:
    """Raise a valid severity by one level."""

    normalized = text(severity).title()

    if normalized not in SEVERITIES:
        normalized = "Medium"

    index = SEVERITIES.index(normalized)

    return SEVERITIES[
        min(index + 1, len(SEVERITIES) - 1)
    ]


def normalize_window_ids(value: Any) -> list[str]:
    """Parse single or semicolon-separated anomaly window IDs."""

    if isinstance(value, list):
        values = value
    else:
        values = text(value).split(";")

    return sorted({
        text(item)
        for item in values
        if text(item)
    })


def make_event_evidence_index(
    suspicious: pd.DataFrame,
) -> dict[str, list[dict]]:
    """
    Map each event ID to all associated anomaly evidence.

    Duplicate IDs are retained as multiple evidence records
    instead of silently overwriting one another.
    """

    evidence_index: dict[str, list[dict]] = {}

    if suspicious.empty or "eventID" not in suspicious.columns:
        return evidence_index

    for _, row in suspicious.iterrows():
        event_id = text(row.get("eventID"))

        if not event_id:
            continue

        try:
            z_peak = float(row.get("z_peak", row.get(
                "anomaly_peak_z", 0
            )))
        except (TypeError, ValueError):
            z_peak = 0.0

        if not pd.notna(z_peak):
            z_peak = 0.0

        windows = normalize_window_ids(
            row.get(
                "window_id",
                row.get("anomaly_window_ids", ""),
            )
        )

        evidence_index.setdefault(
            event_id,
            [],
        ).append({
            "z_peak": z_peak,
            "window_ids": windows,
            "event": row,
        })

    return evidence_index


# ============================================================
# ALERT GENERATION
# ============================================================

def build_alerts(
    all_events: pd.DataFrame,
    suspicious: pd.DataFrame,
    windows: pd.DataFrame,
    rules: list[dict],
    *,
    confirmed_event_ids: set[str] | None = None,
) -> pd.DataFrame:
    """
    Build Rule match, Confirmed, and Needs review alerts.

    'Confirmed' is only used when an event ID is explicitly
    supplied in confirmed_event_ids. Statistical overlap alone
    never confirms an incident.
    """

    all_events = normalize_event_frame(all_events)

    suspicious = (
        suspicious.copy()
        if isinstance(suspicious, pd.DataFrame)
        else pd.DataFrame()
    )

    windows = (
        windows.copy()
        if isinstance(windows, pd.DataFrame)
        else pd.DataFrame()
    )

    rules = validate_rules(rules)

    confirmed_event_ids = {
        text(event_id)
        for event_id in (confirmed_event_ids or set())
        if text(event_id)
    }

    evidence_index = make_event_evidence_index(suspicious)

    alerts: list[dict] = []
    seen: set[tuple] = set()

    def add_alert(
        *,
        row: Any,
        status: str,
        severity: str,
        rule: dict | None,
        z_peak: Any = "",
        window_ids: list[str] | None = None,
        evidence_count: int = 1,
        description: str = "",
        dedupe_key: tuple | None = None,
    ) -> None:
        """Append an alert once per stable evidence identity."""

        rule = rule or {}
        window_ids = sorted(set(window_ids or []))

        if dedupe_key is None:
            dedupe_key = (
                text(rule.get("id")),
                tuple(window_ids),
                text(row.get("eventID")),
                text(row.get("time")),
            )

        if dedupe_key in seen:
            return

        seen.add(dedupe_key)

        try:
            z_value = float(z_peak)
            if not pd.notna(z_value):
                z_value = ""
        except (TypeError, ValueError):
            z_value = ""

        alerts.append({
            "alert_id": "",
            "time": text(row.get("time")),
            "status": status,
            "severity": text(severity).title() or "Medium",
            "user": text(row.get("user")),
            "sourceIP": text(row.get("sourceIP")),
            "eventName": text(row.get("eventName")),
            "rule_id": text(rule.get("id")),
            "rule_name": text(
                rule.get("name")
                or "Unmatched statistical anomaly"
            ),
            "mitre": mitre_id(rule),
            "z_peak": z_value,
            "window_id": "; ".join(window_ids),
            "evidence_count": max(1, int(evidence_count or 1)),
            "description": description or text(
                rule.get("description")
            ),
        })

    def evidence_for_ids(
        event_ids: list[str],
    ) -> list[dict]:
        result = []

        for event_id in event_ids:
            result.extend(
                evidence_index.get(event_id, [])
            )

        return result

    # --------------------------------------------------------
    # A. Threshold-based rules
    # --------------------------------------------------------

    for rule in rules:
        if rule.get("id") not in THRESHOLD_RULES:
            continue

        for match in threshold_matches(all_events, rule):
            event_ids = match.get("event_ids", [])
            evidence = evidence_for_ids(event_ids)

            windows_for_match = sorted({
                window_id
                for item in evidence
                for window_id in item["window_ids"]
            })

            z_peak = max(
                (
                    abs(item["z_peak"])
                    for item in evidence
                ),
                default=0.0,
            )

            matched_confirmed_ids = (
                set(event_ids) & confirmed_event_ids
            )

            if matched_confirmed_ids:
                status = "Confirmed"
            else:
                status = "Rule match"

            severity = text(
                rule.get("severity", "Medium")
            ).title()

            if z_peak > 8:
                severity = raised_severity(severity)

            minutes = DEFAULT_THRESHOLDS[
                rule["id"]
            ]["minutes"]

            description = (
                f"{text(rule.get('description'))} "
                f"Evidence: {match['count']} matching events "
                f"within {minutes} minutes for "
                f"{match['group_value']}. "
                f"Statistical overlap: "
                f"{'yes' if evidence else 'no'}."
            ).strip()

            add_alert(
                row={
                    "time": match["time"],
                    "user": match["user"],
                    "sourceIP": match["sourceIP"],
                    "eventName": match["eventName"],
                    "eventID": (
                        event_ids[-1] if event_ids else ""
                    ),
                },
                status=status,
                severity=severity,
                rule=rule,
                z_peak=z_peak if evidence else "",
                window_ids=windows_for_match,
                evidence_count=match["count"],
                description=description,
                dedupe_key=(
                    rule["id"],
                    match["group_value"],
                    text(match["start_time"]),
                    tuple(event_ids),
                ),
            )

    # --------------------------------------------------------
    # B. Individual-event rules
    # --------------------------------------------------------

    single_event_rules = [
        rule for rule in rules
        if rule.get("id") not in THRESHOLD_RULES
    ]

    for _, row in all_events.iterrows():
        event_id = text(row.get("eventID"))

        for rule in single_event_rules:
            if not matches_rule(row, rule):
                continue

            evidence = evidence_index.get(event_id, [])

            windows_for_match = sorted({
                window_id
                for item in evidence
                for window_id in item["window_ids"]
            })

            z_peak = max(
                (
                    abs(item["z_peak"])
                    for item in evidence
                ),
                default=0.0,
            )

            if event_id and event_id in confirmed_event_ids:
                status = "Confirmed"
            else:
                status = "Rule match"

            severity = text(
                rule.get("severity", "Medium")
            ).title()

            if evidence and z_peak > 8:
                severity = raised_severity(severity)

            if evidence:
                description = (
                    f"{text(rule.get('description'))} "
                    "A matching statistical anomaly is also present; "
                    "investigate the underlying event evidence."
                ).strip()
            else:
                description = (
                    f"{text(rule.get('description'))} "
                    "The rule matched, but no correlated statistical "
                    "anomaly was found."
                ).strip()

            add_alert(
                row=row,
                status=status,
                severity=severity,
                rule=rule,
                z_peak=z_peak if evidence else "",
                window_ids=windows_for_match,
                evidence_count=1,
                description=description,
                dedupe_key=(
                    rule["id"],
                    event_id or text(row.get("time")),
                    tuple(windows_for_match),
                ),
            )

    # --------------------------------------------------------
    # C. Statistical anomalies without a matching rule
    # --------------------------------------------------------

    if not windows.empty:
        for _, window in windows.iterrows():
            window_id = text(window.get("window_id"))

            # Do not suppress an anomaly merely because some
            # unrelated rule match occurred in the same window.
            already_explained = any(
                window_id
                and window_id in normalize_window_ids(
                    alert.get("window_id")
                )
                and alert.get("rule_id")
                for alert in alerts
            )

            if already_explained:
                continue

            try:
                z_peak = float(window.get("z_peak", 0))
            except (TypeError, ValueError):
                z_peak = 0.0

            if not pd.notna(z_peak):
                z_peak = 0.0

            severity = "Low" if abs(z_peak) < 6 else "Medium"

            start = text(window.get("start"))
            peak_time = text(
                window.get("peak_time")
            ) or start

            signal = text(window.get("signal"))

            add_alert(
                row={
                    "time": peak_time,
                    "user": "",
                    "sourceIP": "",
                    "eventName": signal,
                    "eventID": "",
                },
                status="Needs review",
                severity=severity,
                rule={
                    "id": "",
                    "name": "Unmatched statistical anomaly",
                    "description": (
                        "A statistical anomaly has no associated "
                        "matching security rule."
                    ),
                },
                z_peak=z_peak,
                window_ids=[window_id] if window_id else [],
                evidence_count=int(
                    window.get("peak_count", 1) or 1
                ),
                description=(
                    f"Statistical anomaly in the {signal} signal. "
                    f"Start: {start}. "
                    "Review the underlying events before drawing "
                    "a security conclusion."
                ),
                dedupe_key=(
                    "ANOMALY",
                    window_id or start,
                    signal,
                ),
            )

    # --------------------------------------------------------
    # D. Stable output schema and sorting
    # --------------------------------------------------------

    result = pd.DataFrame(
        alerts,
        columns=COLUMNS,
    )

    if result.empty:
        return result

    severity_rank = {
        severity: index
        for index, severity in enumerate(SEVERITIES)
    }

    result["_rank"] = (
        result["severity"]
        .map(severity_rank)
        .fillna(0)
    )

    result["_time"] = pd.to_datetime(
        result["time"],
        utc=True,
        errors="coerce",
    )

    result = (
        result.sort_values(
            ["_rank", "_time", "rule_id"],
            ascending=[False, True, True],
            kind="stable",
            na_position="last",
        )
        .drop(columns=["_rank", "_time"])
        .reset_index(drop=True)
    )

    result["alert_id"] = [
        f"CP-{index:04d}"
        for index in range(1, len(result) + 1)
    ]

    return result[COLUMNS]


# ============================================================
# FILE-BASED ENTRY POINT
# ============================================================

def run_rules(
    all_events_file: str | Path = ALL_FILE,
    suspicious_file: str | Path = SUSPICIOUS_FILE,
    windows_file: str | Path = WINDOWS_FILE,
    rules_file: str | Path = RULES_FILE,
    output_file: str | Path = OUTPUT_FILE,
) -> pd.DataFrame:
    """Load analysis artifacts, build alerts, and save the result."""

    rules = load_rules(rules_file)

    all_events = read_csv(all_events_file)
    suspicious = read_csv(suspicious_file)
    windows = read_csv(windows_file)

    if all_events.empty:
        raise FileNotFoundError(
            f"No normalized events found at {all_events_file}. "
            "Run the parser and detector first."
        )

    alerts = build_alerts(
        all_events,
        suspicious,
        windows,
        rules,
    )

    output_path = Path(output_file)
    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    alerts.to_csv(
        output_path,
        index=False,
    )

    print("\nCLOUDPULSE RULE ENGINE")
    print("=" * 32)
    print(f"Rules loaded: {len(rules)}")
    print(f"Events analysed: {len(all_events):,}")
    print(f"Statistically suspicious rows: {len(suspicious):,}")
    print(f"Alerts created: {len(alerts):,}")

    if not alerts.empty:
        print("\nAlerts by status:")
        print(alerts["status"].value_counts().to_string())

        print("\nAlerts by severity:")
        print(alerts["severity"].value_counts().to_string())

    print(f"\nSaved: {output_path}")
    print(
        "Rule matches and statistical anomalies are investigation "
        "indicators, not proof of an attack."
    )

    return alerts


if __name__ == "__main__":
    run_rules()
