
"""Convert CloudTrail JSON logs to CSV using user-provided paths."""

import gzip
import json
from pathlib import Path

import pandas as pd


def load_records(file_path):
    """Load CloudTrail records from JSON or compressed JSON."""

    if file_path.suffix == ".gz":
        with gzip.open(file_path, "rt", encoding="utf-8-sig") as file:
            data = json.load(file)
    else:
        with file_path.open("r", encoding="utf-8-sig") as file:
            data = json.load(file)

    if isinstance(data, dict):
        records = data.get("Records", [])
    elif isinstance(data, list):
        records = data
    else:
        raise ValueError("Unsupported JSON structure.")

    if not isinstance(records, list):
        raise ValueError("CloudTrail Records must be a list.")

    return records


def flatten_event(event, source_file):
    """Extract useful CloudTrail fields."""

    identity = event.get("userIdentity") or {}
    additional = event.get("additionalEventData") or {}
    session_context = identity.get("sessionContext") or {}
    session_issuer = session_context.get("sessionIssuer") or {}

    def json_field(value):
        return json.dumps(value, ensure_ascii=False) if value is not None else None

    return {
        "eventTime": event.get("eventTime"),
        "eventName": event.get("eventName"),
        "eventSource": event.get("eventSource"),
        "awsRegion": event.get("awsRegion"),
        "eventID": event.get("eventID"),
        "eventType": event.get("eventType"),
        "eventCategory": event.get("eventCategory"),
        "readOnly": event.get("readOnly"),
        "sourceIPAddress": event.get("sourceIPAddress"),
        "userAgent": event.get("userAgent"),
        "userIdentityType": identity.get("type"),
        "userIdentityArn": identity.get("arn"),
        "userName": identity.get("userName"),
        "principalId": identity.get("principalId"),
        "accountId": identity.get("accountId"),
        "sessionIssuerArn": session_issuer.get("arn"),
        "mfaUsed": additional.get("MFAUsed") or additional.get("mfaUsed"),
        "errorCode": event.get("errorCode"),
        "errorMessage": event.get("errorMessage"),
        "requestParameters": json_field(event.get("requestParameters")),
        "responseElements": json_field(event.get("responseElements")),
        "resources": json_field(event.get("resources")),
        "sourceFile": source_file,
        "rawEvent": json.dumps(event, ensure_ascii=False),
    }


def main():
    print("CloudTrail JSON to CSV Converter")
    print("-" * 32)

    input_text = input("Enter the path to your JSON file: ").strip().strip('"')
    input_path = Path(input_text)

    if not input_path.is_file():
        print(f"Error: File not found: {input_path}")
        return

    output_text = input(
        "Enter the output CSV path (press Enter for same folder): "
    ).strip().strip('"')

    if output_text:
        output_path = Path(output_text)
        if output_path.suffix.lower() != ".csv":
            output_path = output_path.with_suffix(".csv")
    else:
        output_path = input_path.parent / f"{input_path.stem}.csv"

    try:
        records = load_records(input_path)

        rows = [
            flatten_event(event, input_path.name)
            for event in records
            if isinstance(event, dict)
        ]

        if not rows:
            print("No event records found in the JSON file.")
            return

        df = pd.DataFrame(rows)
        df["eventTime"] = pd.to_datetime(
            df["eventTime"], utc=True, errors="coerce"
        )
        df = df.sort_values("eventTime", na_position="last")

        output_path.parent.mkdir(parents=True, exist_ok=True)
        df.to_csv(output_path, index=False, encoding="utf-8-sig")

        print("\nConversion successful!")
        print(f"Events exported: {len(df):,}")
        print(f"Columns: {len(df.columns)}")
        print(f"Output file: {output_path.resolve()}")

        print("\nFirst five events:")
        print(
            df[["eventTime", "eventName", "eventSource",
                "sourceIPAddress", "errorCode"]]
            .head()
            .to_string(index=False)
        )

    except (json.JSONDecodeError, OSError, ValueError) as error:
        print(f"Conversion failed: {error}")


if __name__ == "__main__":
    main()
