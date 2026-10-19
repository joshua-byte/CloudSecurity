# CloudPulse

**Local AWS CloudTrail log analysis with statistical anomaly detection and explainable security rules.**

CloudPulse analyses CloudTrail event logs to identify unusual activity and potentially suspicious cloud operations. It combines statistical anomaly detection with configurable security rules to generate alerts supported by relevant event evidence.

## Features

- **CloudTrail log processing** — supports JSON, compressed JSON (`.json.gz`), and flattened CSV input.
- **Statistical anomaly detection** — identifies unusual patterns in event activity.
- **Rule-based detection** — evaluates events against configurable security rules defined in `rules.json`.
- **Explainable alerts** — provides rule-based findings and evidence to support investigation.
- **Interactive dashboard** — reviews analysis results, anomalies, and generated alerts.
- **Report generation** — exports alerts as CSV and produces an HTML investigation report.
- **Local processing** — runs locally without requiring AWS credentials or external API calls.

## Getting Started

### 1. Clone the repository

```powershell
git clone <repository-url>
cd CloudPulse
```

### 2. Create and activate a virtual environment

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```powershell
python -m pip install -r requirements.txt
```

### 4. Launch the dashboard

```powershell
streamlit run app.py
```

Open the local URL displayed in the terminal.

## Detection Approach

CloudPulse uses two complementary approaches:

- **Statistical detection:** identifies activity that deviates from the detector's configured baseline or thresholds.
- **Rule-based detection:** identifies events matching explicitly defined security conditions.

These findings serve as investigation leads, not definitive proof of malicious activity. An anomaly may be legitimate, and a rule match requires context before an incident can be confirmed.

## Scope and Limitations

CloudPulse is a local log-analysis tool. It analyses the supplied data rather than monitoring an AWS account in real time.

Detection quality depends on the available CloudTrail fields, configured rules, statistical thresholds, and the activity represented in the input dataset. Findings should be validated before taking remediation action.

## Contributors

- [Your GitHub Username](https://github.com/joshua-byte)
- [Second Contributor](https://github.com/Freya135)
- [Second Contributor](https://github.com/anusree-krishnan)
