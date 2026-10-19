# CloudPulse
Local CloudTrail log analysis, statistical anomaly detection, and explainable security rules.

## Install
```powershell
python -m pip install -r requirements.txt
```

## Run
```powershell
streamlit run app.py
```
Upload CloudTrail `.json`, `.json.gz`, or flattened `.csv`, or use `data/cloudpulse.csv`. Click **Run analysis** to generate detection artifacts and alerts, then download a CSV or HTML report.

## Main files
- `app.py` — Streamlit dashboard and one-click pipeline
- `json_to_csv.py` — CloudTrail JSON flattening
- `detection_engine.py` — statistical anomaly detection
- `rules.py` and `rules.json` — security rules
- `report.py` — HTML investigation report
- `data/` — input datasets and current analysis input
- `logged/` — normalized events, signals, anomaly windows, suspicious events
- `outputs/` — alerts and generated reports

All processing is local. No AWS credentials or external API calls are required.
