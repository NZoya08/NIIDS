# Network Intrusion Detection System (NIDS)

## 1. Project Overview

This repository contains a Python-based Network Intrusion Detection System (NIDS) that captures live network traffic, groups packets into flow records, converts those records into NSL-KDD-style features, and passes the resulting feature vectors to a saved machine learning model for intrusion detection.

The project follows a practical detection workflow implemented directly in the codebase:

- live packets are captured with Scapy;
- IPv4 traffic is converted into flow records;
- flow records are mapped into the NSL-KDD-style feature structure used during model training;
- categorical fields are encoded and numerical values are scaled;
- the saved model predicts whether traffic is normal or an attack label;
- the predicted attack name is mapped to a category such as Normal, DoS, Probe, R2L, or U2R;
- the result is stored in MySQL and, for non-normal predictions, a HIGH alert is created.

This is a research-oriented and academic-style implementation built around the NSL-KDD dataset and a saved scikit-learn model.

## 2. Project Objectives

The implemented system aims to:

- train and save an intrusion detection model using the NSL-KDD/KDDTrain+ dataset;
- process live traffic into flow-based features compatible with the trained model;
- distinguish normal traffic from attack traffic using the saved ML model;
- classify detected attack names into category labels (Normal, DoS, Probe, R2L, U2R);
- compute confidence values from the model probability output when available;
- log intrusion detection results in MySQL;
- generate alert records for non-normal predictions;
- evaluate the trained model on a hold-out dataset and report the measured performance.

## 3. Key Features

The following features are implemented in the repository:

- live packet capture using Scapy;
- flow-level network feature extraction from captured packets;
- model-based intrusion prediction using a saved scikit-learn classifier;
- attack category classification using the repository mapping logic;
- confidence calculation based on the model probability output when supported;
- MySQL logging for intrusion detection records;
- automatic alert generation for non-normal predictions;
- model evaluation using the KDDTrain+ hold-out test split.

## 4. System Architecture

The project flow implemented in the repository is:

Network Traffic
→ Scapy Packet Capture
→ Feature Extraction
→ Feature Encoding / Scaling
→ ML Model
→ Attack Prediction
→ Category Classification
→ MySQL Logging
→ Alert Generation

```mermaid
flowchart LR
    A[Network Traffic] --> B[Scapy Packet Capture]
    B --> C[Feature Extraction]
    C --> D[Feature Encoding / Scaling]
    D --> E[ML Model]
    E --> F[Attack Prediction]
    F --> G[Category Classification]
    G --> H[MySQL Logging]
    H --> I[Alert Generation]
```

## 5. Technologies Used

The repository uses the following technologies and libraries present in the implementation:

- Python
- Scapy
- Pandas
- scikit-learn
- Joblib
- MySQL
- mysql-connector-python
- NSL-KDD

## 6. Dataset

The project is built around the NSL-KDD dataset representation and the training/evaluation file currently used by the code:

- `data/KDDTrain+.txt`

The repository also contains `data/nsl_kdd.csv`, but the active training and evaluation paths in the project currently read `data/KDDTrain+.txt`.

The model input is a 41-feature NSL-KDD-style feature vector. The feature order used by `modules/ml_prediction.py` and `train_model.py` is:

- `duration`
- `protocol_type`
- `service`
- `flag`
- `src_bytes`
- `dst_bytes`
- `land`
- `wrong_fragment`
- `urgent`
- `hot`
- `num_failed_logins`
- `logged_in`
- `num_compromised`
- `root_shell`
- `su_attempted`
- `num_root`
- `num_file_creations`
- `num_shells`
- `num_access_files`
- `num_outbound_cmds`
- `is_host_login`
- `is_guest_login`
- `count`
- `srv_count`
- `serror_rate`
- `srv_serror_rate`
- `rerror_rate`
- `srv_rerror_rate`
- `same_srv_rate`
- `diff_srv_rate`
- `srv_diff_host_rate`
- `dst_host_count`
- `dst_host_srv_count`
- `dst_host_same_srv_rate`
- `dst_host_diff_srv_rate`
- `dst_host_same_src_port_rate`
- `dst_host_srv_diff_host_rate`
- `dst_host_serror_rate`
- `dst_host_srv_serror_rate`
- `dst_host_rerror_rate`
- `dst_host_srv_rerror_rate`
- `difficulty`

## 7. Machine Learning Model

The repository saves and loads the following model artifacts from `models/`:

- `intrusion_model.pkl`
- `scaler.pkl`
- `protocol_encoder.pkl`
- `service_encoder.pkl`
- `flag_encoder.pkl`
- `label_encoder.pkl`

The training script, `train_model.py`, shows that the project trains a scikit-learn `RandomForestClassifier` and saves the serialized model and the supporting preprocessing objects.

The runtime prediction pipeline in `modules/ml_prediction.py` performs the following steps:

1. loads the trained model and preprocessing objects;
2. validates that the input DataFrame contains the required model features;
3. encodes the categorical fields `protocol_type`, `service`, and `flag` using the saved encoders;
4. fills any missing numerical features with default values for fields not available from live traffic;
5. reorders the DataFrame to match the training feature order;
6. scales the feature data with the saved `StandardScaler`;
7. calls `model.predict()` to obtain the attack label ID;
8. converts the label ID back with `label_encoder.inverse_transform()`;
9. computes a confidence value using `model.predict_proba()` when the model supports it.

The code also maps an attack name to a category via `classify_attack()` in `modules/ml_prediction.py`.

## 8. Feature Extraction

The flow-feature construction logic is implemented in `modules/feature_extraction.py`.

Important implementation points:

- only IPv4 packets are processed;
- packets are grouped into flows using source IP, destination IP, protocol, source port, and destination port;
- a service mapping is applied based on destination port values such as `ftp`, `ssh`, `http`, `domain`, `mysql`, and `other`;
- TCP flag values are translated to NSL-KDD-style states such as `S0`, `S1`, `SF`, `REJ`, and `OTH`;
- packet counts, byte totals, SYN, ACK, RST, and FIN counters are accumulated per flow;
- rates such as `serror_rate`, `rerror_rate`, and associated destination-host rates are approximated from packet counts and TCP flags.

Several NSL-KDD fields are not directly available from live packets and are therefore assigned defaults in the implementation, including many `num_*` counters and destination-host statistics. This is a deliberate part of the project and is documented in the code as an approximation of the NSL-KDD feature set.

## 9. Attack Categories

The repository implements the following attack categories:

- Normal
- DoS
- Probe
- R2L
- U2R

The actual attack-name-to-category mapping used in the code is:

- DoS: `back`, `land`, `neptune`, `pod`, `smurf`, `teardrop`
- Probe: `ipsweep`, `nmap`, `portsweep`, `satan`
- R2L: `ftp_write`, `guess_passwd`, `imap`, `multihop`, `phf`, `spy`, `warezclient`, `warezmaster`
- U2R: `buffer_overflow`, `loadmodule`, `perl`, `rootkit`

If no category matches, the code returns `Unknown`.

## 10. Live Detection

The live detection workflow is implemented in `modules/live_detection.py` and `modules/live_capture.py`.

The sequence is:

1. `capture_live_packets()` calls `scapy.all.sniff()`;
2. captured packets are processed through `extract_features()`;
3. feature rows are created for usable IPv4 flows;
4. the feature DataFrame is passed to `predict_attack_with_confidence()`;
5. the model returns the predicted label and confidence value;
6. the result is displayed in the console and saved to the database;
7. non-normal predictions are treated as attack detections and trigger alert creation.

The actual Windows command used to run live detection from the repository root is:

```powershell
python .\modules\live_detection.py
```

The project also includes a lightweight live capture test in `test_live_prediction.py`.

## 11. Database and Logging

The project uses MySQL with the database name `nids_db`, as configured in `modules/db_manager.py` and created in `database/schema.sql`.

The schema defines the following tables:

- `users`
- `intrusion_logs`
- `alerts`

The core detection logging tables used by the runtime flow are:

`intrusion_logs`

- `log_id` — primary key
- `timestamp` — detection time
- `source_ip` — source IP
- `destination_ip` — destination IP
- `protocol` — protocol string such as `tcp`, `udp`, or `icmp`
- `prediction` — attack name predicted by the model
- `confidence` — confidence value produced by the model

`alerts`

- `alert_id` — primary key
- `log_id` — foreign key to `intrusion_logs.log_id`
- `alert_level` — alert level, currently set to `HIGH`
- `message` — alert message
- `alert_time` — alert creation time

The database implementation is in `modules/db_manager.py` and the schema is in `database/schema.sql`.

## 12. Alert System

The alert system is implemented in `modules/db_manager.py` inside `process_prediction()`.

When a prediction is not exactly `normal`:

- the intrusion log is inserted into `intrusion_logs`;
- the corresponding alert record is created in `alerts`;
- `alert_level` is set to `HIGH`;
- the message is created as `Malicious activity detected: <prediction>`.

Each alert is associated with its originating detection record through `alerts.log_id`, which references `intrusion_logs.log_id`.

## 13. Model Evaluation

The project evaluates the saved model using the `KDDTrain+ 80/20 Hold-out Test Set` via `modules/model_evaluation.py`.

The actual results produced by the current repository are:

### Binary evaluation

- Accuracy: 99.93%
- Precision: 99.98%
- Recall: 99.86%
- F1 Score: 99.92%

### Multi-class evaluation

- Accuracy: 99.90%
- Precision: 99.88%
- Recall: 99.90%
- F1 Score: 99.89%

### Category performance

| Category | Precision | Recall | F1 |
| --- | ---: | ---: | ---: |
| Normal | 99.88% | 99.99% | 99.93% |
| DoS | 99.99% | 99.99% | 99.99% |
| Probe | 99.96% | 99.79% | 99.87% |
| R2L | 100.00% | 96.48% | 98.21% |
| U2R | 85.71% | 60.00% | 70.59% |

### Binary confusion matrix

```text
                Predicted Normal    Predicted Attack
Actual Normal        13467                 2
Actual Attack           16             11710
```

### Category confusion matrix

```text
        Normal   DoS  Probe  R2L  U2R
Normal   13467     1      1    0    0
DoS          1  9184      0    0    0
Probe        5     0   2327    0    0
R2L          6     0      0  192    1
U2R          4     0      0    0    6
```

These are hold-out evaluation results on the NSL-KDD/KDDTrain+ dataset. They are not evidence of equivalent real-world network detection accuracy, and they should not be interpreted as real-world deployment performance.

## 14. Example Output

The project contains a successful live detection example with the following behavior:

- Packets captured: 30
- Flows analyzed: 3

Example detections included:

- ICMP traffic from `10.63.133.187` to `8.8.8.8` → normal
- UDP traffic from `10.63.133.92` to `224.0.0.251` → normal
- ICMP traffic from `8.8.8.8` to `10.63.133.187` → normal

The repository does not expose additional private/network-specific details beyond these example values.

## 15. Installation

The repository includes a project `requirements.txt` listing the third-party packages used by the implementation.

The project depends on the following Python packages:

- scapy
- pandas
- scikit-learn
- joblib
- mysql-connector-python
- flask
- flask-cors
- streamlit

Recommended Windows setup:

```powershell
python -m venv venv
.\venv\Scripts\activate
python -m pip install --upgrade pip
python -m pip install -r .\requirements.txt
```

The project also expects the following files to be present in the repository:

- `data/KDDTrain+.txt`
- `models/intrusion_model.pkl`
- `models/scaler.pkl`
- `models/protocol_encoder.pkl`
- `models/service_encoder.pkl`
- `models/flag_encoder.pkl`
- `models/label_encoder.pkl`

If these model files are missing, they can be generated with:

```powershell
python .\train_model.py
```

## 16. MySQL Setup

The project uses MySQL with a database named `nids_db`.

The schema is located at `database/schema.sql` and creates the database and required tables.

To initialize the database from the MySQL CLI:

```powershell
mysql -u root -p
```

Then run:

```sql
CREATE DATABASE IF NOT EXISTS nids_db;
USE nids_db;
SOURCE database\schema.sql;
```

The schema creates:

```sql
CREATE TABLE users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) NOT NULL,
    password VARCHAR(255) NOT NULL
);

CREATE TABLE intrusion_logs (
    log_id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    source_ip VARCHAR(50),
    destination_ip VARCHAR(50),
    protocol VARCHAR(20),
    prediction VARCHAR(50),
    confidence FLOAT
);

CREATE TABLE alerts (
    alert_id INT AUTO_INCREMENT PRIMARY KEY,
    log_id INT,
    alert_level VARCHAR(20),
    message TEXT,
    alert_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (log_id)
        REFERENCES intrusion_logs(log_id)
);
```

## 17. Running the Project

The repository includes the following entry points and commands.

### Model evaluation

```powershell
python .\modules\model_evaluation.py
```

### Live packet capture

```powershell
python .\modules\live_capture.py
```

### Live AI detection

```powershell
python .\modules\live_detection.py
```

### Flask API

```powershell
python .\app.py
```

### Streamlit dashboard

```powershell
streamlit run .\streamlit_app.py
```

## 18. MySQL Verification

Useful SQL checks for the running database are:

```sql
SHOW DATABASES;
USE nids_db;
SHOW TABLES;
SELECT COUNT(*) FROM intrusion_logs;
SELECT COUNT(*) FROM alerts;
SELECT * FROM intrusion_logs ORDER BY timestamp DESC LIMIT 10;
SELECT * FROM alerts ORDER BY alert_time DESC LIMIT 10;
SELECT * FROM intrusion_logs WHERE prediction <> 'normal' ORDER BY timestamp DESC LIMIT 10;
```

These commands help verify the current database state, intrusion log records, and generated alerts.

## 19. Project Structure

The repository currently contains the following structure:

```text
NIDS_Project/
├── README.md
├── app.py
├── requirements.txt
├── streamlit_app.py
├── test_live_prediction.py
├── test_nids.pcap
├── train_model.py
├── data/
│   ├── KDDTrain+.txt
│   └── nsl_kdd.csv
├── database/
│   └── schema.sql
├── models/
│   ├── flag_encoder.pkl
│   ├── intrusion_model.pkl
│   ├── label_encoder.pkl
│   ├── protocol_encoder.pkl
│   ├── scaler.pkl
│   └── service_encoder.pkl
├── modules/
│   ├── __init__.py
│   ├── db_manager.py
│   ├── feature_extraction.py
│   ├── live_capture.py
│   ├── live_detection.py
│   ├── ml_prediction.py
│   ├── model_evaluation.py
│   ├── packet_capture.py
│   └── pcap_reader.py
├── venv/
└── __pycache__/
```

## 20. Limitations

This implementation should be understood as an academic project prototype rather than a production-grade intrusion detection system.

Relevant limitations in the repository include:

- live packet features are approximations of the NSL-KDD feature set, because not every required NSL-KDD feature is directly available from live packets;
- missing NSL-KDD features are assigned defaults in the feature extraction logic;
- evaluation results are based on a hold-out split from the NSL-KDD/KDDTrain+ dataset and are not evidence of equivalent real-world network detection accuracy;
- confidence values are model-derived probability outputs and are not guaranteed to be calibrated as real-world probabilities;
- the live detection workflow is constrained by the limitations of packet-based feature approximation;
- U2R performance is weaker than the other categories in the reported hold-out evaluation;
- packet capture may require appropriate permissions and, on Windows, Npcap or equivalent packet-capture support.

## 21. Future Improvements

The following are realistic future improvements, not implemented features in the current repository:

- richer live flow aggregation to better approximate NSL-KDD features;
- improved handling of the NSL-KDD/live-feature mismatch;
- evaluation on additional datasets beyond KDDTrain+;
- improved U2R and R2L detection performance;
- dashboard and UI improvements;
- continuous monitoring and configurable alert thresholds;
- stronger validation on real network traffic and longer capture windows.

## 22. Conclusion

This project implements a practical machine-learning-based NIDS that combines live packet capture, feature extraction, model inference, category assignment, MySQL persistence, and alert generation. The codebase is organized around the NSL-KDD/KDDTrain+ dataset and a saved scikit-learn RandomForest model, with evaluation results reported through `modules/model_evaluation.py`.

The reported metrics are strong on the benchmark dataset used in this project, but they should be interpreted as hold-out evaluation results on NSL-KDD/KDDTrain+, not as proof of equivalent real-world detection performance. The repository provides a useful research and teaching implementation, but it should be considered a prototype rather than a fully validated production deployment.

## 23. Security / Credential Note

Database credentials must not be committed to GitHub. The repository should be configured with secure local credentials, preferably through environment variables or a local configuration file excluded from version control.

The project includes environment-variable support in `modules/db_manager.py` and `streamlit_app.py` for values such as `NIDS_DB_HOST`, `NIDS_DB_USER`, `NIDS_DB_PASSWORD`, and `NIDS_DB_NAME`. A safe template is provided in `.env.example` and should be copied to a local environment file that is not committed to version control.

Do not commit live credentials, local connection strings, or secret values to the repository.
