import os
import joblib
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report


# ==========================================
# 1. NSL-KDD COLUMN NAMES
# ==========================================

columns = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins",
    "logged_in", "num_compromised", "root_shell", "su_attempted",
    "num_root", "num_file_creations", "num_shells", "num_access_files",
    "num_outbound_cmds", "is_host_login", "is_guest_login", "count",
    "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate",
    "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
    "label", "difficulty"
]


# ==========================================
# 2. LOAD DATASET
# ==========================================

dataset_path = "data/KDDTrain+.txt"

print("Loading dataset...")

data = pd.read_csv(
    dataset_path,
    names=columns
)

print("Dataset loaded successfully!")
print("Shape:", data.shape)


# ==========================================
# 3. CREATE MODELS DIRECTORY
# ==========================================

os.makedirs("models", exist_ok=True)


# ==========================================
# 4. ENCODE CATEGORICAL FEATURES
# ==========================================

protocol_encoder = LabelEncoder()
service_encoder = LabelEncoder()
flag_encoder = LabelEncoder()
label_encoder = LabelEncoder()


data["protocol_type"] = protocol_encoder.fit_transform(
    data["protocol_type"]
)

data["service"] = service_encoder.fit_transform(
    data["service"]
)

data["flag"] = flag_encoder.fit_transform(
    data["flag"]
)

data["label"] = label_encoder.fit_transform(
    data["label"]
)


# ==========================================
# 5. SAVE ENCODERS
# ==========================================

joblib.dump(
    protocol_encoder,
    "models/protocol_encoder.pkl"
)

joblib.dump(
    service_encoder,
    "models/service_encoder.pkl"
)

joblib.dump(
    flag_encoder,
    "models/flag_encoder.pkl"
)

joblib.dump(
    label_encoder,
    "models/label_encoder.pkl"
)

print("Encoders saved.")


# ==========================================
# 6. FEATURES AND TARGET
# ==========================================

X = data.drop("label", axis=1)
y = data["label"]


# ==========================================
# 7. TRAIN / TEST SPLIT
# ==========================================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print("Training samples:", X_train.shape)
print("Testing samples:", X_test.shape)


# ==========================================
# 8. SCALE FEATURES
# ==========================================

scaler = StandardScaler()

X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

joblib.dump(
    scaler,
    "models/scaler.pkl"
)

print("Scaler saved.")


# ==========================================
# 9. TRAIN RANDOM FOREST
# ==========================================

print("Training Random Forest...")

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    n_jobs=-1
)

model.fit(X_train, y_train)

print("Training completed!")


# ==========================================
# 10. TEST MODEL
# ==========================================

y_pred = model.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)

print("\nAccuracy:", round(accuracy * 100, 2), "%")

print("\nClassification Report:")
print(
    classification_report(
        y_test,
        y_pred,
        zero_division=0
    )
)


# ==========================================
# 11. SAVE MODEL
# ==========================================

joblib.dump(
    model,
    "models/intrusion_model.pkl"
)

print("\nModel saved successfully!")


# ==========================================
# 12. DISPLAY LABELS
# ==========================================

print("\nAttack labels known by the model:")

for label in label_encoder.classes_:
    print(" -", label)

print("\nALL TRAINING COMPLETE!")