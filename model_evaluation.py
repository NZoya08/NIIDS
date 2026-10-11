import os

import joblib
import pandas as pd

from sklearn.model_selection import train_test_split

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)


# ============================================================
# PROJECT PATH
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)


# ============================================================
# DATASET
# ============================================================

DATASET_PATH = os.path.join(
    BASE_DIR,
    "data",
    "KDDTrain+.txt"
)


# ============================================================
# MODEL FILES
# ============================================================

MODEL_PATH = os.path.join(
    BASE_DIR,
    "models",
    "intrusion_model.pkl"
)

SCALER_PATH = os.path.join(
    BASE_DIR,
    "models",
    "scaler.pkl"
)

PROTOCOL_ENCODER_PATH = os.path.join(
    BASE_DIR,
    "models",
    "protocol_encoder.pkl"
)

SERVICE_ENCODER_PATH = os.path.join(
    BASE_DIR,
    "models",
    "service_encoder.pkl"
)

FLAG_ENCODER_PATH = os.path.join(
    BASE_DIR,
    "models",
    "flag_encoder.pkl"
)

LABEL_ENCODER_PATH = os.path.join(
    BASE_DIR,
    "models",
    "label_encoder.pkl"
)


# ============================================================
# NSL-KDD COLUMNS
# ============================================================

COLUMNS = [

    "duration",

    "protocol_type",

    "service",

    "flag",

    "src_bytes",

    "dst_bytes",

    "land",

    "wrong_fragment",

    "urgent",

    "hot",

    "num_failed_logins",

    "logged_in",

    "num_compromised",

    "root_shell",

    "su_attempted",

    "num_root",

    "num_file_creations",

    "num_shells",

    "num_access_files",

    "num_outbound_cmds",

    "is_host_login",

    "is_guest_login",

    "count",

    "srv_count",

    "serror_rate",

    "srv_serror_rate",

    "rerror_rate",

    "srv_rerror_rate",

    "same_srv_rate",

    "diff_srv_rate",

    "srv_diff_host_rate",

    "dst_host_count",

    "dst_host_srv_count",

    "dst_host_same_srv_rate",

    "dst_host_diff_srv_rate",

    "dst_host_same_src_port_rate",

    "dst_host_srv_diff_host_rate",

    "dst_host_serror_rate",

    "dst_host_srv_serror_rate",

    "dst_host_rerror_rate",

    "dst_host_srv_rerror_rate",

    "label",

    "difficulty"
]


# ============================================================
# FEATURE ORDER
# ============================================================

FEATURE_ORDER = [

    "duration",

    "protocol_type",

    "service",

    "flag",

    "src_bytes",

    "dst_bytes",

    "land",

    "wrong_fragment",

    "urgent",

    "hot",

    "num_failed_logins",

    "logged_in",

    "num_compromised",

    "root_shell",

    "su_attempted",

    "num_root",

    "num_file_creations",

    "num_shells",

    "num_access_files",

    "num_outbound_cmds",

    "is_host_login",

    "is_guest_login",

    "count",

    "srv_count",

    "serror_rate",

    "srv_serror_rate",

    "rerror_rate",

    "srv_rerror_rate",

    "same_srv_rate",

    "diff_srv_rate",

    "srv_diff_host_rate",

    "dst_host_count",

    "dst_host_srv_count",

    "dst_host_same_srv_rate",

    "dst_host_diff_srv_rate",

    "dst_host_same_src_port_rate",

    "dst_host_srv_diff_host_rate",

    "dst_host_serror_rate",

    "dst_host_srv_serror_rate",

    "dst_host_rerror_rate",

    "dst_host_srv_rerror_rate",

    "difficulty"
]


# ============================================================
# LOAD MODEL COMPONENTS
# ============================================================

def load_components():

    print(
        "Loading model components..."
    )

    model = joblib.load(
        MODEL_PATH
    )

    scaler = joblib.load(
        SCALER_PATH
    )

    protocol_encoder = joblib.load(
        PROTOCOL_ENCODER_PATH
    )

    service_encoder = joblib.load(
        SERVICE_ENCODER_PATH
    )

    flag_encoder = joblib.load(
        FLAG_ENCODER_PATH
    )

    label_encoder = joblib.load(
        LABEL_ENCODER_PATH
    )

    return (
        model,
        scaler,
        protocol_encoder,
        service_encoder,
        flag_encoder,
        label_encoder
    )


# ============================================================
# ATTACK CATEGORY MAPPING
# ============================================================

DOS_ATTACKS = {

    "back",
    "land",
    "neptune",
    "pod",
    "smurf",
    "teardrop"
}


PROBE_ATTACKS = {

    "ipsweep",
    "nmap",
    "portsweep",
    "satan"
}


R2L_ATTACKS = {

    "ftp_write",
    "guess_passwd",
    "imap",
    "multihop",
    "phf",
    "spy",
    "warezclient",
    "warezmaster"
}


U2R_ATTACKS = {

    "buffer_overflow",
    "loadmodule",
    "perl",
    "rootkit"
}


def classify_attack(
    attack_name
):

    attack_name = str(
        attack_name
    ).strip().lower()

    if attack_name == "normal":

        return "Normal"

    if attack_name in DOS_ATTACKS:

        return "DoS"

    if attack_name in PROBE_ATTACKS:

        return "Probe"

    if attack_name in R2L_ATTACKS:

        return "R2L"

    if attack_name in U2R_ATTACKS:

        return "U2R"

    return "Unknown"


# ============================================================
# EVALUATE MODEL
# ============================================================

def evaluate_model():

    # --------------------------------------------------------
    # LOAD COMPONENTS
    # --------------------------------------------------------

    (
        model,
        scaler,
        protocol_encoder,
        service_encoder,
        flag_encoder,
        label_encoder
    ) = load_components()

    # --------------------------------------------------------
    # LOAD DATASET
    # --------------------------------------------------------

    print(
        "Loading KDDTrain+.txt..."
    )

    data = pd.read_csv(
        DATASET_PATH,
        names=COLUMNS
    )

    print(
        "Dataset shape:",
        data.shape
    )

    # --------------------------------------------------------
    # ENCODE CATEGORICAL FEATURES
    # --------------------------------------------------------

    data["protocol_type"] = (
        protocol_encoder.transform(
            data["protocol_type"]
        )
    )

    data["service"] = (
        service_encoder.transform(
            data["service"]
        )
    )

    data["flag"] = (
        flag_encoder.transform(
            data["flag"]
        )
    )

    # --------------------------------------------------------
    # ENCODE LABEL
    # --------------------------------------------------------

    data["label"] = (
        label_encoder.transform(
            data["label"]
        )
    )

    # --------------------------------------------------------
    # FEATURES / TARGET
    # --------------------------------------------------------

    X = data.drop(
        "label",
        axis=1
    )

    y = data["label"]

    # --------------------------------------------------------
    # 80/20 HOLD-OUT SPLIT
    # --------------------------------------------------------

    (
        X_train,
        X_test,
        y_train,
        y_test
    ) = train_test_split(

        X,

        y,

        test_size=0.20,

        random_state=42,

        stratify=y
    )

    # --------------------------------------------------------
    # FEATURE ORDER
    # --------------------------------------------------------

    X_test = X_test[
        FEATURE_ORDER
    ]

    # --------------------------------------------------------
    # SCALE
    # --------------------------------------------------------

    X_test_scaled = scaler.transform(
        X_test
    )

    # --------------------------------------------------------
    # PREDICTION
    # --------------------------------------------------------

    y_pred = model.predict(
        X_test_scaled
    )

    # --------------------------------------------------------
    # DECODE LABELS
    # --------------------------------------------------------

    actual_names = (
        label_encoder.inverse_transform(
            y_test
        )
    )

    predicted_names = (
        label_encoder.inverse_transform(
            y_pred
        )
    )

    actual_names = [

        str(value).strip().lower()

        for value in actual_names
    ]

    predicted_names = [

        str(value).strip().lower()

        for value in predicted_names
    ]

    # ========================================================
    # BINARY NORMAL VS ATTACK
    # ========================================================

    actual_binary = [

        "Normal"
        if value == "normal"
        else "Attack"

        for value in actual_names
    ]

    predicted_binary = [

        "Normal"
        if value == "normal"
        else "Attack"

        for value in predicted_names
    ]

    # --------------------------------------------------------
    # BINARY METRICS
    # --------------------------------------------------------

    binary_accuracy = accuracy_score(
        actual_binary,
        predicted_binary
    )

    binary_precision = precision_score(
        actual_binary,
        predicted_binary,
        pos_label="Attack",
        zero_division=0
    )

    binary_recall = recall_score(
        actual_binary,
        predicted_binary,
        pos_label="Attack",
        zero_division=0
    )

    binary_f1 = f1_score(
        actual_binary,
        predicted_binary,
        pos_label="Attack",
        zero_division=0
    )

    # --------------------------------------------------------
    # BINARY CONFUSION MATRIX
    # --------------------------------------------------------

    binary_cm = confusion_matrix(

        actual_binary,

        predicted_binary,

        labels=[
            "Normal",
            "Attack"
        ]
    )

    # ========================================================
    # MULTI-CLASS METRICS
    # ========================================================

    multiclass_accuracy = accuracy_score(
        y_test,
        y_pred
    )

    multiclass_precision = precision_score(
        y_test,
        y_pred,
        average="weighted",
        zero_division=0
    )

    multiclass_recall = recall_score(
        y_test,
        y_pred,
        average="weighted",
        zero_division=0
    )

    multiclass_f1 = f1_score(
        y_test,
        y_pred,
        average="weighted",
        zero_division=0
    )

    # --------------------------------------------------------
    # MULTI-CLASS CONFUSION MATRIX
    # --------------------------------------------------------

    model_classes = [

        str(value)

        for value in label_encoder.classes_
    ]

    multiclass_cm = confusion_matrix(

        y_test,

        y_pred,

        labels=list(
            range(
                len(model_classes)
            )
        )
    )

    # ========================================================
    # ATTACK CATEGORIES
    # ========================================================

    actual_categories = [

        classify_attack(
            value
        )

        for value in actual_names
    ]

    predicted_categories = [

        classify_attack(
            value
        )

        for value in predicted_names
    ]

    category_labels = [

        "Normal",

        "DoS",

        "Probe",

        "R2L",

        "U2R"
    ]

    # --------------------------------------------------------
    # CATEGORY CONFUSION MATRIX
    # --------------------------------------------------------

    category_cm = confusion_matrix(

        actual_categories,

        predicted_categories,

        labels=category_labels
    )

    # --------------------------------------------------------
    # CATEGORY REPORT
    # --------------------------------------------------------

    category_report = classification_report(

        actual_categories,

        predicted_categories,

        labels=category_labels,

        target_names=category_labels,

        output_dict=True,

        zero_division=0
    )

    # ========================================================
    # PREDICTED DISTRIBUTION
    # ========================================================

    distribution = {}

    for category in category_labels:

        distribution[category] = (
            predicted_categories.count(
                category
            )
        )

    # ========================================================
    # RETURN RESULTS
    # ========================================================

    return {

        "dataset":
            "KDDTrain+ 80/20 Hold-out Test Set",

        "total_samples":
            int(len(data)),

        "test_samples":
            int(len(y_test)),

        "binary_accuracy":
            float(binary_accuracy),

        "binary_precision":
            float(binary_precision),

        "binary_recall":
            float(binary_recall),

        "binary_f1":
            float(binary_f1),

        "accuracy":
            float(multiclass_accuracy),

        "precision":
            float(multiclass_precision),

        "recall":
            float(multiclass_recall),

        "f1_score":
            float(multiclass_f1),

        "binary_confusion_matrix":
            binary_cm.tolist(),

        "multiclass_confusion_matrix":
            multiclass_cm.tolist(),

        "model_classes":
            model_classes,

        "category_confusion_matrix":
            category_cm.tolist(),

        "category_labels":
            category_labels,

        "category_report":
            category_report,

        "predicted_distribution":
            distribution
    }


# ============================================================
# DISPLAY RESULTS
# ============================================================

def display_results(
    results
):

    print(
        "\n" + "=" * 60
    )

    print(
        "NIDS MODEL EVALUATION"
    )

    print(
        "=" * 60
    )

    print(
        "\nDataset:",
        results["dataset"]
    )

    print(
        "Total Dataset Samples:",
        results["total_samples"]
    )

    print(
        "Test Samples:",
        results["test_samples"]
    )

    # ========================================================
    # BINARY METRICS
    # ========================================================

    print(
        "\n========== BINARY METRICS =========="
    )

    print(
        f"Accuracy : "
        f"{results['binary_accuracy'] * 100:.2f}%"
    )

    print(
        f"Precision: "
        f"{results['binary_precision'] * 100:.2f}%"
    )

    print(
        f"Recall   : "
        f"{results['binary_recall'] * 100:.2f}%"
    )

    print(
        f"F1 Score : "
        f"{results['binary_f1'] * 100:.2f}%"
    )

    # ========================================================
    # BINARY CONFUSION MATRIX
    # ========================================================

    print(
        "\n========== BINARY CONFUSION MATRIX =========="
    )

    print(
        pd.DataFrame(

            results[
                "binary_confusion_matrix"
            ],

            index=[
                "Actual Normal",
                "Actual Attack"
            ],

            columns=[
                "Predicted Normal",
                "Predicted Attack"
            ]
        )
    )

    # ========================================================
    # MULTI-CLASS METRICS
    # ========================================================

    print(
        "\n========== MULTI-CLASS METRICS =========="
    )

    print(
        f"Accuracy : "
        f"{results['accuracy'] * 100:.2f}%"
    )

    print(
        f"Precision: "
        f"{results['precision'] * 100:.2f}%"
    )

    print(
        f"Recall   : "
        f"{results['recall'] * 100:.2f}%"
    )

    print(
        f"F1 Score : "
        f"{results['f1_score'] * 100:.2f}%"
    )

    # ========================================================
    # MODEL CLASSES
    # ========================================================

    print(
        "\n========== MODEL CLASSES =========="
    )

    for value in results["model_classes"]:

        print(
            "-",
            value
        )

    # ========================================================
    # CATEGORY CONFUSION MATRIX
    # ========================================================

    print(
        "\n========== CATEGORY CONFUSION MATRIX =========="
    )

    print(
        pd.DataFrame(

            results[
                "category_confusion_matrix"
            ],

            index=results[
                "category_labels"
            ],

            columns=results[
                "category_labels"
            ]
        )
    )

    # ========================================================
    # CATEGORY REPORT
    # ========================================================

    print(
        "\n========== CATEGORY PERFORMANCE =========="
    )

    category_report = results[
        "category_report"
    ]

    for category in results[
        "category_labels"
    ]:

        if category not in category_report:

            continue

        metrics = category_report[
            category
        ]

        print(
            f"\n{category}"
        )

        print(
            f"  Precision: "
            f"{metrics['precision'] * 100:.2f}%"
        )

        print(
            f"  Recall   : "
            f"{metrics['recall'] * 100:.2f}%"
        )

        print(
            f"  F1 Score : "
            f"{metrics['f1-score'] * 100:.2f}%"
        )

    # ========================================================
    # DISTRIBUTION
    # ========================================================

    print(
        "\n========== PREDICTED CATEGORY DISTRIBUTION =========="
    )

    for category, count in (
        results[
            "predicted_distribution"
        ].items()
    ):

        print(
            f"{category}: {count}"
        )

    print(
        "\n" + "=" * 60
    )

    print(
        "EVALUATION COMPLETE"
    )

    print(
        "=" * 60
    )


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    try:

        results = evaluate_model()

        display_results(
            results
        )

    except FileNotFoundError as err:

        print(
            "\nFile error:"
        )

        print(err)

    except Exception as err:

        print(
            "\nEvaluation error:"
        )

        print(err)