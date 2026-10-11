import os
import joblib
import pandas as pd


# ============================================================
# PROJECT PATH
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)


# ============================================================
# MODEL PATHS
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
# EXACT 41 FEATURES USED BY THE MODEL
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

def load_model_components():

    try:

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

    except FileNotFoundError as exc:

        raise FileNotFoundError(
            "\nModel file not found.\n"
            f"Please check your models folder:\n"
            f"{os.path.join(BASE_DIR, 'models')}\n\n"
            f"Missing file: {exc}"
        ) from exc

    except Exception as exc:

        raise RuntimeError(
            f"Unable to load NIDS model components: {exc}"
        ) from exc


# ============================================================
# LOAD EVERYTHING
# ============================================================

(
    model,
    scaler,
    protocol_encoder,
    service_encoder,
    flag_encoder,
    label_encoder
) = load_model_components()


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


# ============================================================
# CLASSIFY ATTACK CATEGORY
# ============================================================

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
# GET ENCODER CLASSES
# ============================================================

def get_encoder_classes(
    encoder
):

    if hasattr(
        encoder,
        "classes_"
    ):

        return [
            str(value)
            for value in encoder.classes_
        ]

    return []


# ============================================================
# SAFE CATEGORICAL ENCODING
# ============================================================

def encode_column(
    df,
    column,
    encoder,
    lowercase=False
):

    values = df[column].astype(str)

    # --------------------------------------------------------
    # Normalization
    # --------------------------------------------------------

    if lowercase:

        values = (
            values
            .str.strip()
            .str.lower()
        )

    else:

        values = (
            values
            .str.strip()
        )

    # --------------------------------------------------------
    # Encoder classes
    # --------------------------------------------------------

    known_classes = get_encoder_classes(
        encoder
    )

    # --------------------------------------------------------
    # If encoder has known classes, normalize input to match
    # the exact saved encoder representation.
    # --------------------------------------------------------

    if known_classes:

        class_map = {
            str(value).lower(): value
            for value in encoder.classes_
        }

        normalized_values = []

        for value in values:

            key = str(
                value
            ).strip().lower()

            if key in class_map:

                normalized_values.append(
                    class_map[key]
                )

            else:

                raise ValueError(
                    "\nUnknown "
                    f"{column} value encountered.\n"
                    f"Value: {value}\n"
                    f"Known values: {known_classes}"
                )

        values = pd.Series(
            normalized_values,
            index=df.index
        )

    # --------------------------------------------------------
    # Transform
    # --------------------------------------------------------

    try:

        encoded = encoder.transform(
            values
        )

    except Exception as exc:

        raise ValueError(
            f"\nEncoding failed for '{column}'.\n"
            f"Values received: "
            f"{values.unique().tolist()}\n"
            f"Known encoder values: "
            f"{known_classes}\n"
            f"Original error: {exc}"
        ) from exc

    df[column] = encoded

    return df


# ============================================================
# ENCODE ALL CATEGORICAL FEATURES
# ============================================================

def encode_features(df):

    df = df.copy()

    required_columns = [

        "protocol_type",
        "service",
        "flag"
    ]

    # --------------------------------------------------------
    # Check columns
    # --------------------------------------------------------

    for column in required_columns:

        if column not in df.columns:

            raise ValueError(
                f"Missing categorical feature: {column}"
            )

    # --------------------------------------------------------
    # Protocol
    # --------------------------------------------------------

    df = encode_column(
        df,
        "protocol_type",
        protocol_encoder,
        lowercase=True
    )

    # --------------------------------------------------------
    # Service
    # --------------------------------------------------------

    df = encode_column(
        df,
        "service",
        service_encoder,
        lowercase=True
    )

    # --------------------------------------------------------
    # Flag
    #
    # Case-insensitive matching means both:
    #
    # sf -> SF
    # s0 -> S0
    # s1 -> S1
    #
    # will work with the saved encoder.
    # --------------------------------------------------------

    df = encode_column(
        df,
        "flag",
        flag_encoder,
        lowercase=False
    )

    return df


# ============================================================
# NUMERICAL DEFAULTS
# ============================================================

NUMERICAL_DEFAULTS = {

    "duration": 0,

    "src_bytes": 0,
    "dst_bytes": 0,

    "land": 0,
    "wrong_fragment": 0,
    "urgent": 0,
    "hot": 0,

    "num_failed_logins": 0,
    "logged_in": 0,
    "num_compromised": 0,
    "root_shell": 0,
    "su_attempted": 0,
    "num_root": 0,

    "num_file_creations": 0,
    "num_shells": 0,
    "num_access_files": 0,
    "num_outbound_cmds": 0,

    "is_host_login": 0,
    "is_guest_login": 0,

    "count": 0,
    "srv_count": 0,

    "serror_rate": 0,
    "srv_serror_rate": 0,

    "rerror_rate": 0,
    "srv_rerror_rate": 0,

    "same_srv_rate": 0,
    "diff_srv_rate": 0,
    "srv_diff_host_rate": 0,

    "dst_host_count": 0,
    "dst_host_srv_count": 0,

    "dst_host_same_srv_rate": 0,
    "dst_host_diff_srv_rate": 0,

    "dst_host_same_src_port_rate": 0,

    "dst_host_srv_diff_host_rate": 0,

    "dst_host_serror_rate": 0,
    "dst_host_srv_serror_rate": 0,

    "dst_host_rerror_rate": 0,
    "dst_host_srv_rerror_rate": 0,

    "difficulty": 0
}


# ============================================================
# PREPARE FEATURES
# ============================================================

def prepare_features(df):

    if df is None:

        raise ValueError(
            "Input dataframe is None."
        )

    if df.empty:

        raise ValueError(
            "Input dataframe is empty."
        )

    df = df.copy()

    # --------------------------------------------------------
    # Encode categorical features
    # --------------------------------------------------------

    df = encode_features(
        df
    )

    # --------------------------------------------------------
    # Add missing numerical features
    # --------------------------------------------------------

    for feature, default in (
        NUMERICAL_DEFAULTS.items()
    ):

        if feature not in df.columns:

            df[feature] = default

    # --------------------------------------------------------
    # Keep ONLY model features
    # --------------------------------------------------------

    missing_features = [

        feature
        for feature in FEATURE_ORDER
        if feature not in df.columns
    ]

    if missing_features:

        raise ValueError(
            "Missing required model features: "
            f"{missing_features}"
        )

    df = df[
        FEATURE_ORDER
    ]

    # --------------------------------------------------------
    # Convert to numeric
    # --------------------------------------------------------

    for column in FEATURE_ORDER:

        df[column] = pd.to_numeric(
            df[column],
            errors="coerce"
        )

    # --------------------------------------------------------
    # Replace NaN / infinity
    # --------------------------------------------------------

    df = df.replace(
        [float("inf"), float("-inf")],
        0
    )

    df = df.fillna(
        0
    )

    return df


# ============================================================
# SCALE FEATURES
# ============================================================

def scale_features(df):

    try:

        prepared = prepare_features(
            df
        )

        scaled = scaler.transform(
            prepared
        )

        return scaled

    except Exception as exc:

        raise ValueError(
            f"Feature scaling failed: {exc}"
        ) from exc


# ============================================================
# PREDICT ATTACK
# ============================================================

def predict_attack(df):

    scaled_data = scale_features(
        df
    )

    prediction = model.predict(
        scaled_data
    )

    attack_names = (
        label_encoder.inverse_transform(
            prediction
        )
    )

    categories = [

        classify_attack(
            name
        )

        for name in attack_names
    ]

    return (
        attack_names,
        categories
    )


# ============================================================
# PREDICT ATTACK WITH CONFIDENCE
# ============================================================

def predict_attack_with_confidence(df):

    scaled_data = scale_features(
        df
    )

    # --------------------------------------------------------
    # Model prediction
    # --------------------------------------------------------

    prediction = model.predict(
        scaled_data
    )

    # --------------------------------------------------------
    # Confidence
    # --------------------------------------------------------

    if hasattr(
        model,
        "predict_proba"
    ):

        probabilities = model.predict_proba(
            scaled_data
        )

        confidence = probabilities.max(
            axis=1
        )

    else:

        confidence = [
            0.0
            for _ in prediction
        ]

    # --------------------------------------------------------
    # Decode label
    # --------------------------------------------------------

    attack_names = (
        label_encoder.inverse_transform(
            prediction
        )
    )

    # --------------------------------------------------------
    # Categories
    # --------------------------------------------------------

    categories = [

        classify_attack(
            name
        )

        for name in attack_names
    ]

    return (
        attack_names,
        categories,
        confidence
    )


# ============================================================
# MODEL INFORMATION
# ============================================================

def get_model_info():

    return {

        "model_type":
            type(model).__name__,

        "feature_count":
            len(FEATURE_ORDER),

        "classes":
            [
                str(value)
                for value
                in label_encoder.classes_
            ],

        "feature_order":
            FEATURE_ORDER,

        "protocol_values":
            get_encoder_classes(
                protocol_encoder
            ),

        "service_values":
            get_encoder_classes(
                service_encoder
            ),

        "flag_values":
            get_encoder_classes(
                flag_encoder
            )
    }


# ============================================================
# DIRECT TEST
# ============================================================

if __name__ == "__main__":

    print("=" * 60)
    print("NIDS ML PREDICTION MODULE")
    print("=" * 60)

    info = get_model_info()

    print(
        "\nModel:",
        info["model_type"]
    )

    print(
        "Feature count:",
        info["feature_count"]
    )

    print(
        "\nModel classes:"
    )

    for value in info["classes"]:

        print(
            "  ",
            value
        )

    print(
        "\nProtocol encoder values:"
    )

    for value in info["protocol_values"]:

        print(
            "  ",
            value
        )

    print(
        "\nService encoder values:"
    )

    for value in info["service_values"]:

        print(
            "  ",
            value
        )

    print(
        "\nFlag encoder values:"
    )

    for value in info["flag_values"]:

        print(
            "  ",
            value
        )

    print(
        "\nModel prediction module loaded successfully."
    )

    print("=" * 60)