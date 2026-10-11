import os
import subprocess
import sys

import mysql.connector
from mysql.connector import Error
import pandas as pd
import streamlit as st


# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="NIDS | AI Network Security",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ============================================================
# PROJECT PATHS
# ============================================================

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))

LIVE_DETECTION_SCRIPT = os.path.join(
    PROJECT_ROOT,
    "modules",
    "live_detection.py",
)

MODEL_PATH = os.path.join(
    PROJECT_ROOT,
    "models",
    "intrusion_model.pkl",
)

DATASET_PATH = os.path.join(
    PROJECT_ROOT,
    "data",
    "KDDTrain+.txt",
)


# ============================================================
# DATABASE CONFIG
# ============================================================

DB_HOST = os.getenv("NIDS_DB_HOST", "localhost")
DB_USER = os.getenv("NIDS_DB_USER", "root")
DB_PASSWORD = os.getenv("NIDS_DB_PASSWORD")
DB_NAME = os.getenv(
    "NIDS_DB_NAME",
    "nids_db",
)


# ============================================================
# DATABASE CONNECTION
# ============================================================

def get_db_connection():

    connection_kwargs = {
        "host": DB_HOST,
        "user": DB_USER,
        "database": DB_NAME,
        "connection_timeout": 5,
    }

    if DB_PASSWORD is not None:
        connection_kwargs["password"] = DB_PASSWORD

    return mysql.connector.connect(**connection_kwargs)


def database_is_online():

    connection = None

    try:

        connection = get_db_connection()

        if connection.is_connected():
            return True

        return False

    except Error:

        return False

    finally:

        try:

            if connection:
                connection.close()

        except Exception:
            pass


# ============================================================
# GENERIC DATABASE HELPERS
# ============================================================

def fetch_dataframe(query, params=None):

    connection = None
    cursor = None

    try:

        connection = get_db_connection()

        cursor = connection.cursor(
            dictionary=True
        )

        cursor.execute(
            query,
            params or (),
        )

        rows = cursor.fetchall()

        return pd.DataFrame(rows)

    except Error as e:

        st.error(
            f"MySQL error: {e}"
        )

        return pd.DataFrame()

    finally:

        try:

            if cursor:
                cursor.close()

            if connection:
                connection.close()

        except Exception:
            pass


def execute_scalar(query, params=None):

    connection = None
    cursor = None

    try:

        connection = get_db_connection()

        cursor = connection.cursor()

        cursor.execute(
            query,
            params or (),
        )

        result = cursor.fetchone()

        if result:
            return result[0]

        return 0

    except Error:

        return 0

    finally:

        try:

            if cursor:
                cursor.close()

            if connection:
                connection.close()

        except Exception:
            pass


# ============================================================
# LIVE DATABASE STATISTICS
# ============================================================

def get_live_stats():

    total_logs = execute_scalar(
        """
        SELECT COUNT(*)
        FROM intrusion_logs
        """
    )

    total_attacks = execute_scalar(
        """
        SELECT COUNT(*)
        FROM intrusion_logs
        WHERE LOWER(prediction) != 'normal'
        """
    )

    normal_traffic = execute_scalar(
        """
        SELECT COUNT(*)
        FROM intrusion_logs
        WHERE LOWER(prediction) = 'normal'
        """
    )

    total_alerts = execute_scalar(
        """
        SELECT COUNT(*)
        FROM alerts
        """
    )

    high_alerts = execute_scalar(
        """
        SELECT COUNT(*)
        FROM alerts
        WHERE UPPER(alert_level) = 'HIGH'
        """
    )

    attack_rate = 0.0

    if total_logs:

        attack_rate = (
            total_attacks / total_logs
        ) * 100

    return {
        "total_logs": int(total_logs or 0),
        "total_attacks": int(total_attacks or 0),
        "normal_traffic": int(normal_traffic or 0),
        "total_alerts": int(total_alerts or 0),
        "high_alerts": int(high_alerts or 0),
        "attack_rate": float(attack_rate),
    }


# ============================================================
# RECENT INTRUSION LOGS
# ============================================================

def get_recent_logs(limit=20):

    limit = max(
        1,
        min(int(limit), 5000),
    )

    return fetch_dataframe(
        f"""
        SELECT
            log_id,
            source_ip,
            destination_ip,
            protocol,
            prediction,
            confidence,
            timestamp
        FROM intrusion_logs
        ORDER BY timestamp DESC
        LIMIT {limit}
        """
    )


# ============================================================
# RECENT ALERTS
# ============================================================

def get_recent_alerts(limit=50):

    limit = max(
        1,
        min(int(limit), 5000),
    )

    return fetch_dataframe(
        f"""
        SELECT
            alert_id,
            log_id,
            alert_level,
            message,
            alert_time
        FROM alerts
        ORDER BY alert_time DESC
        LIMIT {limit}
        """
    )


# ============================================================
# ATTACK DISTRIBUTION
# ============================================================

def get_attack_distribution():

    return fetch_dataframe(
        """
        SELECT
            prediction,
            COUNT(*) AS count
        FROM intrusion_logs
        WHERE LOWER(prediction) != 'normal'
        GROUP BY prediction
        ORDER BY count DESC
        """
    )


# ============================================================
# PROTOCOL DISTRIBUTION
# ============================================================

def get_protocol_distribution():

    return fetch_dataframe(
        """
        SELECT
            protocol,
            COUNT(*) AS count
        FROM intrusion_logs
        GROUP BY protocol
        ORDER BY count DESC
        """
    )


# ============================================================
# PREDICTION DISTRIBUTION
# ============================================================

def get_prediction_distribution():

    return fetch_dataframe(
        """
        SELECT
            prediction,
            COUNT(*) AS count
        FROM intrusion_logs
        GROUP BY prediction
        ORDER BY count DESC
        """
    )


# ============================================================
# ATTACK CATEGORY MAPPING
# ============================================================

def get_category(prediction):

    prediction = str(
        prediction
    ).lower()

    dos = {
        "back",
        "land",
        "neptune",
        "pod",
        "smurf",
        "teardrop",
    }

    probe = {
        "ipsweep",
        "nmap",
        "portsweep",
        "satan",
    }

    r2l = {
        "ftp_write",
        "guess_passwd",
        "imap",
        "phf",
        "warezclient",
        "warezmaster",
        "multihop",
    }

    u2r = {
        "buffer_overflow",
        "loadmodule",
        "perl",
        "rootkit",
        "spy",
    }

    if prediction == "normal":
        return "Normal"

    if prediction in dos:
        return "DoS"

    if prediction in probe:
        return "Probe"

    if prediction in r2l:
        return "R2L"

    if prediction in u2r:
        return "U2R"

    return "Other"


def get_category_distribution():

    df = fetch_dataframe(
        """
        SELECT
            prediction,
            COUNT(*) AS count
        FROM intrusion_logs
        GROUP BY prediction
        ORDER BY count DESC
        """
    )

    if df.empty:
        return pd.DataFrame()

    df["category"] = df[
        "prediction"
    ].apply(get_category)

    category_df = (
        df.groupby(
            "category",
            as_index=False,
        )["count"]
        .sum()
        .sort_values(
            "count",
            ascending=False,
        )
    )

    return category_df


# ============================================================
# DETECTION TIMELINE
# ============================================================

def get_detection_timeline():

    return fetch_dataframe(
        """
        SELECT
            DATE_FORMAT(
                timestamp,
                '%Y-%m-%d %H:%i'
            ) AS detection_time,
            COUNT(*) AS detections
        FROM intrusion_logs
        GROUP BY DATE_FORMAT(
            timestamp,
            '%Y-%m-%d %H:%i'
        )
        ORDER BY detection_time ASC
        """
    )


# ============================================================
# TOP SOURCE IPS
# ============================================================

def get_top_source_ips():

    return fetch_dataframe(
        """
        SELECT
            source_ip,
            COUNT(*) AS detections
        FROM intrusion_logs
        GROUP BY source_ip
        ORDER BY detections DESC
        LIMIT 10
        """
    )


# ============================================================
# TOP DESTINATION IPS
# ============================================================

def get_top_destination_ips():

    return fetch_dataframe(
        """
        SELECT
            destination_ip,
            COUNT(*) AS detections
        FROM intrusion_logs
        GROUP BY destination_ip
        ORDER BY detections DESC
        LIMIT 10
        """
    )


# ============================================================
# CONFIDENCE STATISTICS
# ============================================================

def get_confidence_stats():

    return fetch_dataframe(
        """
        SELECT
            AVG(confidence) AS average_confidence,
            MAX(confidence) AS maximum_confidence,
            MIN(confidence) AS minimum_confidence
        FROM intrusion_logs
        """
    )


# ============================================================
# START LIVE DETECTION
# ============================================================

def start_live_detection():

    detection_script = os.path.join(
        PROJECT_ROOT,
        "modules",
        "live_detection.py",
    )

    # --------------------------------------------------------
    # CHECK FILE
    # --------------------------------------------------------

    if not os.path.exists(
        detection_script
    ):

        return {
            "success": False,
            "output": (
                "❌ live_detection.py not found.\n\n"
                f"Expected location:\n"
                f"{detection_script}"
            ),
            "returncode": 1,
        }

    # --------------------------------------------------------
    # RUN LIVE DETECTION
    # --------------------------------------------------------

    try:

        result = subprocess.run(
            [
                sys.executable,
                detection_script,
            ],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
            creationflags=(
                subprocess.CREATE_NO_WINDOW
                if sys.platform.startswith("win")
                else 0
            ),
        )

        output_parts = []

        if result.stdout:
            output_parts.append(
                result.stdout
            )

        if result.stderr:
            output_parts.append(
                "\n===== ERROR / STDERR =====\n"
                + result.stderr
            )

        output = "\n".join(
            output_parts
        )

        if not output.strip():

            output = (
                "No output was returned "
                "by live_detection.py."
            )

        return {
            "success": (
                result.returncode == 0
            ),
            "output": output,
            "returncode": result.returncode,
        }

    except subprocess.TimeoutExpired:

        return {
            "success": False,
            "output": (
                "⏱️ Live detection timed out "
                "after 120 seconds.\n\n"
                "Scapy may be waiting for packets."
            ),
            "returncode": -1,
        }

    except Exception as e:

        return {
            "success": False,
            "output": (
                "❌ Unable to run live detection.\n\n"
                f"{type(e).__name__}: {e}"
            ),
            "returncode": -1,
        }


# ============================================================
# FORMATTERS
# ============================================================

def format_confidence(value):

    try:

        return (
            f"{float(value) * 100:.2f}%"
        )

    except Exception:

        return "0.00%"


# ============================================================
# CUSTOM CSS
# ============================================================

st.markdown(
    """
    <style>

    .stApp {
        background:
            radial-gradient(
                circle at top right,
                rgba(15, 118, 110, 0.12),
                transparent 35%
            ),
            #070b14;
        color: #f8fafc;
    }

    section[data-testid="stSidebar"] {
        background: #050912;
        border-right: 1px solid #1e293b;
    }

    .main-title {
        font-size: 40px;
        font-weight: 800;
        letter-spacing: -1px;
        margin-bottom: 4px;
    }

    .subtitle {
        color: #94a3b8;
        font-size: 15px;
        margin-bottom: 22px;
    }

    .status-online {
        background: rgba(6, 78, 59, 0.35);
        border: 1px solid #047857;
        border-radius: 12px;
        padding: 13px 18px;
        color: #6ee7b7;
        font-weight: 650;
        margin-bottom: 18px;
    }

    .status-offline {
        background: rgba(127, 29, 29, 0.35);
        border: 1px solid #991b1b;
        border-radius: 12px;
        padding: 13px 18px;
        color: #fca5a5;
        font-weight: 650;
        margin-bottom: 18px;
    }

    .live-badge {
        display: inline-block;
        background: #064e3b;
        color: #6ee7b7;
        border: 1px solid #047857;
        border-radius: 30px;
        padding: 6px 14px;
        font-size: 12px;
        font-weight: 750;
        letter-spacing: 0.4px;
    }

    .dashboard-card {
        background:
            linear-gradient(
                145deg,
                #111827,
                #0d1422
            );
        border: 1px solid #1f2937;
        border-radius: 16px;
        padding: 19px;
        min-height: 135px;
        box-shadow:
            0 8px 25px rgba(0,0,0,0.20);
    }

    .card-title {
        color: #94a3b8;
        font-size: 13px;
        font-weight: 650;
        margin-bottom: 10px;
    }

    .card-value {
        color: #f8fafc;
        font-size: 32px;
        font-weight: 800;
    }

    .card-description {
        color: #64748b;
        font-size: 11px;
        margin-top: 7px;
    }

    .section-title {
        font-size: 23px;
        font-weight: 760;
        margin-top: 26px;
        margin-bottom: 13px;
    }

    .footer {
        color: #64748b;
        text-align: center;
        padding: 22px;
        font-size: 12px;
    }

    </style>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:

    st.markdown(
        "# 🛡️ NIDS"
    )

    st.caption(
        "AI-Based Network Intrusion Detection System"
    )

    st.divider()

    page = st.radio(
        "Navigation",
        [
            "📊 Dashboard",
            "🚨 Security Alerts",
            "📋 Intrusion Logs",
            "📈 Live Analytics",
            "📁 PCAP Analysis",
            "📑 Reports",
            "⚙️ System Status",
        ],
    )

    st.divider()

    st.markdown(
        "### ⚡ Live Monitoring"
    )

    st.caption(
        "Click Start Live Detection "
        "to analyze network packets."
    )

    st.divider()

    st.caption("AI Engine")
    st.caption("Random Forest")

    st.caption("Packet Capture")
    st.caption("Scapy + Npcap")

    st.caption("Database")
    st.caption("MySQL")

    st.caption("Dashboard")
    st.caption("Streamlit")


# ============================================================
# DASHBOARD
# ============================================================

if page == "📊 Dashboard":

    st.markdown(
        '<div class="main-title">'
        '🛡️ Network Intrusion Detection System'
        '</div>',
        unsafe_allow_html=True,
    )

    st.markdown(
        '<div class="subtitle">'
        'Real-time AI network monitoring, '
        'intrusion detection and '
        'Security Operations Center dashboard'
        '</div>',
        unsafe_allow_html=True,
    )

    # --------------------------------------------------------
    # DATABASE STATUS
    # --------------------------------------------------------

    if database_is_online():

        st.markdown(
            '<div class="status-online">'
            '🟢 MYSQL ONLINE &nbsp;|&nbsp; '
            'Live database monitoring active'
            '</div>',
            unsafe_allow_html=True,
        )

    else:

        st.markdown(
            '<div class="status-offline">'
            '🔴 MYSQL OFFLINE &nbsp;|&nbsp; '
            'Check MySQL server and credentials'
            '</div>',
            unsafe_allow_html=True,
        )

        st.stop()

    # --------------------------------------------------------
    # LIVE DETECTION CONTROL
    # --------------------------------------------------------

    control_col1, control_col2 = st.columns(
        [3, 1]
    )

    with control_col1:

        st.markdown(
            '<span class="live-badge">'
            '● LIVE DATABASE MONITOR'
            '</span>',
            unsafe_allow_html=True,
        )

    with control_col2:

        start_detection = st.button(
            "▶ Start Live Detection",
            type="primary",
            width="stretch",
        )

    # --------------------------------------------------------
    # RUN DETECTION
    # --------------------------------------------------------

    if start_detection:

        with st.spinner(
            "🛡️ Running live detection..."
        ):

            result = start_live_detection()

        if result["success"]:

            st.success(
                "✅ Live detection completed successfully."
            )

        else:

            st.error(
                "❌ Live detection failed."
            )

        with st.expander(
            "📋 View Detection Output",
            expanded=True,
        ):

            st.code(
                result["output"],
                language="text",
            )

        st.info(
            f"Process return code: "
            f"{result['returncode']}"
        )

    # --------------------------------------------------------
    # LIVE STATISTICS
    # --------------------------------------------------------

    stats = get_live_stats()

    st.markdown(
        '<div class="section-title">'
        '📡 Live Network Statistics'
        '</div>',
        unsafe_allow_html=True,
    )

    col1, col2, col3, col4, col5 = st.columns(5)

    with col1:

        st.markdown(
            f"""
            <div class="dashboard-card">
                <div class="card-title">
                    📡 TOTAL NETWORK LOGS
                </div>
                <div class="card-value">
                    {stats["total_logs"]:,}
                </div>
                <div class="card-description">
                    Records stored in MySQL
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col2:

        st.markdown(
            f"""
            <div class="dashboard-card">
                <div class="card-title">
                    🚨 DETECTED ATTACKS
                </div>
                <div class="card-value">
                    {stats["total_attacks"]:,}
                </div>
                <div class="card-description">
                    Malicious predictions
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col3:

        st.markdown(
            f"""
            <div class="dashboard-card">
                <div class="card-title">
                    ✅ NORMAL TRAFFIC
                </div>
                <div class="card-value">
                    {stats["normal_traffic"]:,}
                </div>
                <div class="card-description">
                    Safe predictions
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col4:

        st.markdown(
            f"""
            <div class="dashboard-card">
                <div class="card-title">
                    ⚠️ ATTACK RATE
                </div>
                <div class="card-value">
                    {stats["attack_rate"]:.1f}%
                </div>
                <div class="card-description">
                    Malicious traffic ratio
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col5:

        st.markdown(
            f"""
            <div class="dashboard-card">
                <div class="card-title">
                    🔔 SECURITY ALERTS
                </div>
                <div class="card-value">
                    {stats["total_alerts"]:,}
                </div>
                <div class="card-description">
                    Generated by detection engine
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # --------------------------------------------------------
    # ATTACK DISTRIBUTION
    # --------------------------------------------------------

    st.markdown(
        '<div class="section-title">'
        '🚨 Attack Distribution'
        '</div>',
        unsafe_allow_html=True,
    )

    attack_df = get_attack_distribution()

    if not attack_df.empty:

        chart_df = attack_df.rename(
            columns={
                "prediction": "Attack Type",
                "count": "Detections",
            }
        )

        col1, col2 = st.columns([2, 1])

        with col1:

            st.bar_chart(
                chart_df.set_index(
                    "Attack Type"
                ),
                width="stretch",
            )

        with col2:

            st.dataframe(
                chart_df,
                width="stretch",
                hide_index=True,
            )

    else:

        st.success(
            "✅ No malicious traffic detected yet."
        )

    # --------------------------------------------------------
    # CATEGORY DISTRIBUTION
    # --------------------------------------------------------

    st.markdown(
        '<div class="section-title">'
        '🎯 Attack Categories'
        '</div>',
        unsafe_allow_html=True,
    )

    category_df = get_category_distribution()

    if not category_df.empty:

        category_display = category_df.rename(
            columns={
                "category": "Category",
                "count": "Detections",
            }
        )

        st.bar_chart(
            category_display.set_index(
                "Category"
            ),
            width="stretch",
        )

    else:

        st.info(
            "No category data available yet."
        )

    # --------------------------------------------------------
    # RECENT ACTIVITY
    # --------------------------------------------------------

    st.markdown(
        '<div class="section-title">'
        '📋 Recent Detection Activity'
        '</div>',
        unsafe_allow_html=True,
    )

    recent_logs = get_recent_logs(10)

    if not recent_logs.empty:

        display_logs = recent_logs.copy()

        display_logs["confidence"] = (
            display_logs["confidence"]
            .apply(format_confidence)
        )

        st.dataframe(
            display_logs,
            width="stretch",
            hide_index=True,
        )

    else:

        st.info(
            "No intrusion logs have been recorded yet."
        )


# ============================================================
# SECURITY ALERTS
# ============================================================

elif page == "🚨 Security Alerts":

    st.title(
        "🚨 Security Alerts"
    )

    st.caption(
        "Alerts generated by the AI intrusion detection engine."
    )

    if not database_is_online():

        st.error(
            "MySQL database is unavailable."
        )

        st.stop()

    stats = get_live_stats()

    c1, c2, c3, c4 = st.columns(4)

    with c1:
        st.metric(
            "Total Alerts",
            stats["total_alerts"],
        )

    with c2:
        st.metric(
            "High Severity",
            stats["high_alerts"],
        )

    with c3:
        st.metric(
            "Detected Attacks",
            stats["total_attacks"],
        )

    with c4:
        st.metric(
            "Attack Rate",
            f'{stats["attack_rate"]:.2f}%',
        )

    st.divider()

    alerts = get_recent_alerts(100)

    if alerts.empty:

        st.success(
            "✅ No security alerts detected."
        )

    else:

        for _, alert in alerts.iterrows():

            level = str(
                alert.get(
                    "alert_level",
                    "UNKNOWN",
                )
            ).upper()

            message = str(
                alert.get(
                    "message",
                    "Security alert",
                )
            )

            alert_time = alert.get(
                "alert_time",
                "",
            )

            log_id = alert.get(
                "log_id",
                "",
            )

            if level == "HIGH":

                st.error(
                    f"🚨 **HIGH** | "
                    f"Log ID: `{log_id}` | "
                    f"{message} | "
                    f"{alert_time}"
                )

            elif level == "MEDIUM":

                st.warning(
                    f"⚠️ **MEDIUM** | "
                    f"Log ID: `{log_id}` | "
                    f"{message} | "
                    f"{alert_time}"
                )

            else:

                st.info(
                    f"ℹ️ **{level}** | "
                    f"Log ID: `{log_id}` | "
                    f"{message} | "
                    f"{alert_time}"
                )

    st.subheader(
        "📋 Alert Records"
    )

    if not alerts.empty:

        st.dataframe(
            alerts,
            width="stretch",
            hide_index=True,
        )


# ============================================================
# INTRUSION LOGS
# ============================================================

elif page == "📋 Intrusion Logs":

    st.title(
        "📋 Intrusion Logs"
    )

    st.caption(
        "Complete history of AI-analyzed network traffic."
    )

    if not database_is_online():

        st.error(
            "MySQL database is unavailable."
        )

        st.stop()

    logs = get_recent_logs(500)

    if logs.empty:

        st.info(
            "No intrusion logs available."
        )

    else:

        col1, col2, col3 = st.columns(3)

        with col1:

            prediction_options = [
                "All"
            ] + sorted(
                logs["prediction"]
                .dropna()
                .astype(str)
                .unique()
                .tolist()
            )

            selected_prediction = st.selectbox(
                "Prediction",
                prediction_options,
            )

        with col2:

            protocol_options = [
                "All"
            ] + sorted(
                logs["protocol"]
                .dropna()
                .astype(str)
                .unique()
                .tolist()
            )

            selected_protocol = st.selectbox(
                "Protocol",
                protocol_options,
            )

        with col3:

            min_confidence = st.slider(
                "Minimum Confidence",
                0,
                100,
                0,
            )

        filtered = logs.copy()

        if selected_prediction != "All":

            filtered = filtered[
                filtered["prediction"]
                .astype(str)
                == selected_prediction
            ]

        if selected_protocol != "All":

            filtered = filtered[
                filtered["protocol"]
                .astype(str)
                == selected_protocol
            ]

        filtered = filtered[
            pd.to_numeric(
                filtered["confidence"],
                errors="coerce",
            ).fillna(0) * 100
            >= min_confidence
        ]

        filtered["category"] = (
            filtered["prediction"]
            .apply(get_category)
        )

        display_df = filtered.copy()

        display_df["confidence"] = (
            display_df["confidence"]
            .apply(format_confidence)
        )

        st.dataframe(
            display_df,
            width="stretch",
            hide_index=True,
        )

        csv_data = filtered.to_csv(
            index=False
        )

        st.download_button(
            "⬇️ Download Logs as CSV",
            data=csv_data,
            file_name="nids_intrusion_logs.csv",
            mime="text/csv",
        )


# ============================================================
# LIVE ANALYTICS
# ============================================================

elif page == "📈 Live Analytics":

    st.title(
        "📈 Live Analytics"
    )

    st.caption(
        "Real-time analytics generated directly from MySQL."
    )

    if not database_is_online():

        st.error(
            "MySQL database is unavailable."
        )

        st.stop()

    stats = get_live_stats()

    c1, c2, c3, c4 = st.columns(4)

    with c1:
        st.metric(
            "Total Logs",
            stats["total_logs"],
        )

    with c2:
        st.metric(
            "Normal",
            stats["normal_traffic"],
        )

    with c3:
        st.metric(
            "Attacks",
            stats["total_attacks"],
        )

    with c4:
        st.metric(
            "Attack Rate",
            f'{stats["attack_rate"]:.2f}%',
        )

    st.divider()

    st.subheader(
        "🌐 Protocol Distribution"
    )

    protocol_df = get_protocol_distribution()

    if not protocol_df.empty:

        st.bar_chart(
            protocol_df.set_index(
                "protocol"
            ),
            width="stretch",
        )

    else:

        st.info(
            "No protocol data available."
        )

    st.subheader(
        "🤖 AI Prediction Distribution"
    )

    prediction_df = get_prediction_distribution()

    if not prediction_df.empty:

        st.bar_chart(
            prediction_df.set_index(
                "prediction"
            ),
            width="stretch",
        )

    else:

        st.info(
            "No prediction data available."
        )

    st.subheader(
        "🎯 Attack Category Distribution"
    )

    category_df = get_category_distribution()

    if not category_df.empty:

        st.bar_chart(
            category_df.set_index(
                "category"
            ),
            width="stretch",
        )

    else:

        st.info(
            "No category data available."
        )

    st.subheader(
        "⏱️ Detection Timeline"
    )

    timeline_df = get_detection_timeline()

    if not timeline_df.empty:

        timeline_df["detection_time"] = pd.to_datetime(
            timeline_df["detection_time"]
        )

        timeline_df = timeline_df.set_index(
            "detection_time"
        )

        st.line_chart(
            timeline_df["detections"],
            width="stretch",
        )

    else:

        st.info(
            "No timeline data available."
        )

    c1, c2 = st.columns(2)

    with c1:

        st.subheader(
            "🔝 Top Source IPs"
        )

        source_df = get_top_source_ips()

        if not source_df.empty:

            st.bar_chart(
                source_df.set_index(
                    "source_ip"
                ),
                width="stretch",
            )

            st.dataframe(
                source_df,
                width="stretch",
                hide_index=True,
            )

        else:

            st.info(
                "No source IP data."
            )

    with c2:

        st.subheader(
            "🎯 Top Destination IPs"
        )

        destination_df = (
            get_top_destination_ips()
        )

        if not destination_df.empty:

            st.bar_chart(
                destination_df.set_index(
                    "destination_ip"
                ),
                width="stretch",
            )

            st.dataframe(
                destination_df,
                width="stretch",
                hide_index=True,
            )

        else:

            st.info(
                "No destination IP data."
            )

    st.subheader(
        "🎯 AI Confidence"
    )

    confidence_df = get_confidence_stats()

    if not confidence_df.empty:

        row = confidence_df.iloc[0]

        c1, c2, c3 = st.columns(3)

        with c1:

            st.metric(
                "Average Confidence",
                format_confidence(
                    row["average_confidence"]
                ),
            )

        with c2:

            st.metric(
                "Maximum Confidence",
                format_confidence(
                    row["maximum_confidence"]
                ),
            )

        with c3:

            st.metric(
                "Minimum Confidence",
                format_confidence(
                    row["minimum_confidence"]
                ),
            )


# ============================================================
# PCAP ANALYSIS
# ============================================================

elif page == "📁 PCAP Analysis":

    st.title(
        "📁 PCAP Analysis"
    )

    st.caption(
        "Upload a packet capture for offline AI-based analysis."
    )

    st.info(
        "PCAP analysis UI is ready. "
        "The existing Flask/backend pipeline "
        "can be connected here later."
    )

    uploaded_file = st.file_uploader(
        "Upload PCAP file",
        type=[
            "pcap",
            "pcapng",
        ],
    )

    if uploaded_file:

        st.success(
            f"Uploaded: {uploaded_file.name}"
        )

        st.write(
            "File size: "
            f"{len(uploaded_file.getvalue()) / 1024:.2f} KB"
        )

        if st.button(
            "🔍 Prepare PCAP Analysis",
            width="stretch",
        ):

            st.info(
                "PCAP received successfully."
            )

    else:

        st.info(
            "Upload a .pcap or .pcapng file to begin."
        )


# ============================================================
# REPORTS
# ============================================================

elif page == "📑 Reports":

    st.title(
        "📑 NIDS Reports"
    )

    st.caption(
        "Model information, detection statistics "
        "and system reports."
    )

    st.subheader(
        "🤖 Model Information"
    )

    model_exists = os.path.exists(
        MODEL_PATH
    )

    dataset_exists = os.path.exists(
        DATASET_PATH
    )

    c1, c2, c3 = st.columns(3)

    with c1:

        st.metric(
            "Model",
            "Random Forest"
            if model_exists
            else "Not Found",
        )

    with c2:

        st.metric(
            "Input Features",
            "41",
        )

    with c3:

        st.metric(
            "Classes",
            "23",
        )

    st.divider()

    st.subheader(
        "📊 Live Detection Statistics"
    )

    stats = get_live_stats()

    c1, c2, c3, c4 = st.columns(4)

    with c1:

        st.metric(
            "Total Logs",
            stats["total_logs"],
        )

    with c2:

        st.metric(
            "Normal",
            stats["normal_traffic"],
        )

    with c3:

        st.metric(
            "Attacks",
            stats["total_attacks"],
        )

    with c4:

        st.metric(
            "Attack Rate",
            f'{stats["attack_rate"]:.2f}%',
        )

    st.divider()

    st.subheader(
        "📦 Dataset / Model Files"
    )

    files_df = pd.DataFrame(
        [
            {
                "Component": "NSL-KDD Dataset",
                "Path": "data/KDDTrain+.txt",
                "Status": (
                    "Available"
                    if dataset_exists
                    else "Missing"
                ),
            },
            {
                "Component": "Random Forest Model",
                "Path": "models/intrusion_model.pkl",
                "Status": (
                    "Available"
                    if model_exists
                    else "Missing"
                ),
            },
            {
                "Component": "Scaler",
                "Path": "models/scaler.pkl",
                "Status": (
                    "Available"
                    if os.path.exists(
                        os.path.join(
                            PROJECT_ROOT,
                            "models",
                            "scaler.pkl",
                        )
                    )
                    else "Missing"
                ),
            },
            {
                "Component": "Live Detection",
                "Path": "modules/live_detection.py",
                "Status": (
                    "Available"
                    if os.path.exists(
                        LIVE_DETECTION_SCRIPT
                    )
                    else "Missing"
                ),
            },
        ]
    )

    st.dataframe(
        files_df,
        width="stretch",
        hide_index=True,
    )

    st.divider()

    st.subheader(
        "🎯 Category Distribution"
    )

    category_df = get_category_distribution()

    if not category_df.empty:

        category_display = category_df.rename(
            columns={
                "category": "Category",
                "count": "Detections",
            }
        )

        st.dataframe(
            category_display,
            width="stretch",
            hide_index=True,
        )

    else:

        st.info(
            "No category data available."
        )

    st.subheader(
        "🎯 Confidence Report"
    )

    confidence_df = get_confidence_stats()

    if not confidence_df.empty:

        row = confidence_df.iloc[0]

        report_df = pd.DataFrame(
            [
                {
                    "Metric": "Average Confidence",
                    "Value": format_confidence(
                        row["average_confidence"]
                    ),
                },
                {
                    "Metric": "Maximum Confidence",
                    "Value": format_confidence(
                        row["maximum_confidence"]
                    ),
                },
                {
                    "Metric": "Minimum Confidence",
                    "Value": format_confidence(
                        row["minimum_confidence"]
                    ),
                },
            ]
        )

        st.dataframe(
            report_df,
            width="stretch",
            hide_index=True,
        )

    else:

        st.info(
            "No confidence information available."
        )


# ============================================================
# SYSTEM STATUS
# ============================================================

elif page == "⚙️ System Status":

    st.title(
        "⚙️ System Status"
    )

    st.caption(
        "NIDS component health and configuration."
    )

    mysql_status = database_is_online()

    c1, c2, c3 = st.columns(3)

    with c1:

        if mysql_status:

            st.success(
                "🟢 MySQL\n\nConnected"
            )

        else:

            st.error(
                "🔴 MySQL\n\nOffline"
            )

    with c2:

        if os.path.exists(
            LIVE_DETECTION_SCRIPT
        ):

            st.success(
                "🟢 Live Detection\n\nAvailable"
            )

        else:

            st.error(
                "🔴 Live Detection\n\nMissing"
            )

    with c3:

        if os.path.exists(
            MODEL_PATH
        ):

            st.success(
                "🟢 Random Forest\n\nModel Available"
            )

        else:

            st.error(
                "🔴 Random Forest\n\nModel Missing"
            )

    st.divider()

    st.subheader(
        "📦 System Components"
    )

    components = pd.DataFrame(
        [
            {
                "Component": "Packet Capture",
                "Technology": "Scapy + Npcap",
                "Status": (
                    "Ready"
                    if os.path.exists(
                        LIVE_DETECTION_SCRIPT
                    )
                    else "Unavailable"
                ),
            },
            {
                "Component": "Machine Learning",
                "Technology": "Random Forest",
                "Status": (
                    "Ready"
                    if os.path.exists(
                        MODEL_PATH
                    )
                    else "Unavailable"
                ),
            },
            {
                "Component": "Database",
                "Technology": "MySQL",
                "Status": (
                    "Connected"
                    if mysql_status
                    else "Offline"
                ),
            },
            {
                "Component": "Dashboard",
                "Technology": "Streamlit",
                "Status": "Running",
            },
            {
                "Component": "Backend",
                "Technology": "Flask",
                "Status": "Configured",
            },
        ]
    )

    st.dataframe(
        components,
        width="stretch",
        hide_index=True,
    )

    st.divider()

    st.subheader(
        "🗄️ Database Configuration"
    )

    st.write(
        f"**Host:** {DB_HOST}"
    )

    st.write(
        f"**User:** {DB_USER}"
    )

    st.write(
        f"**Database:** {DB_NAME}"
    )

    st.caption(
        "Database password is intentionally hidden."
    )

    st.divider()

    st.subheader(
        "🧠 NIDS Architecture"
    )

    st.code(
        """
Npcap
   ↓
Scapy Live Capture
   ↓
Feature Extraction
   ↓
Random Forest AI
   ↓
Prediction + Confidence
   ↓
MySQL
   ├── intrusion_logs
   └── alerts
   ↓
Streamlit SOC Dashboard
        """,
        language="text",
    )


# ============================================================
# FOOTER
# ============================================================

st.divider()

st.markdown(
    """
    <div class="footer">
        🛡️ NIDS | AI-Based Network Intrusion Detection System
        <br>
        Random Forest • Scapy • Npcap • MySQL • Flask • Streamlit
    </div>
    """,
    unsafe_allow_html=True,
)