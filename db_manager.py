import os

import mysql.connector
from mysql.connector import Error


# ============================================================
# DATABASE CONFIGURATION
# ============================================================

DB_HOST = os.getenv("NIDS_DB_HOST", "localhost")
DB_USER = os.getenv("NIDS_DB_USER", "root")
DB_PASSWORD = os.getenv("NIDS_DB_PASSWORD")
DB_NAME = os.getenv("NIDS_DB_NAME", "nids_db")


# ============================================================
# GLOBAL DATABASE OBJECTS
# ============================================================

connection = None
cursor = None


# ============================================================
# CONNECT TO DATABASE
# ============================================================

def connect_database():
    """
    Establish a connection to the NIDS MySQL database.

    Returns
    -------
    bool
        True if connection succeeds, otherwise False.
    """

    global connection
    global cursor

    try:

        # Close old connection if necessary
        if connection is not None:

            try:

                if connection.is_connected():
                    connection.close()

            except Exception:
                pass

        connection_kwargs = {
            "host": DB_HOST,
            "user": DB_USER,
            "database": DB_NAME,
        }

        if DB_PASSWORD is not None:
            connection_kwargs["password"] = DB_PASSWORD

        connection = mysql.connector.connect(**connection_kwargs)

        if connection.is_connected():

            cursor = connection.cursor()

            print("Connected to MySQL Successfully!")

            return True

    except Error as err:

        print("Database Connection Error:", err)

        connection = None
        cursor = None

        return False

    return False


# ============================================================
# ENSURE DATABASE CONNECTION
# ============================================================

def ensure_connection():
    """
    Check whether the database connection is active.

    If the connection is unavailable, reconnect automatically.

    Returns
    -------
    bool
        True if database is available, otherwise False.
    """

    global connection
    global cursor

    try:

        if connection is None:

            return connect_database()

        if not connection.is_connected():

            return connect_database()

        # Recreate cursor if necessary
        if cursor is None:

            cursor = connection.cursor()

        return True

    except Error as err:

        print("Database connection check failed:", err)

        return connect_database()


# ============================================================
# INSERT NETWORK LOG
# ============================================================

def insert_log(
    source_ip,
    destination_ip,
    protocol,
    prediction,
    confidence
):
    """
    Insert a network detection result into intrusion_logs.

    Returns
    -------
    int or None
        Inserted log ID if successful.
    """

    if not ensure_connection():

        print("Unable to connect to MySQL.")

        return None

    query = """
        INSERT INTO intrusion_logs
        (
            source_ip,
            destination_ip,
            protocol,
            prediction,
            confidence
        )
        VALUES (%s, %s, %s, %s, %s)
    """

    values = (
        str(source_ip),
        str(destination_ip),
        str(protocol),
        str(prediction),
        float(confidence)
    )

    try:

        cursor.execute(
            query,
            values
        )

        connection.commit()

        return cursor.lastrowid

    except Error as err:

        print("Error inserting network log:", err)

        try:
            connection.rollback()
        except Exception:
            pass

        return None


# ============================================================
# FETCH ALL NETWORK LOGS
# ============================================================

def get_logs():
    """
    Retrieve all intrusion logs.

    Returns
    -------
    list
        List of database records.
    """

    if not ensure_connection():

        print("Unable to connect to MySQL.")

        return []

    query = """
        SELECT
            log_id,
            timestamp,
            source_ip,
            destination_ip,
            protocol,
            prediction,
            confidence
        FROM intrusion_logs
        ORDER BY timestamp DESC
    """

    try:

        cursor.execute(query)

        return cursor.fetchall()

    except Error as err:

        print("Error fetching logs:", err)

        return []


# ============================================================
# CREATE ALERT
# ============================================================

def create_alert(
    log_id,
    alert_level,
    message
):
    """
    Create an alert associated with a network log.

    Returns
    -------
    int or None
        Alert ID if successful.
    """

    if not ensure_connection():

        print("Unable to connect to MySQL.")

        return None

    query = """
        INSERT INTO alerts
        (
            log_id,
            alert_level,
            message
        )
        VALUES (%s, %s, %s)
    """

    values = (
        int(log_id),
        str(alert_level),
        str(message)
    )

    try:

        cursor.execute(
            query,
            values
        )

        connection.commit()

        return cursor.lastrowid

    except Error as err:

        print("Error creating alert:", err)

        try:
            connection.rollback()
        except Exception:
            pass

        return None


# ============================================================
# PROCESS PREDICTION
# ============================================================

def process_prediction(
    source_ip,
    destination_ip,
    protocol,
    prediction,
    confidence
):
    """
    Save prediction to database and generate an alert
    when traffic is classified as malicious.

    Returns
    -------
    int or None
        Network log ID.
    """

    # --------------------------------------------------------
    # SAVE NETWORK LOG
    # --------------------------------------------------------

    log_id = insert_log(
        source_ip,
        destination_ip,
        protocol,
        prediction,
        confidence
    )

    if log_id is None:

        print("Network log could not be saved.")

        return None

    # --------------------------------------------------------
    # NORMALIZE PREDICTION
    # --------------------------------------------------------

    prediction_text = str(
        prediction
    ).strip().lower()

    # --------------------------------------------------------
    # GENERATE ALERT FOR ATTACK
    # --------------------------------------------------------

    if prediction_text != "normal":

        message = (
            f"Malicious activity detected: "
            f"{prediction}"
        )

        alert_id = create_alert(
            log_id,
            "HIGH",
            message
        )

        if alert_id is not None:

            print(
                f"HIGH ALERT GENERATED! "
                f"Alert ID: {alert_id}"
            )

        else:

            print(
                "Warning: Attack detected, "
                "but alert could not be created."
            )

    else:

        print("Normal Traffic")

    return log_id


# ============================================================
# FETCH ALL ALERTS
# ============================================================

def get_alerts():
    """
    Retrieve all generated alerts.

    Returns
    -------
    list
        List of alert records.
    """

    if not ensure_connection():

        print("Unable to connect to MySQL.")

        return []

    query = """
        SELECT
            alert_id,
            log_id,
            alert_level,
            message,
            alert_time
        FROM alerts
        ORDER BY alert_time DESC
    """

    try:

        cursor.execute(query)

        return cursor.fetchall()

    except Error as err:

        print("Error fetching alerts:", err)

        return []


# ============================================================
# DATABASE STATISTICS
# ============================================================

def get_statistics():
    """
    Return basic NIDS database statistics.

    Returns
    -------
    dict
        Total logs, attacks, normal traffic and alerts.
    """

    if not ensure_connection():

        return {
            "total_logs": 0,
            "normal_logs": 0,
            "attack_logs": 0,
            "total_alerts": 0
        }

    statistics = {
        "total_logs": 0,
        "normal_logs": 0,
        "attack_logs": 0,
        "total_alerts": 0
    }

    try:

        cursor.execute(
            "SELECT COUNT(*) FROM intrusion_logs"
        )

        statistics["total_logs"] = cursor.fetchone()[0]

        cursor.execute(
            """
            SELECT COUNT(*)
            FROM intrusion_logs
            WHERE LOWER(prediction) = 'normal'
            """
        )

        statistics["normal_logs"] = cursor.fetchone()[0]

        cursor.execute(
            """
            SELECT COUNT(*)
            FROM intrusion_logs
            WHERE LOWER(prediction) <> 'normal'
            """
        )

        statistics["attack_logs"] = cursor.fetchone()[0]

        cursor.execute(
            "SELECT COUNT(*) FROM alerts"
        )

        statistics["total_alerts"] = cursor.fetchone()[0]

    except Error as err:

        print(
            "Error retrieving database statistics:",
            err
        )

    return statistics


# ============================================================
# CLOSE DATABASE CONNECTION
# ============================================================

def close_connection():
    """
    Close cursor and MySQL connection safely.
    """

    global connection
    global cursor

    try:

        if cursor is not None:

            cursor.close()

            cursor = None

        if connection is not None:

            if connection.is_connected():

                connection.close()

            connection = None

            print("MySQL Connection Closed")

    except Error as err:

        print(
            "Error closing MySQL connection:",
            err
        )


# ============================================================
# DATABASE TEST
# ============================================================

def test_database():
    """
    Test database connectivity and basic insert operations.
    """

    print("\n" + "=" * 60)
    print("NIDS DATABASE TEST")
    print("=" * 60)

    if not ensure_connection():

        print("Database connection test FAILED.")

        return False

    print("Database connection test PASSED.")

    test_log_id = process_prediction(
        "192.168.1.15",
        "192.168.1.50",
        "TCP",
        "DoS",
        0.98
    )

    if test_log_id is None:

        print("Test log insertion FAILED.")

        return False

    print(
        f"Test log successfully inserted. "
        f"Log ID: {test_log_id}"
    )

    print("\n========== RECENT LOGS ==========")

    logs = get_logs()

    for log in logs[:10]:

        print(log)

    print("\n========== RECENT ALERTS ==========")

    alerts = get_alerts()

    for alert in alerts[:10]:

        print(alert)

    print("\n========== DATABASE STATISTICS ==========")

    statistics = get_statistics()

    for key, value in statistics.items():

        print(
            f"{key}: {value}"
        )

    return True


# ============================================================
# MAIN TEST
# ============================================================

if __name__ == "__main__":

    try:

        test_database()

    finally:

        close_connection()