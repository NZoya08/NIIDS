from scapy.all import IP, TCP, UDP, ICMP
import pandas as pd
from datetime import datetime


# ============================================================
# SERVICE MAP
# ============================================================

SERVICE_MAP = {
    20: "ftp_data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "domain",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "http_443",
    3306: "mysql",
    8080: "http",
}


# ============================================================
# PROTOCOL
# ============================================================

def get_protocol(packet):

    if TCP in packet:
        return "tcp"

    if UDP in packet:
        return "udp"

    if ICMP in packet:
        return "icmp"

    return "other"


# ============================================================
# SERVICE
# ============================================================

def get_service(packet):

    port = None

    if TCP in packet:
        port = int(packet[TCP].dport)

    elif UDP in packet:
        port = int(packet[UDP].dport)

    return SERVICE_MAP.get(
        port,
        "other"
    )


# ============================================================
# TCP FLAG
# IMPORTANT:
# Saved encoder expects UPPERCASE NSL-KDD flag values.
# ============================================================

def get_flag(packet):

    if TCP not in packet:
        return "OTH"

    flags = str(packet[TCP].flags).upper()

    # SYN only
    if flags == "S":
        return "S0"

    # SYN + ACK
    if flags == "SA":
        return "S1"

    # Normal established/finished traffic
    if flags in ["A", "PA", "FA"]:
        return "SF"

    # Reset / rejected traffic
    if "R" in flags:

        if flags == "RSTO":
            return "RSTO"

        if flags == "RSTOS0":
            return "RSTOS0"

        if flags == "RSTR":
            return "RSTR"

        return "REJ"

    # Other valid NSL-KDD style states
    if flags == "S2":
        return "S2"

    if flags == "S3":
        return "S3"

    if flags == "SH":
        return "SH"

    return "OTH"


# ============================================================
# SOURCE PORT
# ============================================================

def get_src_port(packet):

    if TCP in packet:
        return int(packet[TCP].sport)

    if UDP in packet:
        return int(packet[UDP].sport)

    return 0


# ============================================================
# DESTINATION PORT
# ============================================================

def get_dst_port(packet):

    if TCP in packet:
        return int(packet[TCP].dport)

    if UDP in packet:
        return int(packet[UDP].dport)

    return 0


# ============================================================
# FLOW KEY
# ============================================================

def get_flow_key(packet):

    if IP not in packet:
        return None

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    protocol = get_protocol(packet)

    src_port = get_src_port(packet)
    dst_port = get_dst_port(packet)

    return (
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol
    )


# ============================================================
# FLOW EXTRACTION
# ============================================================

def extract_features(packets):

    flows = {}

    for packet in packets:

        # ----------------------------------------------------
        # Only IPv4 packets
        # ----------------------------------------------------

        if IP not in packet:
            continue

        key = get_flow_key(packet)

        if key is None:
            continue

        (
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol
        ) = key

        packet_length = len(packet)

        timestamp = float(
            getattr(
                packet,
                "time",
                datetime.now().timestamp()
            )
        )

        # ----------------------------------------------------
        # CREATE NEW FLOW
        # ----------------------------------------------------

        if key not in flows:

            flows[key] = {

                "src_ip": src_ip,
                "dst_ip": dst_ip,

                "src_port": src_port,
                "dst_port": dst_port,

                "protocol_type": protocol,

                "first_time": timestamp,
                "last_time": timestamp,

                "src_bytes": 0,
                "dst_bytes": 0,

                "packet_count": 0,

                "src_packet_count": 0,
                "dst_packet_count": 0,

                "syn_count": 0,
                "ack_count": 0,
                "rst_count": 0,
                "fin_count": 0,

                "service": get_service(packet),

                "flag": get_flag(packet)
            }

        flow = flows[key]

        # ----------------------------------------------------
        # UPDATE TIME
        # ----------------------------------------------------

        flow["last_time"] = max(
            flow["last_time"],
            timestamp
        )

        # ----------------------------------------------------
        # PACKET COUNT
        # ----------------------------------------------------

        flow["packet_count"] += 1

        # ----------------------------------------------------
        # SOURCE / DESTINATION BYTES
        #
        # For a unidirectional flow, captured packets belong
        # to the source side.
        # ----------------------------------------------------

        flow["src_bytes"] += packet_length

        flow["src_packet_count"] += 1

        # ----------------------------------------------------
        # UPDATE CURRENT FLAG
        # ----------------------------------------------------

        flow["flag"] = get_flag(packet)

        # ----------------------------------------------------
        # TCP FLAGS
        # ----------------------------------------------------

        if TCP in packet:

            flags = str(
                packet[TCP].flags
            ).upper()

            if "S" in flags:
                flow["syn_count"] += 1

            if "A" in flags:
                flow["ack_count"] += 1

            if "R" in flags:
                flow["rst_count"] += 1

            if "F" in flags:
                flow["fin_count"] += 1

    # ========================================================
    # CONVERT FLOWS TO DATAFRAME ROWS
    # ========================================================

    rows = []

    for flow in flows.values():

        # ----------------------------------------------------
        # DURATION
        # ----------------------------------------------------

        duration = (
            flow["last_time"]
            - flow["first_time"]
        )

        if duration <= 0:
            duration = 0.001

        # ----------------------------------------------------
        # PACKET COUNT
        # ----------------------------------------------------

        packet_count = flow["packet_count"]

        if packet_count <= 0:
            packet_count = 1

        # ----------------------------------------------------
        # RATES
        # ----------------------------------------------------

        syn_rate = (
            flow["syn_count"]
            / packet_count
        )

        rst_rate = (
            flow["rst_count"]
            / packet_count
        )

        # ----------------------------------------------------
        # NSL-KDD STYLE ROW
        # ----------------------------------------------------

        row = {

            # ----------------------------------------------
            # Basic connection features
            # ----------------------------------------------

            "duration":
                duration,

            "protocol_type":
                flow["protocol_type"],

            "service":
                flow["service"],

            "flag":
                flow["flag"],

            "src_bytes":
                flow["src_bytes"],

            "dst_bytes":
                flow["dst_bytes"],

            # ----------------------------------------------
            # Basic security features
            # ----------------------------------------------

            "land":
                int(
                    flow["src_ip"]
                    == flow["dst_ip"]
                    and
                    flow["src_port"]
                    == flow["dst_port"]
                ),

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

            # ----------------------------------------------
            # Traffic statistics
            # ----------------------------------------------

            "count":
                packet_count,

            "srv_count":
                packet_count,

            # ----------------------------------------------
            # Error rates
            # ----------------------------------------------

            "serror_rate":
                syn_rate,

            "srv_serror_rate":
                syn_rate,

            "rerror_rate":
                rst_rate,

            "srv_rerror_rate":
                rst_rate,

            # ----------------------------------------------
            # Service statistics
            # ----------------------------------------------

            "same_srv_rate":
                1.0,

            "diff_srv_rate":
                0.0,

            "srv_diff_host_rate":
                0.0,

            # ----------------------------------------------
            # Destination host statistics
            # ----------------------------------------------

            "dst_host_count":
                packet_count,

            "dst_host_srv_count":
                packet_count,

            "dst_host_same_srv_rate":
                1.0,

            "dst_host_diff_srv_rate":
                0.0,

            "dst_host_same_src_port_rate":
                1.0,

            "dst_host_srv_diff_host_rate":
                0.0,

            "dst_host_serror_rate":
                syn_rate,

            "dst_host_srv_serror_rate":
                syn_rate,

            "dst_host_rerror_rate":
                rst_rate,

            "dst_host_srv_rerror_rate":
                rst_rate,

            # ----------------------------------------------
            # NSL-KDD difficulty
            # ----------------------------------------------

            "difficulty":
                0,

            # ----------------------------------------------
            # Extra live-system fields
            # ----------------------------------------------

            "src_ip":
                flow["src_ip"],

            "dst_ip":
                flow["dst_ip"],

            "src_port":
                flow["src_port"],

            "dst_port":
                flow["dst_port"],

            "packet_count":
                flow["packet_count"],

            "syn_count":
                flow["syn_count"],

            "ack_count":
                flow["ack_count"],

            "rst_count":
                flow["rst_count"],

            "fin_count":
                flow["fin_count"]
        }

        rows.append(row)

    # ========================================================
    # RETURN DATAFRAME
    # ========================================================

    return pd.DataFrame(rows)


# ============================================================
# DIRECT TEST
# ============================================================

if __name__ == "__main__":

    print("=" * 60)
    print("NIDS FEATURE EXTRACTION MODULE")
    print("=" * 60)

    print("\nModule loaded successfully.")

    print("\nSupported services:")

    for port, service in SERVICE_MAP.items():
        print(
            f"{port:<6} -> {service}"
        )

    print("\nFeature extraction module ready.")