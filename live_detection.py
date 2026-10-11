try:
    from modules.live_capture import capture_live_packets
    from modules.feature_extraction import extract_features
    from modules.ml_prediction import predict_attack_with_confidence
    from modules.db_manager import process_prediction
except ImportError:  # pragma: no cover
    from live_capture import capture_live_packets
    from feature_extraction import extract_features
    from ml_prediction import predict_attack_with_confidence
    from db_manager import process_prediction


# ============================================================
# SETTINGS
# ============================================================

PACKET_COUNT = 30


# ============================================================
# MAIN LIVE DETECTION
# ============================================================

def run_live_detection(
    packet_count=PACKET_COUNT,
    iface=None
):
    """
    Run the complete NIDS pipeline.

    Pipeline:

        Packet Capture
             ↓
        Feature Extraction
             ↓
        ML Prediction
             ↓
        Attack Classification
             ↓
        Database Logging
             ↓
        Alert Generation
    """

    print("\n" + "=" * 60)
    print("NIDS LIVE AI DETECTION SYSTEM")
    print("=" * 60)

    print(
        f"\nPacket capture count: {packet_count}"
    )

    # ========================================================
    # CAPTURE PACKETS
    # ========================================================

    packets = capture_live_packets(
        packet_count=packet_count,
        iface=iface
    )

    print(
        f"\nPackets captured : {len(packets)}"
    )

    if len(packets) == 0:

        print(
            "\nNo packets were captured."
        )

        return

    # ========================================================
    # FEATURE EXTRACTION
    # ========================================================

    try:

        features = extract_features(
            packets
        )

    except Exception as err:

        print(
            "\nFeature extraction failed:"
        )

        print(err)

        return

    print(
        f"Flows analyzed   : {len(features)}"
    )

    # ========================================================
    # NO USABLE FLOWS
    # ========================================================

    if features.empty:

        print(
            "\nNo usable IP flows found."
        )

        print_summary(
            packet_count=len(packets),
            flow_count=0,
            normal_count=0,
            attack_count=0,
            database_records=0
        )

        return

    # ========================================================
    # AI PREDICTION
    # ========================================================

    print(
        "\n========== LIVE AI DETECTIONS =========="
    )

    try:

        (
            names,
            categories,
            confidence
        ) = predict_attack_with_confidence(
            features
        )

    except Exception as err:

        print(
            "\nML prediction failed:"
        )

        print(err)

        return

    # ========================================================
    # COUNTERS
    # ========================================================

    normal_count = 0

    attack_count = 0

    database_records = 0

    # ========================================================
    # PROCESS EACH FLOW
    # ========================================================

    for index in range(
        len(features)
    ):

        row = features.iloc[
            index
        ]

        prediction = str(
            names[index]
        )

        category = str(
            categories[index]
        )

        conf = float(
            confidence[index]
        )

        # ----------------------------------------------------
        # NETWORK INFORMATION
        # ----------------------------------------------------

        source_ip = row.get(
            "src_ip",
            "Unknown"
        )

        destination_ip = row.get(
            "dst_ip",
            "Unknown"
        )

        protocol = row.get(
            "protocol_type",
            "other"
        )

        # ----------------------------------------------------
        # DISPLAY FLOW
        # ----------------------------------------------------

        print(
            f"\nFlow {index + 1}"
        )

        print(
            "-" * 40
        )

        print(
            f"Source      : {source_ip}"
        )

        print(
            f"Destination : {destination_ip}"
        )

        print(
            f"Protocol    : {protocol}"
        )

        print(
            f"Prediction  : {prediction}"
        )

        print(
            f"Category    : {category}"
        )

        print(
            f"Confidence  : {conf * 100:.2f}%"
        )

        # ----------------------------------------------------
        # DATABASE
        # ----------------------------------------------------

        try:

            log_id = process_prediction(
                source_ip,
                destination_ip,
                protocol,
                prediction,
                conf
            )

            if log_id is not None:

                database_records += 1

                print(
                    f"Database Log ID: {log_id}"
                )

            else:

                print(
                    "Database logging failed."
                )

        except Exception as err:

            print(
                f"Database error: {err}"
            )

        # ----------------------------------------------------
        # COUNT NORMAL / ATTACK
        # ----------------------------------------------------

        if prediction.lower() == "normal":

            normal_count += 1

            print(
                "STATUS      : NORMAL TRAFFIC"
            )

        else:

            attack_count += 1

            print(
                "STATUS      : ATTACK DETECTED"
            )

    # ========================================================
    # FINAL SUMMARY
    # ========================================================

    print_summary(
        packet_count=len(packets),
        flow_count=len(features),
        normal_count=normal_count,
        attack_count=attack_count,
        database_records=database_records
    )


# ============================================================
# SUMMARY
# ============================================================

def print_summary(
    packet_count,
    flow_count,
    normal_count,
    attack_count,
    database_records
):

    print(
        "\n" + "=" * 60
    )

    print(
        "LIVE DETECTION SUMMARY"
    )

    print(
        "=" * 60
    )

    print(
        f"Packets captured : {packet_count}"
    )

    print(
        f"Flows analyzed   : {flow_count}"
    )

    print(
        f"Normal traffic   : {normal_count}"
    )

    print(
        f"Attacks detected : {attack_count}"
    )

    print(
        f"Database records : {database_records}"
    )

    print(
        "=" * 60
    )


# ============================================================
# PROGRAM ENTRY POINT
# ============================================================

if __name__ == "__main__":

    try:

        run_live_detection(
            packet_count=PACKET_COUNT
        )

    except KeyboardInterrupt:

        print(
            "\n\nNIDS stopped by user."
        )

    except Exception as err:

        print(
            "\nNIDS execution error:"
        )

        print(err)