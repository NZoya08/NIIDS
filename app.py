from flask import Flask, jsonify, request
from flask_cors import CORS

import os
import tempfile

from modules.pcap_reader import read_pcap
from modules.feature_extraction import extract_features
from modules.ml_prediction import predict_attack_with_confidence

from modules.db_manager import (
    process_prediction,
    get_logs,
    get_alerts
)

from modules.model_evaluation import evaluate_model


# ============================================================
# FLASK APPLICATION
# ============================================================

app = Flask(__name__)
CORS(app)


# ============================================================
# HOME / API STATUS
# ============================================================

@app.route("/", methods=["GET"])
def home():

    return jsonify({
        "status": "success",
        "message": "NIDS API is running"
    })


# ============================================================
# GET INTRUSION LOGS
# ============================================================

@app.route("/api/logs", methods=["GET"])
def logs():

    try:

        rows = get_logs()

        data = []

        for row in rows:

            # Database column order:
            #
            # row[0] = id
            # row[1] = timestamp
            # row[2] = source_ip
            # row[3] = destination_ip
            # row[4] = protocol
            # row[5] = prediction
            # row[6] = confidence

            data.append({
                "id": row[0],
                "timestamp": str(row[1]),
                "source_ip": row[2],
                "destination_ip": row[3],
                "protocol": row[4],
                "prediction": row[5],
                "confidence": float(row[6])
            })

        return jsonify(data)

    except Exception as e:

        return jsonify({
            "status": "error",
            "error": str(e)
        }), 500


# ============================================================
# GET SECURITY ALERTS
# ============================================================

@app.route("/api/alerts", methods=["GET"])
def alerts():

    try:

        rows = get_alerts()

        data = []

        for row in rows:

            # Expected alerts table order:
            #
            # row[0] = id
            # row[1] = log_id
            # row[2] = alert_level
            # row[3] = message
            # row[4] = alert_time

            data.append({
                "id": row[0],
                "log_id": row[1],
                "alert_level": row[2],
                "message": row[3],
                "alert_time": str(row[4])
            })

        return jsonify(data)

    except Exception as e:

        return jsonify({
            "status": "error",
            "error": str(e)
        }), 500


# ============================================================
# DASHBOARD STATISTICS
# ============================================================

@app.route("/api/stats", methods=["GET"])
def stats():

    try:

        rows = get_logs()

        total = len(rows)
        attacks = 0
        normal = 0

        attack_types = {}

        for row in rows:

            # IMPORTANT:
            # row[5] is prediction
            prediction = str(row[5])

            if prediction.lower() == "normal":

                normal += 1

            else:

                attacks += 1

                attack_types[prediction] = (
                    attack_types.get(prediction, 0) + 1
                )

        attack_rate = 0

        if total > 0:

            attack_rate = (
                attacks / total
            ) * 100

        return jsonify({

            "status": "success",

            "total_logs": total,

            "total_attacks": attacks,

            "normal_traffic": normal,

            "attack_rate": round(
                attack_rate,
                2
            ),

            "attack_types": attack_types

        })

    except Exception as e:

        return jsonify({

            "status": "error",

            "error": str(e)

        }), 500


# ============================================================
# ANALYZE PCAP FILE
# ============================================================

@app.route("/api/analyze-pcap", methods=["POST"])
def analyze_pcap():

    # --------------------------------------------------------
    # CHECK FILE
    # --------------------------------------------------------

    if "file" not in request.files:

        return jsonify({
            "status": "error",
            "error": "No PCAP file uploaded"
        }), 400

    uploaded_file = request.files["file"]

    # --------------------------------------------------------
    # CHECK FILE NAME
    # --------------------------------------------------------

    if uploaded_file.filename == "":

        return jsonify({
            "status": "error",
            "error": "No file selected"
        }), 400

    # --------------------------------------------------------
    # CHECK EXTENSION
    # --------------------------------------------------------

    if not uploaded_file.filename.lower().endswith(".pcap"):

        return jsonify({
            "status": "error",
            "error": "Please upload a .pcap file"
        }), 400

    temp_path = None

    try:

        # ====================================================
        # SAVE TEMPORARY PCAP
        # ====================================================

        with tempfile.NamedTemporaryFile(
            delete=False,
            suffix=".pcap"
        ) as temp_file:

            uploaded_file.save(temp_file.name)
            temp_path = temp_file.name

        # ====================================================
        # READ PCAP
        # ====================================================

        packets = read_pcap(temp_path)

        if len(packets) == 0:

            return jsonify({
                "status": "error",
                "error": "PCAP file contains no packets"
            }), 400

        # ====================================================
        # KEEP ONLY IP PACKETS
        # ====================================================

        ip_packets = [
            packet
            for packet in packets
            if "IP" in packet
        ]

        if len(ip_packets) == 0:

            return jsonify({
                "status": "error",
                "error": "No IP packets found in PCAP"
            }), 400

        # ====================================================
        # FEATURE EXTRACTION
        # ====================================================

        features = extract_features(ip_packets)

        if features.empty:

            return jsonify({
                "status": "error",
                "error": "Unable to extract features from PCAP"
            }), 400

        # ====================================================
        # ML PREDICTION
        # ====================================================

        attack_names, categories, confidence = (
            predict_attack_with_confidence(features)
        )

        # ====================================================
        # VERIFY COUNTS
        # ====================================================

        if len(ip_packets) != len(attack_names):

            return jsonify({
                "status": "error",
                "error": (
                    "Packet count and prediction count do not match"
                )
            }), 500

        # ====================================================
        # PROCESS RESULTS
        # ====================================================

        results = []

        attack_packets = 0
        normal_packets = 0

        category_distribution = {}

        protocol_names = {
            1: "ICMP",
            6: "TCP",
            17: "UDP"
        }

        for index, packet in enumerate(ip_packets):

            # ------------------------------------------------
            # IP INFORMATION
            # ------------------------------------------------

            source_ip = packet["IP"].src
            destination_ip = packet["IP"].dst

            # ------------------------------------------------
            # PREDICTION
            # ------------------------------------------------

            prediction = str(
                attack_names[index]
            )

            category = str(
                categories[index]
            )

            score = float(
                confidence[index]
            )

            # ------------------------------------------------
            # PROTOCOL
            # ------------------------------------------------

            protocol_number = packet["IP"].proto

            protocol = protocol_names.get(
                protocol_number,
                str(protocol_number)
            )

            # ------------------------------------------------
            # COUNT NORMAL / ATTACK
            # ------------------------------------------------

            if prediction.lower() == "normal":

                normal_packets += 1

            else:

                attack_packets += 1

            # ------------------------------------------------
            # CATEGORY DISTRIBUTION
            # ------------------------------------------------

            category_distribution[category] = (
                category_distribution.get(category, 0) + 1
            )

            # ------------------------------------------------
            # SAVE TO DATABASE
            # ------------------------------------------------

            log_id = process_prediction(

                source_ip,
                destination_ip,
                protocol,
                prediction,
                score

            )

            # ------------------------------------------------
            # RESULT
            # ------------------------------------------------

            results.append({

                "log_id": log_id,

                "source_ip": source_ip,

                "destination_ip": destination_ip,

                "protocol": protocol,

                "prediction": prediction,

                "category": category,

                "confidence": round(
                    score * 100,
                    2
                )

            })

        # ====================================================
        # FINAL RESPONSE
        # ====================================================

        return jsonify({

            "status": "success",

            "packets_analyzed": len(results),

            "attack_packets": attack_packets,

            "normal_packets": normal_packets,

            "category_distribution":
                category_distribution,

            "results": results

        })

    # ========================================================
    # ERROR HANDLING
    # ========================================================

    except Exception as e:

        return jsonify({

            "status": "error",

            "error": str(e)

        }), 500

    # ========================================================
    # DELETE TEMP FILE
    # ========================================================

    finally:

        if (
            temp_path
            and os.path.exists(temp_path)
        ):

            try:

                os.remove(temp_path)

            except Exception:

                pass


# ============================================================
# MODEL EVALUATION
# ============================================================

@app.route("/api/evaluation", methods=["GET"])
def evaluation():

    try:

        results = evaluate_model()

        return jsonify({

            "status": "success",

            **results

        })

    except Exception as e:

        return jsonify({

            "status": "error",

            "error": str(e)

        }), 500


# ============================================================
# RUN FLASK SERVER
# ============================================================

if __name__ == "__main__":

    print("=" * 60)
    print("🛡️  NETWORK INTRUSION DETECTION SYSTEM")
    print("=" * 60)
    print("🚀 Flask backend starting...")
    print("🌐 API: http://127.0.0.1:5000")
    print("📊 Evaluation: http://127.0.0.1:5000/api/evaluation")
    print("📋 Logs: http://127.0.0.1:5000/api/logs")
    print("🚨 Alerts: http://127.0.0.1:5000/api/alerts")
    print("📈 Stats: http://127.0.0.1:5000/api/stats")
    print("📁 PCAP: http://127.0.0.1:5000/api/analyze-pcap")
    print("=" * 60)

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )