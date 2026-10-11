from modules.live_capture import capture_live_packets
from modules.feature_extraction import extract_features
from modules.ml_prediction import predict_attack_with_confidence


print("=" * 60)
print("NIDS LIVE AI DETECTION TEST")
print("=" * 60)

# ------------------------------------------------------------
# 1. CAPTURE PACKETS
# ------------------------------------------------------------

print("\nStarting live packet capture...")
print("Generate some network traffic while this runs.\n")

packets = capture_live_packets(20)


# ------------------------------------------------------------
# 2. EXTRACT FEATURES
# ------------------------------------------------------------

df = extract_features(packets)

print("\nPackets captured:", len(packets))
print("Feature rows:", len(df))


if df.empty:

    print("\n❌ No usable IP packets were captured.")
    print("Try browsing a website or running:")
    print("ping -4 google.com")

    raise SystemExit


# ------------------------------------------------------------
# 3. DISPLAY FEATURES
# ------------------------------------------------------------

print("\n========== EXTRACTED FEATURES ==========")

print(
    df[
        [
            "protocol_type",
            "service",
            "flag",
            "src_bytes",
            "dst_bytes"
        ]
    ].to_string(index=False)
)


# ------------------------------------------------------------
# 4. ML PREDICTION
# ------------------------------------------------------------

print("\n========== RANDOM FOREST PREDICTION ==========")

try:

    attack_names, categories, confidence = (
        predict_attack_with_confidence(df)
    )

except Exception as e:

    print("\n❌ ML prediction failed:")
    print(e)

    raise SystemExit


# ------------------------------------------------------------
# 5. DISPLAY RESULTS
# ------------------------------------------------------------

for i in range(len(attack_names)):

    print(
        f"\nPacket {i + 1}"
    )

    print(
        "Prediction :",
        attack_names[i]
    )

    print(
        "Category   :",
        categories[i]
    )

    print(
        "Confidence :",
        f"{confidence[i] * 100:.2f}%"
    )


# ------------------------------------------------------------
# 6. SUMMARY
# ------------------------------------------------------------

normal_count = sum(
    1
    for category in categories
    if category == "Normal"
)

attack_count = len(categories) - normal_count


print("\n" + "=" * 60)
print("LIVE DETECTION SUMMARY")
print("=" * 60)

print("Packets captured :", len(packets))
print("Packets analyzed :", len(df))
print("Normal traffic   :", normal_count)
print("Attacks detected :", attack_count)

print("=" * 60)