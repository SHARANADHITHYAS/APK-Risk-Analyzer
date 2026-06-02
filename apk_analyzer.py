from __future__ import annotations

import math
import os
import re
import zipfile


SUSPICIOUS_PERMISSIONS = {
    "android.permission.SEND_SMS": 1.8,
    "android.permission.RECEIVE_SMS": 1.6,
    "android.permission.READ_SMS": 1.6,
    "android.permission.WRITE_SMS": 1.5,
    "android.permission.READ_CONTACTS": 1.2,
    "android.permission.WRITE_CONTACTS": 1.1,
    "android.permission.READ_CALL_LOG": 1.1,
    "android.permission.WRITE_CALL_LOG": 1.1,
    "android.permission.RECORD_AUDIO": 0.9,
    "android.permission.CAMERA": 0.8,
    "android.permission.ACCESS_FINE_LOCATION": 0.5,
    "android.permission.ACCESS_COARSE_LOCATION": 0.4,
    "android.permission.SYSTEM_ALERT_WINDOW": 1.2,
    "android.permission.REQUEST_INSTALL_PACKAGES": 1.5,
    "android.permission.QUERY_ALL_PACKAGES": 1.1,
    "android.permission.BIND_ACCESSIBILITY_SERVICE": 1.8,
    "android.permission.INTERNET": 0.3,
}


SUSPICIOUS_NAME_HINTS = {
    "payload": 1.4,
    "shell": 1.2,
    "dropper": 1.3,
    "inject": 1.0,
    "stub": 0.9,
    "loader": 1.0,
    "exploit": 1.5,
    "trojan": 1.7,
    "malware": 2.0,
    "obfus": 0.8,
    "packer": 0.9,
}


def _extract_printable_strings(blob):
    matches = re.findall(rb"[ -~]{4,}", blob)
    return {match.decode("utf-8", errors="ignore") for match in matches}


def _sigmoid(value):
    if value >= 60:
        return 1.0
    if value <= -60:
        return 0.0
    return 1.0 / (1.0 + math.exp(-value))


def _score_features(features):
    score = -1.6

    if not features["has_manifest"]:
        score += 2.0

    if not features["has_signature"]:
        score += 1.1

    if features["dex_count"] > 1:
        score += min(1.0, (features["dex_count"] - 1) * 0.25)

    if features["native_lib_count"]:
        score += min(1.0, features["native_lib_count"] * 0.2)

    if features["asset_count"] > 40:
        score += 0.4

    for permission in features["permissions"]:
        score += SUSPICIOUS_PERMISSIONS.get(permission, 0)

    for hint, weight in SUSPICIOUS_NAME_HINTS.items():
        if hint in features["name_blob"]:
            score += weight

    if features["file_count"] > 300:
        score += 0.4

    if features["has_classes_marker"] and features["dex_count"] > 2:
        score += 0.5

    return score


def _build_features(file_path):
    with zipfile.ZipFile(file_path, "r") as zip_ref:
        names = zip_ref.namelist()
        name_blob = " ".join(name.lower() for name in names)
        has_signature = any(name.upper().startswith("META-INF/") for name in names)
        manifest_bytes = b""

        for candidate in names:
            if candidate.endswith("AndroidManifest.xml"):
                manifest_bytes = zip_ref.read(candidate)
                break

        manifest_strings = _extract_printable_strings(manifest_bytes) if manifest_bytes else set()
        permissions = {value for value in manifest_strings if value.startswith("android.permission.")}

        return {
            "file_count": len(names),
            "dex_count": sum(1 for name in names if name.endswith(".dex")),
            "native_lib_count": sum(1 for name in names if name.endswith(".so")),
            "asset_count": sum(1 for name in names if name.startswith("assets/")),
            "has_manifest": bool(manifest_bytes),
            "has_signature": has_signature,
            "permissions": sorted(permission for permission in permissions if permission in SUSPICIOUS_PERMISSIONS),
            "name_blob": name_blob,
            "has_classes_marker": any(name.startswith("classes") and name.endswith(".dex") for name in names),
        }


def analyze_apk(file_path):
    try:
        if not os.path.isfile(file_path):
            return {
                "verdict": "dangerous",
                "label": "Dangerous",
                "confidence": 0.0,
                "risk_score": 0.0,
                "summary": "The selected file does not exist.",
                "reasons": ["The selected file does not exist."],
                "features": {},
            }

        features = _build_features(file_path)
        score = _score_features(features)
        confidence = _sigmoid(score)

        if confidence >= 0.75:
            verdict = "dangerous"
            label = "Dangerous / malware suspected"
        elif confidence >= 0.5:
            verdict = "suspicious"
            label = "Potentially dangerous"
        else:
            verdict = "safe"
            label = "Safe to use"

        reasons = []
        if not features["has_manifest"]:
            reasons.append("AndroidManifest.xml was not found in the APK.")
        if not features["has_signature"]:
            reasons.append("No META-INF signature files were found.")
        if features["permissions"]:
            reasons.append("Suspicious permissions detected: " + ", ".join(features["permissions"]))
        if features["dex_count"] > 1:
            reasons.append(f"Multiple DEX files detected ({features['dex_count']}).")
        if features["native_lib_count"]:
            reasons.append(f"Native libraries found ({features['native_lib_count']}).")
        if not reasons:
            reasons.append("No strong static risk indicators were found.")

        summary = (
            f"{label} (confidence: {confidence * 100:.1f}%). "
            f"This is a static APK risk estimate, not a guarantee of safety."
        )

        return {
            "verdict": verdict,
            "label": label,
            "confidence": confidence,
            "risk_score": score,
            "summary": summary,
            "reasons": reasons,
            "features": features,
            "file_size_kb": os.path.getsize(file_path) / 1024,
            "file_name": os.path.basename(file_path),
        }

    except zipfile.BadZipFile:
        return {
            "verdict": "dangerous",
            "label": "Dangerous",
            "confidence": 1.0,
            "risk_score": 10.0,
            "summary": "The file is not a valid APK archive.",
            "reasons": ["The file is not a valid APK archive."],
            "features": {},
            "file_name": os.path.basename(file_path),
        }
    except Exception as exc:
        return {
            "verdict": "dangerous",
            "label": "Dangerous",
            "confidence": 1.0,
            "risk_score": 10.0,
            "summary": str(exc),
            "reasons": [str(exc)],
            "features": {},
            "file_name": os.path.basename(file_path),
        }


def format_report(report):
    lines = [
        f"File: {report.get('file_name', 'Unknown')}",
        f"Verdict: {report['label']}",
        f"Confidence: {report['confidence'] * 100:.1f}%",
        f"APK Size: {report.get('file_size_kb', 0.0):.2f} KB",
        "",
        report["summary"],
        "",
        "Reasons:",
    ]
    lines.extend(f"- {reason}" for reason in report.get("reasons", []))
    return "\n".join(lines)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python apk_analyzer.py <path-to-apk>")
    else:
        print(format_report(analyze_apk(sys.argv[1])))
