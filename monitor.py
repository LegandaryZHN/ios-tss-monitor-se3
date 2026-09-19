#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import smtplib
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from email.message import EmailMessage
from pathlib import Path
from typing import Any

import requests

ROOT = Path(__file__).resolve().parent
TARGETS_FILE = ROOT / "targets.json"
STATE_FILE = ROOT / "state.json"
TSS_DIR = ROOT / "Modern_TSS_Checker"
IPSW_API = "https://api.ipsw.me/v4/device/{device}?type=ipsw"
HTTP_TIMEOUT = 30
TSS_TIMEOUT = 120
MAX_WORKERS = int(os.getenv("MAX_WORKERS", "6"))


def version_tuple(v: str) -> tuple[int, int, int]:
    m = re.fullmatch(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?", v.strip())
    if not m:
        raise ValueError(f"Invalid release version: {v}")
    return (int(m.group(1)), int(m.group(2) or 0), int(m.group(3) or 0))


def in_range(version: str, minimum: str, maximum: str) -> bool:
    v = version_tuple(version)
    return version_tuple(minimum) <= v <= version_tuple(maximum)


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"[WARN] Could not read {path}: {exc}; using empty state.", file=sys.stderr)
        return default


def save_state(state: dict[str, Any]) -> None:
    tmp = STATE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(STATE_FILE)


def fetch_ipsw_firmwares(device: str) -> list[dict[str, Any]]:
    url = IPSW_API.format(device=device)
    r = requests.get(url, timeout=HTTP_TIMEOUT)
    r.raise_for_status()
    data = r.json()
    firmwares = data.get("firmwares")
    if not isinstance(firmwares, list):
        raise RuntimeError("IPSW.me response does not contain a firmware list")
    return firmwares


def check_tss(device: str, buildid: str) -> tuple[str, int | None, str]:
    if not TSS_DIR.exists():
        return "UNKNOWN", None, "Modern_TSS_Checker directory missing"

    cmd = [
        sys.executable,
        str(TSS_DIR / "tsschecker.py"),
        "-d", device,
        "-Z", buildid,
        "--print-tss-response",
        "-v",
    ]
    try:
        proc = subprocess.run(
            cmd,
            cwd=TSS_DIR,
            capture_output=True,
            text=True,
            timeout=TSS_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        return "UNKNOWN", None, "TSS checker timed out"
    except Exception as exc:
        return "UNKNOWN", None, f"TSS checker launch failed: {exc}"

    output = (proc.stdout or "") + "\n" + (proc.stderr or "")
    status_matches = re.findall(r"(?:^|[&\s])STATUS=(-?\d+)", output)
    if not status_matches:
        detail = output.strip().splitlines()[-1] if output.strip() else f"exit={proc.returncode}"
        return "UNKNOWN", None, detail[:300]

    status = int(status_matches[-1])
    if status == 0:
        return "SIGNED", status, "STATUS=0"
    if status == 94:
        return "UNSIGNED", status, "STATUS=94"
    return "UNKNOWN", status, f"STATUS={status}"


def final_status(ipsw_signed: bool | None, tss_status: str) -> str:
    if ipsw_signed is None or tss_status == "UNKNOWN":
        return "UNKNOWN"
    tss_signed = tss_status == "SIGNED"
    if ipsw_signed and tss_signed:
        return "SIGNED_CONFIRMED"
    if not ipsw_signed and not tss_signed:
        return "UNSIGNED_CONFIRMED"
    return "CONFLICT"


def do_check(target: dict[str, str], fw: dict[str, Any]) -> dict[str, Any]:
    version = str(fw.get("version", ""))
    buildid = str(fw.get("buildid", ""))
    signed = fw.get("signed")
    if not version or not buildid or not isinstance(signed, bool):
        return {"ok": False, "reason": "Malformed IPSW.me firmware object", "firmware": fw}

    tss, tss_code, tss_detail = check_tss(target["device"], buildid)
    final = final_status(signed, tss)
    return {
        "ok": True,
        "name": target["name"],
        "device": target["device"],
        "version": version,
        "buildid": buildid,
        "ipsw_signed": signed,
        "tss_status": tss,
        "tss_code": tss_code,
        "tss_detail": tss_detail,
        "status": final,
    }


def smtp_send(subject: str, body: str) -> None:
    host = os.environ.get("SMTP_HOST")
    port = int(os.environ.get("SMTP_PORT", "465"))
    username = os.environ.get("SMTP_USERNAME")
    password = os.environ.get("SMTP_PASSWORD")
    sender = os.environ.get("MAIL_FROM") or username
    recipient = os.environ.get("MAIL_TO")
    if not all([host, username, password, sender, recipient]):
        raise RuntimeError("SMTP secrets are incomplete")

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = recipient
    msg.set_content(body)

    if port == 465:
        with smtplib.SMTP_SSL(host, port, timeout=30) as smtp:
            smtp.login(username, password)
            smtp.send_message(msg)
    else:
        with smtplib.SMTP(host, port, timeout=30) as smtp:
            smtp.starttls()
            smtp.login(username, password)
            smtp.send_message(msg)


def render_alert(
    result: dict[str, Any],
    previous_record: dict[str, Any],
    reason: str,
    changed: list[str],
) -> tuple[str, str]:
    subject = f"🚨 Apple Signing Status Changed — {result['name']} — iOS {result['version']} ({result['buildid']})"
    previous_ipsw = previous_record.get("ipsw_status", "UNKNOWN")
    previous_tss = previous_record.get("tss_status", "UNKNOWN")
    current_ipsw = "SIGNED" if result["ipsw_signed"] else "UNSIGNED"

    body = (
        "Apple firmware signing monitor alert\n\n"
        f"Device: {result['name']}\n"
        f"ProductType: {result['device']}\n"
        f"iOS: {result['version']}\n"
        f"Build: {result['buildid']}\n\n"
        f"IPSW.me: {previous_ipsw} → {current_ipsw}\n"
        f"Apple TSS: {previous_tss} → {result['tss_status']}\n"
        f"Verification: {result['status']}\n\n"
        f"Changed source(s): {'; '.join(changed)}\n"
        f"TSS detail: {result['tss_detail']}\n\n"
        "If this firmware is important to you, save the SHSH2 blob immediately.\n"
    )
    return subject, body


def main() -> int:
    targets = load_json(TARGETS_FILE, [])
    state = load_json(STATE_FILE, {})
    if not isinstance(targets, list) or not targets:
        raise RuntimeError("targets.json is empty")
    if not isinstance(state, dict):
        state = {}

    all_results: list[dict[str, Any]] = []
    for target in targets:
        device = target["device"]
        minimum = target["min_version"]
        maximum = target["max_version"]
        firmwares = fetch_ipsw_firmwares(device)
        selected = [
            fw for fw in firmwares
            if isinstance(fw, dict)
            and isinstance(fw.get("version"), str)
            and in_range(fw["version"], minimum, maximum)
            and re.fullmatch(r"\d+(?:\.\d+){1,2}", fw["version"].strip())
        ]
        # De-duplicate by Build ID and keep deterministic ordering.
        selected_by_build: dict[str, dict[str, Any]] = {
            str(fw["buildid"]): fw for fw in selected if fw.get("buildid")
        }
        selected = sorted(selected_by_build.values(), key=lambda fw: (version_tuple(fw["version"]), fw["buildid"]))
        print(f"[{device}] {len(selected)} public IPSW builds in range {minimum}–{maximum}")

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
            futures = [pool.submit(do_check, target, fw) for fw in selected]
            for future in as_completed(futures):
                result = future.result()
                if result.get("ok"):
                    all_results.append(result)
                    print(
                        f"{result['version']:>8} {result['buildid']:<10} "
                        f"IPSW={'Y' if result['ipsw_signed'] else 'N'} "
                        f"TSS={result['tss_status']:<8} -> {result['status']}"
                    )
                else:
                    print(f"[WARN] {result.get('reason')}", file=sys.stderr)

    alerts: list[tuple[str, str]] = []
    baseline: list[dict[str, Any]] = []

    for result in sorted(all_results, key=lambda r: (r["device"], version_tuple(r["version"]), r["buildid"])):
        key = f"{result['device']}:{result['buildid']}"
        previous_record = state.get(key)
        current_ipsw = "SIGNED" if result["ipsw_signed"] else "UNSIGNED"
        current_tss = result["tss_status"]

        if not isinstance(previous_record, dict) or not previous_record:
            # First run: establish the baseline and report it once.
            baseline.append(result)
        else:
            previous_ipsw = previous_record.get("ipsw_status")
            previous_tss = previous_record.get("tss_status")

            changed: list[str] = []
            if previous_ipsw in {"SIGNED", "UNSIGNED"} and current_ipsw in {"SIGNED", "UNSIGNED"} and previous_ipsw != current_ipsw:
                changed.append(f"IPSW.me: {previous_ipsw} → {current_ipsw}")

            if previous_tss in {"SIGNED", "UNSIGNED"} and current_tss in {"SIGNED", "UNSIGNED"} and previous_tss != current_tss:
                changed.append(f"Apple TSS: {previous_tss} → {current_tss}")

            if changed:
                alerts.append(
                    render_alert(
                        result,
                        previous_record,
                        "Status changed: " + "; ".join(changed),
                        changed,
                    )
                )

        state[key] = {
            "name": result["name"],
            "device": result["device"],
            "version": result["version"],
            "buildid": result["buildid"],
            "ipsw_status": current_ipsw,
            "tss_status": current_tss,
            "status": result["status"],
        }

    if baseline:
        lines = [
            "Initial baseline for Apple firmware signing monitor",
            "",
            "The following status was recorded on the first run. Future emails are sent only when IPSW.me or Apple TSS changes between SIGNED and UNSIGNED.",
            "",
        ]
        for r in sorted(baseline, key=lambda x: (version_tuple(x["version"]), x["buildid"])):
            ipsw_status = "SIGNED" if r["ipsw_signed"] else "UNSIGNED"
            lines.append(
                f"iOS {r['version']} ({r['buildid']}) — IPSW.me: {ipsw_status} | Apple TSS: {r['tss_status']} | Verification: {r['status']}"
            )
        alerts.insert(0, ("📋 Initial Signing Baseline — iPhone SE 3rd", "\n".join(lines)))

    save_state(state)

    for subject, body in alerts:
        smtp_send(subject, body)
        print(f"[MAIL] Sent: {subject}")

    print(f"Completed: {len(all_results)} builds checked, {len(alerts)} email(s) sent.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"[FATAL] {exc}", file=sys.stderr)
        raise
