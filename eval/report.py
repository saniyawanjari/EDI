"""Metrics and report files for the evaluation (Phase 7).

Pure functions (pandas / numpy / matplotlib only), so they can be tested without servers.
Positive class = ATTACK (expected DENY).
  TP attack denied   FN attack allowed   FP legitimate denied   TN legitimate allowed
"""
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")  # draw to files, no window needed
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

FULL_SYSTEM = ("full", "opa_down")  # the real system (opa_down = full mode with OPA unreachable)


def latency_stats(values) -> dict:
    data = [float(v) for v in values if v is not None and not pd.isna(v)]
    if not data:
        return {"count": 0, "mean": None, "p50": None, "p95": None, "p99": None}
    return {"count": len(data), "mean": round(float(np.mean(data)), 3),
            "p50": round(float(np.percentile(data, 50)), 3),
            "p95": round(float(np.percentile(data, 95)), 3),
            "p99": round(float(np.percentile(data, 99)), 3)}


def confusion_metrics(df: pd.DataFrame) -> dict:
    attack = df["expected"] == "DENY"
    denied = df["decision"] == "DENY"
    tp = int((attack & denied).sum())
    fn = int((attack & ~denied).sum())
    fp = int((~attack & denied).sum())
    tn = int((~attack & ~denied).sum())

    def ratio(a, b):
        return round(a / b, 4) if b else None

    return {
        "n": int(len(df)), "TP": tp, "FN": fn, "FP": fp, "TN": tn,
        "accuracy": ratio(tp + tn, len(df)),
        "precision": ratio(tp, tp + fp),
        "recall": ratio(tp, tp + fn),
        "false_positive_rate": ratio(fp, fp + tn),   # legitimate requests that were denied
        "false_negative_rate": ratio(fn, fn + tp),   # attacks that were allowed
        "confusion_matrix": {"rows": ["actual attack", "actual legitimate"],
                             "columns": ["predicted deny", "predicted allow"],
                             "values": [[tp, fn], [fp, tn]]},
    }


def summarize(rows: list[dict]) -> dict:
    df = pd.DataFrame(rows)
    full = df[df["mode"].isin(FULL_SYSTEM)]
    summary = {
        "runs": int(df["run"].max()),
        "scenarios_per_run": int(len(full[full["run"] == 1])),
        "full_system": confusion_metrics(full),
        "latency_ms": {
            "total_decision_time": latency_stats(full["decision_ms"]),
            "token_verification_time": latency_stats(full["token_verify_ms"]),
            "opa_time": latency_stats(full["opa_ms"]),
        },
        "accuracy_by_type": {},
        "modes": {},
        "mistakes": [],
    }

    for type_name, group in full.groupby("type"):
        summary["accuracy_by_type"][type_name] = {
            "n": int(len(group)), "correct": int(group["correct"].sum()),
            "accuracy": round(float(group["correct"].mean()), 4)}

    # Weak baselines vs the real system: how many attacks get through?
    for mode in ("full", "header_only", "none"):
        part = df[df["mode"] == mode]
        if part.empty:
            continue
        attacks = part[part["expected"] == "DENY"]
        legit = part[part["expected"] == "ALLOW"]
        succeeded = int((attacks["decision"] == "ALLOW").sum())
        summary["modes"][mode] = {
            "attack_requests": int(len(attacks)),
            "attacks_succeeded": succeeded,
            "attacks_blocked": int(len(attacks)) - succeeded,
            "attack_success_rate": round(succeeded / len(attacks), 4) if len(attacks) else None,
            "legit_mean_decision_ms": latency_stats(legit["decision_ms"])["mean"],
            "legit_mean_request_ms": latency_stats(legit["request_ms"])["mean"],
        }

    wrong = full[~full["correct"]]
    for (sid, name, type_name, expected), group in wrong.groupby(["scenario_id", "name", "type", "expected"]):
        summary["mistakes"].append({
            "scenario_id": sid, "name": name, "type": type_name, "expected": expected,
            "got_status": [int(s) for s in sorted(set(group["status"]))], "times": int(len(group))})
    return summary


# ------------------------------------------------------------------ files
def _bar(ax, labels, values, colors, title, ylabel):
    ax.bar(labels, values, color=colors)
    ax.set_title(title)
    ax.set_ylabel(ylabel)
    ax.tick_params(axis="x", rotation=20)


def make_charts(df: pd.DataFrame, summary: dict, out: Path) -> None:
    full = df[df["mode"].isin(FULL_SYSTEM)]

    # 1) accuracy by scenario type
    types = summary["accuracy_by_type"]
    fig, ax = plt.subplots(figsize=(9, 6))
    names = list(types)
    ax.barh(names, [types[n]["accuracy"] * 100 for n in names], color="#2e8b57")
    ax.set_xlim(0, 105)
    ax.set_xlabel("Accuracy (%)")
    ax.set_title("Authorization accuracy by scenario type (full system)")
    fig.tight_layout()
    fig.savefig(out / "accuracy_by_type.png", dpi=150)
    plt.close(fig)

    # 2) latency histogram with p95 line
    values = full["decision_ms"].dropna()
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.hist(values, bins=40, color="#4682b4")
    p95 = summary["latency_ms"]["total_decision_time"]["p95"]
    if p95 is not None:
        ax.axvline(p95, color="red", linestyle="--", label=f"p95 = {p95} ms")
        ax.legend()
    ax.set_xlabel("Total decision time (ms)")
    ax.set_ylabel("Requests")
    ax.set_title("Decision latency (full system)")
    fig.tight_layout()
    fig.savefig(out / "latency_histogram.png", dpi=150)
    plt.close(fig)

    # 3) overhead: full vs header_only vs none (legitimate requests only)
    modes = [m for m in ("full", "header_only", "none") if m in summary["modes"]]
    x = np.arange(len(modes))
    decision = [summary["modes"][m]["legit_mean_decision_ms"] or 0 for m in modes]
    request = [summary["modes"][m]["legit_mean_request_ms"] or 0 for m in modes]
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.bar(x - 0.2, decision, 0.4, label="decision time", color="#4682b4")
    ax.bar(x + 0.2, request, 0.4, label="whole request", color="#f0ad4e")
    ax.set_xticks(x, modes)
    ax.set_ylabel("Mean time (ms)")
    ax.set_title("Overhead of the security layers (legitimate requests)")
    ax.legend()
    fig.tight_layout()
    fig.savefig(out / "overhead_by_mode.png", dpi=150)
    plt.close(fig)

    # 4) attacks blocked per mode
    fig, ax = plt.subplots(figsize=(8, 5))
    blocked = [summary["modes"][m]["attacks_blocked"] for m in modes]
    total = [summary["modes"][m]["attack_requests"] for m in modes]
    ax.bar(modes, total, color="#dddddd", label="attack requests")
    ax.bar(modes, blocked, color="#2e8b57", label="blocked")
    ax.set_ylabel("Requests")
    ax.set_title("Attacks blocked per security mode")
    ax.legend()
    fig.tight_layout()
    fig.savefig(out / "attacks_blocked_by_mode.png", dpi=150)
    plt.close(fig)


def markdown_table(summary: dict) -> str:
    fs = summary["full_system"]
    lat = summary["latency_ms"]
    lines = [
        "## Evaluation results", "",
        f"{summary['scenarios_per_run']} scenarios x {summary['runs']} runs (full system, positive class = attack).", "",
        "| Metric | Value |", "|---|---|",
        f"| Accuracy | {fs['accuracy']} |", f"| Precision | {fs['precision']} |",
        f"| Recall | {fs['recall']} |", f"| False-positive rate | {fs['false_positive_rate']} |",
        f"| False-negative rate | {fs['false_negative_rate']} |",
        f"| TP / FN / FP / TN | {fs['TP']} / {fs['FN']} / {fs['FP']} / {fs['TN']} |", "",
        "| Latency (ms) | mean | p50 | p95 | p99 |", "|---|---|---|---|---|",
    ]
    for label, key in [("Total decision time", "total_decision_time"),
                       ("Token verification", "token_verification_time"), ("OPA call", "opa_time")]:
        s = lat[key]
        lines.append(f"| {label} | {s['mean']} | {s['p50']} | {s['p95']} | {s['p99']} |")
    lines += ["", "| Security mode | Attack requests | Attacks succeeded | Success rate | Mean decision ms |",
              "|---|---|---|---|---|"]
    for mode, m in summary["modes"].items():
        lines.append(f"| {mode} | {m['attack_requests']} | {m['attacks_succeeded']} | "
                     f"{m['attack_success_rate']} | {m['legit_mean_decision_ms']} |")
    lines += ["", "| Scenario type | n | Accuracy |", "|---|---|---|"]
    for name, t in summary["accuracy_by_type"].items():
        lines.append(f"| {name} | {t['n']} | {t['accuracy']} |")
    lines += ["", "**Mistakes (full system):** " +
              ("none" if not summary["mistakes"] else
               ", ".join(f"{m['scenario_id']} ({m['type']})" for m in summary["mistakes"]))]
    return "\n".join(lines) + "\n"


def write_all(rows: list[dict], summary: dict, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    df = pd.DataFrame(rows)
    df.to_csv(out_dir / "results.csv", index=False)
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    (out_dir / "results.md").write_text(markdown_table(summary), encoding="utf-8")
    make_charts(df, summary, out_dir)
