import json
import os

from ai.ai_engine import generate_suggestion
from scanners.code_scanner import scan_code
from scanners.config_scanner import scan_config
from scanners.dependency_scanner import scan_dependencies
from utils.file_loader import read_file


def calculate_score(results):
    high_count = sum(1 for result in results if result["severity"] == "High")
    medium_count = sum(1 for result in results if result["severity"] == "Medium")
    low_count = sum(1 for result in results if result["severity"] == "Low")

    score = 100
    score -= min(high_count * 6, 45)
    score -= min(medium_count * 3, 25)
    score -= min(low_count * 1, 10)

    return max(score, 0)


def deduplicate_results(results):
    seen = set()
    unique_results = []

    for result in results:
        key = (
            result.get("type"),
            result.get("file"),
            result.get("line"),
            result.get("message"),
            result.get("package"),
            result.get("cve_id"),
        )

        if key not in seen:
            seen.add(key)
            unique_results.append(result)

    return unique_results


def summarize_results(results):
    summary = {
        "total_issues": len(results),
        "by_severity": {
            "High": 0,
            "Medium": 0,
            "Low": 0,
        },
        "by_source": {
            "dependency": 0,
            "code": 0,
            "config": 0,
        },
    }

    for result in results:
        severity = result.get("severity")
        source = result.get("source")

        if severity in summary["by_severity"]:
            summary["by_severity"][severity] += 1

        if source in summary["by_source"]:
            summary["by_source"][source] += 1

    return summary


def main():
    base_path = "../"
    results = []

    requirements_path = os.path.join(base_path, "requirements.txt")
    requirements_content = read_file(requirements_path)

    if requirements_content:
        results.extend(scan_dependencies(requirements_content))
    else:
        print("requirements.txt not found")

    code_path = os.path.join(base_path, "vulnerable.py")
    code_content = read_file(code_path)

    if code_content:
        results.extend(scan_code(code_content, "vulnerable.py"))
    else:
        print("vulnerable.py not found")

    config_path = os.path.join(base_path, "config.yaml")
    config_content = read_file(config_path)

    if config_content:
        results.extend(scan_config(config_content, "config.yaml"))
    else:
        print("config.yaml not found")

    results = deduplicate_results(results)

    for result in results:
        if result.get("suggestion") is None or result.get("explanation") is None:
            suggestion_data = generate_suggestion(result)
            result["suggestion"] = suggestion_data.get("fix")
            result["explanation"] = suggestion_data.get("explanation")

    score = calculate_score(results)
    summary = summarize_results(results)

    print("\nFinal Scan Results:\n")
    print(json.dumps(results, indent=4))

    print("\nRisk Score:", score, "/100")

    print("\nSummary:\n")
    print(json.dumps(summary, indent=4))


if __name__ == "__main__":
    main()