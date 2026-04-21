import requests

OSV_API_URL = "https://api.osv.dev/v1/query"


def parse_requirements(content):
    dependencies = []

    for line in content.split("\n"):
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        if "==" in line:
            name, version = line.split("==")
        else:
            name, version = line, None

        dependencies.append((name.strip(), version))

    return dependencies


def get_severity(vulnerability):
    try:
        score = float(vulnerability.get("severity", [{}])[0].get("score", 0))
    except Exception:
        return "High"

    if score >= 7:
        return "High"
    if score >= 4:
        return "Medium"
    return "Low"


def check_osv(package, version):
    try:
        payload = {
            "package": {
                "name": package,
                "ecosystem": "PyPI",
            }
        }

        if version:
            payload["version"] = version

        response = requests.post(OSV_API_URL, json=payload, timeout=5)

        if response.status_code != 200:
            return []

        data = response.json()
        vulnerabilities = data.get("vulns", [])

        seen_ids = set()
        results = []

        for vulnerability in vulnerabilities:
            vulnerability_id = vulnerability.get("id")

            if vulnerability_id in seen_ids:
                continue

            seen_ids.add(vulnerability_id)

            results.append(
                {
                    "type": "vulnerable_dependency",
                    "file": "requirements.txt",
                    "line": None,
                    "severity": get_severity(vulnerability),
                    "message": vulnerability.get("summary", "Known vulnerability detected"),
                    "source": "dependency",
                    "cve_id": vulnerability_id,
                    "package": package,
                    "suggestion": "Upgrade to the latest secure version.",
                    "explanation": "Public vulnerability detected in this package.",
                }
            )

        if len(results) > 10:
            return [
                {
                    "type": "vulnerable_dependency",
                    "file": "requirements.txt",
                    "line": None,
                    "severity": "High",
                    "message": f"{package} has {len(results)} known vulnerabilities",
                    "source": "dependency",
                    "cve_id": "MULTIPLE",
                    "package": package,
                    "suggestion": "Upgrade immediately to latest version.",
                    "explanation": "Multiple vulnerabilities detected.",
                }
            ]

        return results

    except Exception:
        return []


def basic_safety_check(package, version):
    issues = []

    if package.lower() in ["django", "flask"] and version:
        if version.startswith(("0.", "1.")):
            issues.append(
                {
                    "type": "vulnerable_dependency",
                    "file": "requirements.txt",
                    "line": None,
                    "severity": "Medium",
                    "message": f"Outdated version detected for {package}",
                    "source": "dependency",
                    "cve_id": None,
                    "package": package,
                    "suggestion": "Upgrade to latest version",
                    "explanation": "Older versions may contain vulnerabilities.",
                }
            )

    return issues


def scan_dependencies(content):
    issues = []
    dependencies = parse_requirements(content)

    for package, version in dependencies:
        osv_results = check_osv(package, version)

        if osv_results:
            issues.extend(osv_results)
        else:
            issues.extend(basic_safety_check(package, version))

    return issues