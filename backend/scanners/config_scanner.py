import json
import yaml


def scan_config(config_content, file_name="unknown"):
    issues = []

    try:
        config = yaml.safe_load(config_content)
    except Exception:
        try:
            config = json.loads(config_content)
        except Exception:
            return issues

    if not isinstance(config, dict):
        return issues

    if config.get("debug") is True:
        issues.append(
            {
                "type": "debug_mode",
                "file": file_name,
                "line": None,
                "severity": "Medium",
                "message": "Debug mode is enabled",
                "source": "config",
                "cve_id": None,
                "package": None,
                "suggestion": None,
                "explanation": None,
            }
        )

    cors = config.get("cors") or config.get("CORS")
    if cors == "*" or cors == ["*"]:
        issues.append(
            {
                "type": "open_cors",
                "file": file_name,
                "line": None,
                "severity": "High",
                "message": "CORS is open to all (*)",
                "source": "config",
                "cve_id": None,
                "package": None,
                "suggestion": None,
                "explanation": None,
            }
        )

    tls = config.get("tls") or config.get("ssl")
    if isinstance(tls, dict):
        version = str(tls.get("version", "")).lower()
        if "1.0" in version or "1.1" in version:
            issues.append(
                {
                    "type": "weak_tls",
                    "file": file_name,
                    "line": None,
                    "severity": "High",
                    "message": "Weak TLS version detected",
                    "source": "config",
                    "cve_id": None,
                    "package": None,
                    "suggestion": None,
                    "explanation": None,
                }
            )

    for key, value in config.items():
        if any(term in key.lower() for term in ["password", "secret", "key", "token"]):
            if isinstance(value, str) and value.strip():
                issues.append(
                    {
                        "type": "exposed_secret",
                        "file": file_name,
                        "line": None,
                        "severity": "High",
                        "message": f"Possible exposed secret in config: {key}",
                        "source": "config",
                        "cve_id": None,
                        "package": None,
                        "suggestion": None,
                        "explanation": None,
                    }
                )

    host = config.get("host") or config.get("bind")
    if host == "0.0.0.0":
        issues.append(
            {
                "type": "open_binding",
                "file": file_name,
                "line": None,
                "severity": "Medium",
                "message": "Service exposed on 0.0.0.0",
                "source": "config",
                "cve_id": None,
                "package": None,
                "suggestion": None,
                "explanation": None,
            }
        )

    return issues