def generate_suggestion(issue):
    issue_type = issue.get("type", "")
    message = issue.get("message", "")
    package = issue.get("package", "")

    if issue_type == "hardcoded_secret":
        return {
            "explanation": (
                "Hardcoded credentials in source code can be exposed through "
                "repositories, logs, screenshots, or accidental sharing."
            ),
            "impact": (
                "This may allow unauthorized access to internal tools, databases, "
                "test environments, or production systems."
            ),
            "fix": "Move the secret to environment variables or a secure secrets manager.",
        }

    if issue_type == "weak_crypto":
        return {
            "explanation": (
                "Weak cryptographic algorithms such as MD5 or SHA1 are susceptible "
                to collision and tampering attacks."
            ),
            "impact": (
                "This can weaken integrity checks, password storage, or other "
                "security-sensitive workflows."
            ),
            "fix": (
                "Replace weak algorithms with SHA-256, bcrypt, scrypt, or Argon2, "
                "depending on the use case."
            ),
        }

    if issue_type == "debug_mode":
        return {
            "explanation": (
                "Debug mode can expose stack traces, internal configuration, and "
                "application behavior that should not be visible in production."
            ),
            "impact": (
                "This can make it easier for an attacker to understand and exploit "
                "the application."
            ),
            "fix": "Disable debug mode in production and use controlled logging instead.",
        }

    if issue_type == "open_cors":
        return {
            "explanation": (
                "Open CORS allows any website to send requests to your backend resources."
            ),
            "impact": (
                "This may allow untrusted frontends to misuse authenticated sessions "
                "or sensitive APIs."
            ),
            "fix": "Restrict CORS to a defined list of trusted domains.",
        }

    if issue_type == "open_binding":
        return {
            "explanation": (
                "Binding a service to 0.0.0.0 exposes it on all available network interfaces."
            ),
            "impact": (
                "This can make internal services accessible from networks where they "
                "were not intended to be exposed."
            ),
            "fix": (
                "Bind the service only to the required interface, such as 127.0.0.1 "
                "or a private internal IP."
            ),
        }

    if issue_type == "vulnerable_dependency":
        if package:
            return {
                "explanation": (
                    f"The installed version of {package} is associated with a known "
                    "public vulnerability."
                ),
                "impact": (
                    f"If {package} is used in production, attackers may be able to "
                    "exploit publicly documented weaknesses."
                ),
                "fix": (
                    f"Upgrade {package} to the latest secure version and verify "
                    "compatibility before release."
                ),
            }

        return {
            "explanation": (
                "A known public vulnerability was detected in one of the installed dependencies."
            ),
            "impact": (
                "If the affected package is exposed in the deployed application, "
                "it may increase the risk of exploitation."
            ),
            "fix": "Upgrade the affected dependency to the latest secure version.",
        }

    return {
        "explanation": f"Security issue detected: {message}",
        "impact": "This issue may increase the application's attack surface.",
        "fix": "Review the affected file and apply the appropriate secure fix.",
    }