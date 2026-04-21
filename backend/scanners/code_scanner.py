import ast
import re


SECRET_PATTERNS = [
    r'password\s*=\s*["\'].*["\']',
    r'api_key\s*=\s*["\'].*["\']',
    r'secret\s*=\s*["\'].*["\']',
    r'token\s*=\s*["\'].*["\']',
]

WEAK_CRYPTO_PATTERNS = [
    r'hashlib\.md5',
    r'hashlib\.sha1',
    r'DES',
    r'RC4',
]

DEBUG_PATTERN = r'debug\s*=\s*true'


def is_comment(line):
    return line.strip().startswith("#")


class CodeVisitor(ast.NodeVisitor):
    def __init__(self):
        self.issues = []

    def visit_Assign(self, node):
        try:
            for target in node.targets:
                if not isinstance(target, ast.Name):
                    continue

                variable_name = target.id.lower()

                if variable_name in ["password", "api_key", "secret", "token"]:
                    if isinstance(node.value, ast.Constant):
                        self.issues.append(
                            {
                                "type": "hardcoded_secret",
                                "file": "unknown",
                                "line": node.lineno,
                                "severity": "High",
                                "message": f"Hardcoded value assigned to '{variable_name}'",
                                "source": "code",
                                "cve_id": None,
                                "package": None,
                                "suggestion": None,
                                "explanation": None,
                            }
                        )
        except Exception:
            pass

        self.generic_visit(node)


def scan_code(source_code, file_name="unknown"):
    issues = []
    lines = source_code.split("\n")

    for line_number, line in enumerate(lines, start=1):
        if is_comment(line):
            continue

        for pattern in SECRET_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                issues.append(
                    {
                        "type": "hardcoded_secret",
                        "file": file_name,
                        "line": line_number,
                        "severity": "High",
                        "message": "Possible hardcoded secret detected",
                        "source": "code",
                        "cve_id": None,
                        "package": None,
                        "suggestion": None,
                        "explanation": None,
                    }
                )

        for pattern in WEAK_CRYPTO_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                issues.append(
                    {
                        "type": "weak_crypto",
                        "file": file_name,
                        "line": line_number,
                        "severity": "Medium",
                        "message": "Weak cryptographic function used",
                        "source": "code",
                        "cve_id": None,
                        "package": None,
                        "suggestion": None,
                        "explanation": None,
                    }
                )

        if re.search(DEBUG_PATTERN, line, re.IGNORECASE):
            issues.append(
                {
                    "type": "debug_mode",
                    "file": file_name,
                    "line": line_number,
                    "severity": "Medium",
                    "message": "Debug mode is enabled",
                    "source": "code",
                    "cve_id": None,
                    "package": None,
                    "suggestion": None,
                    "explanation": None,
                }
            )

    try:
        tree = ast.parse(source_code)
        visitor = CodeVisitor()
        visitor.visit(tree)

        for issue in visitor.issues:
            issue["file"] = file_name

        issues.extend(visitor.issues)
    except Exception:
        pass

    return issues