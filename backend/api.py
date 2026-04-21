from flask import Flask, jsonify, request
from flask_cors import CORS
import os
import tempfile
import zipfile

from ai.ai_engine import generate_suggestion
from main import calculate_score, deduplicate_results, summarize_results
from scanners.code_scanner import scan_code
from scanners.config_scanner import scan_config
from scanners.dependency_scanner import scan_dependencies

app = Flask(__name__)
CORS(app)


def read_text_file(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as file:
            return file.read()
    except Exception:
        return ""


def enrich_results(results):
    for issue in results:
        if issue.get("suggestion") is None or issue.get("explanation") is None:
            suggestion_data = generate_suggestion(issue)
            issue["suggestion"] = suggestion_data.get("fix")
            issue["explanation"] = suggestion_data.get("explanation")
    return results


def scan_extracted_project(extract_dir):
    results = []

    for root, _, files in os.walk(extract_dir):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            normalized_name = file_name.lower()

            if normalized_name.endswith(".py"):
                content = read_text_file(file_path)
                if content:
                    results.extend(scan_code(content, file_name))

            elif normalized_name == "requirements.txt":
                content = read_text_file(file_path)
                if content:
                    results.extend(scan_dependencies(content))

            elif normalized_name.endswith((".yaml", ".yml", ".json", ".env")):
                content = read_text_file(file_path)
                if content:
                    results.extend(scan_config(content, file_name))

    return results


@app.route("/scan", methods=["POST"])
def scan():
    payload = request.get_json()

    if not payload:
        return jsonify({"error": "Invalid JSON body"}), 400

    results = []

    requirements_content = payload.get("requirements")
    code_content = payload.get("code")
    config_content = payload.get("config")

    if requirements_content:
        results.extend(scan_dependencies(requirements_content))

    if code_content:
        results.extend(scan_code(code_content, "input.py"))

    if config_content:
        results.extend(scan_config(config_content, "config.yaml"))

    results = deduplicate_results(results)
    results = enrich_results(results)

    score = calculate_score(results)
    summary = summarize_results(results)

    return jsonify(
        {
            "vulnerabilities": results,
            "score": score,
            "summary": summary,
        }
    )


@app.route("/scan-zip", methods=["POST"])
def scan_zip():
    if "file" not in request.files:
        return jsonify({"error": "No ZIP file uploaded"}), 400

    uploaded_file = request.files["file"]

    if uploaded_file.filename == "":
        return jsonify({"error": "Empty filename"}), 400

    if not uploaded_file.filename.lower().endswith(".zip"):
        return jsonify({"error": "Only ZIP files are supported"}), 400

    with tempfile.TemporaryDirectory() as temp_dir:
        zip_path = os.path.join(temp_dir, uploaded_file.filename)
        uploaded_file.save(zip_path)

        extract_dir = os.path.join(temp_dir, "extracted")
        os.makedirs(extract_dir, exist_ok=True)

        try:
            with zipfile.ZipFile(zip_path, "r") as zip_ref:
                zip_ref.extractall(extract_dir)
        except Exception:
            return jsonify({"error": "Invalid ZIP file"}), 400

        results = scan_extracted_project(extract_dir)
        results = deduplicate_results(results)
        results = enrich_results(results)

        score = calculate_score(results)
        summary = summarize_results(results)

        return jsonify(
            {
                "vulnerabilities": results,
                "score": score,
                "summary": summary,
            }
        )


if __name__ == "__main__":
    app.run(debug=True)