import React from "react";

function getSeverityClass(severity) {
  const value = (severity || "").toLowerCase();

  if (value === "high" || value === "critical") return "sev-high";
  if (value === "medium") return "sev-medium";
  return "sev-low";
}

function formatType(text) {
  if (!text) return "-";

  return text
    .replace(/_/g, " ")
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

function ResultsTable({ vulnerabilities }) {
  const hasResults = vulnerabilities && vulnerabilities.length > 0;

  return (
    <div className="panel reveal">
      <h2>Detected Vulnerabilities</h2>

      {!hasResults ? (
        <p className="empty-text">No vulnerabilities found.</p>
      ) : (
        <div className="table-wrapper">
          <table className="results-table">
            <thead>
              <tr>
                <th>Type</th>
                <th>Severity</th>
                <th>Source</th>
                <th>File</th>
                <th>Line</th>
                <th>Message</th>
                <th>CVE</th>
                <th>Package</th>
              </tr>
            </thead>
            <tbody>
              {vulnerabilities.map((item, index) => (
                <tr key={index}>
                  <td>{formatType(item.type)}</td>

                  <td>
                    <span
                      className={`severity-badge ${getSeverityClass(
                        item.severity
                      )}`}
                    >
                      {item.severity || "-"}
                    </span>
                  </td>

                  <td>{item.source || "-"}</td>
                  <td>{item.file || "-"}</td>
                  <td>{item.line ?? "-"}</td>
                  <td>{item.message || "-"}</td>
                  <td>{item.cve_id || "-"}</td>
                  <td>{item.package || "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

export default ResultsTable;