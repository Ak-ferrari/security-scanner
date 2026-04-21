import React from "react";

function formatType(text) {
  if (!text) return "";

  return text
    .replace(/_/g, " ")
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

function getSeverityClass(severity) {
  const value = (severity || "").toLowerCase();

  if (value === "high" || value === "critical") return "sev-high";
  if (value === "medium") return "sev-medium";
  return "sev-low";
}

function Suggestions({ vulnerabilities }) {
  const filtered = vulnerabilities.filter(
    (item) => item.suggestion || item.explanation
  );

  const seen = new Set();
  const uniqueSuggestions = [];

  for (const item of filtered) {
    const key = `${item.type}-${item.suggestion}`;

    if (!seen.has(key)) {
      seen.add(key);
      uniqueSuggestions.push(item);
    }
  }

  const suggestions = uniqueSuggestions.slice(0, 6);
  const hasSuggestions = suggestions.length > 0;

  return (
    <div className="panel suggestions-panel reveal">
      <h2 className="section-title">Recommended Security Actions</h2>

      {!hasSuggestions ? (
        <p className="empty-text">No suggestions available.</p>
      ) : (
        <div className="suggestions-grid">
          {suggestions.map((item, index) => (
            <div className="suggestion-card" key={index}>
              <div className="suggestion-header">
                <span className="suggestion-type">
                  {formatType(item.type)}
                </span>

                <span
                  className={`severity-badge ${getSeverityClass(
                    item.severity
                  )}`}
                >
                  {item.severity || "-"}
                </span>
              </div>

              <p className="suggestion-msg">{item.message}</p>

              {item.explanation && (
                <p className="suggestion-explain">
                  {item.explanation}
                </p>
              )}

              {item.suggestion && (
                <div className="suggestion-fix">
                  {item.suggestion}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default Suggestions;