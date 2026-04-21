import React from "react";

function getScoreClass(score) {
  if (score <= 40) return "score-high-risk";
  if (score <= 70) return "score-medium-risk";
  return "score-low-risk";
}

function RiskScore({ score, summary }) {
  return (
    <div className="panel reveal">
      <h2>Risk Score Overview</h2>

      <div className="score-section">
        <div className={`score-circle ${getScoreClass(score)}`}>{score}</div>

        <div className="score-details">
          <p><strong>Total Issues:</strong> {summary?.total_issues ?? 0}</p>
          <p><strong>High:</strong> {summary?.by_severity?.High ?? 0}</p>
          <p><strong>Medium:</strong> {summary?.by_severity?.Medium ?? 0}</p>
          <p><strong>Low:</strong> {summary?.by_severity?.Low ?? 0}</p>
          <p><strong>Dependency:</strong> {summary?.by_source?.dependency ?? 0}</p>
          <p><strong>Code:</strong> {summary?.by_source?.code ?? 0}</p>
          <p><strong>Config:</strong> {summary?.by_source?.config ?? 0}</p>
        </div>
      </div>
    </div>
  );
}

export default RiskScore;