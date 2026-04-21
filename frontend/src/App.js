import React, { useState } from "react";
import { runScan, runZipScan } from "./api";
import FileUpload from "./components/FileUpload";
import ResultsTable from "./components/ResultsTable";
import RiskScore from "./components/RiskScore";
import Suggestions from "./components/Suggestions";
import "./styles.css";

function App() {
  const [code, setCode] = useState("");
  const [requirements, setRequirements] = useState("");
  const [config, setConfig] = useState("");
  const [zipFile, setZipFile] = useState(null);

  const [loading, setLoading] = useState(false);
  const [scanData, setScanData] = useState(null);
  const [error, setError] = useState("");

  const handleRunScan = async () => {
    setLoading(true);
    setError("");
    setScanData(null);

    try {
      let data;

      if (zipFile) {
        data = await runZipScan(zipFile);
      } else {
        data = await runScan({ code, requirements, config });
      }

      setScanData(data);
    } catch (err) {
      setError(err.message || "Something went wrong while scanning.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="app-shell">
      <div className="bg-glow glow-1"></div>
      <div className="bg-glow glow-2"></div>
      <div className="bg-glow glow-3"></div>

      <div className="app-container">
        <header className="hero-card">
          <div className="hero-left">
            <div className="hero-pill">AI Security Scanner</div>
            <h1 className="hero-title">Scan Fast. Ship Safe.</h1>
            <p className="hero-subtitle">
              Detect insecure dependencies, risky code, and unsafe configs before release.
            </p>

            <div className="hero-tags">
              <span>Code</span>
              <span>Dependencies</span>
              <span>Config</span>
              <span>ZIP Projects</span>
            </div>
          </div>

          <div className="hero-stats">
            <div className="stat-box float-a">
              <span>Layers</span>
              <strong>3</strong>
            </div>
            <div className="stat-box float-b">
              <span>AI</span>
              <strong>Smart</strong>
            </div>
            <div className="stat-box float-c">
              <span>Mode</span>
              <strong>Live</strong>
            </div>
          </div>
        </header>

        <section className="glass-card reveal">
          <div className="section-header">
            <div>
              <h2>Security Workspace</h2>
              <p>Upload a ZIP or paste inputs manually.</p>
            </div>
          </div>

          <div className="zip-box">
            <div className="zip-box-left">
              <h3>Project ZIP Upload</h3>
              <p>Upload one archive to scan a full project structure.</p>
            </div>

            <div className="zip-box-right">
              <input
                type="file"
                className="file-input"
                accept=".zip"
                onChange={(e) => setZipFile(e.target.files[0])}
              />
              <small className="zip-note">
                If ZIP is selected, the main Run button will scan the ZIP.
              </small>
            </div>
          </div>

          <div className="divider">
            <span>OR</span>
          </div>

          <div className="input-grid">
            <FileUpload
              title="Source Code"
              value={code}
              setValue={setCode}
              placeholder="Paste source code..."
              accept=".py,.js,.ts,.java,.txt"
            />

            <FileUpload
              title="requirements.txt"
              value={requirements}
              setValue={setRequirements}
              placeholder="Paste dependency file content..."
              accept=".txt"
            />

            <FileUpload
              title="Config File"
              value={config}
              setValue={setConfig}
              placeholder="Paste YAML / JSON config..."
              accept=".yaml,.yml,.json,.env,.txt"
            />
          </div>

          <div className="action-row">
            <button className="run-btn" onClick={handleRunScan} disabled={loading}>
              {loading ? "Scanning..." : "Run Security Scan"}
            </button>
          </div>

          {error && <div className="error-box">{error}</div>}
        </section>

        {scanData && (
          <>
            <div className="reveal">
              <RiskScore score={scanData.score} summary={scanData.summary} />
            </div>
            <div className="reveal">
              <ResultsTable vulnerabilities={scanData.vulnerabilities || []} />
            </div>
            <div className="reveal">
              <Suggestions vulnerabilities={scanData.vulnerabilities || []} />
            </div>
          </>
        )}
      </div>
    </div>
  );
}

export default App;