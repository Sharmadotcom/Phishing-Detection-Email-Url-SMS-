// ─── PhishGuard Extension — Popup Logic ─────────────────────────────────────
// Uses the unified /predict endpoint from app.py

const API_BASE = "http://127.0.0.1:5000";

// Display the current tab URL on popup open
chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  const url = tabs[0]?.url || "Unknown";
  document.getElementById("current-url").textContent = url;
});

// Scan button click handler
document.getElementById("scan-btn").addEventListener("click", async () => {
  const btn = document.getElementById("scan-btn");
  const resultDiv = document.getElementById("result");
  const resultStatus = document.getElementById("result-status");
  const resultConfidence = document.getElementById("result-confidence");

  // Loading state
  btn.classList.add("loading");
  btn.disabled = true;
  resultDiv.classList.remove("visible", "safe", "threat", "error-state");

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const url = tab.url;

    const response = await fetch(`${API_BASE}/predict`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content: url, type: "url" })
    });

    if (!response.ok) throw new Error(`Server error: ${response.status}`);

    const data = await response.json();

    // Determine result type
    let type, icon, statusText;
    if (data.status === "Safe") {
      type = "safe";
      icon = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>`;
      statusText = "Safe — No Threats";
    } else if (data.status === "Phishing Warning") {
      type = "threat";
      icon = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z"/></svg>`;
      statusText = "⚠ Phishing Threat";
    } else {
      type = "error-state";
      icon = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m0-10.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.75c0 5.592 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.57-.598-3.75h-.152c-3.196 0-6.1-1.249-8.25-3.286zm0 13.036h.008v.008H12v-.008z"/></svg>`;
      statusText = "Analysis Error";
    }

    resultDiv.className = `result visible ${type}`;
    resultStatus.innerHTML = `${icon} ${statusText}`;

    const confidence = data.confidence || 0;
    resultConfidence.innerHTML = `Confidence: <strong>${confidence}%</strong>`;

  } catch (err) {
    console.error("PhishGuard scan error:", err);
    resultDiv.className = "result visible error-state";
    resultStatus.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m0-10.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.75c0 5.592 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.57-.598-3.75h-.152c-3.196 0-6.1-1.249-8.25-3.286zm0 13.036h.008v.008H12v-.008z"/></svg> Connection Failed`;
    resultConfidence.textContent = "Ensure the PhishGuard server is running (python app.py)";
  } finally {
    btn.classList.remove("loading");
    btn.disabled = false;
  }
});
