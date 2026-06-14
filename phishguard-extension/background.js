// ─── PhishGuard Extension — Background Service Worker ───────────────────────
// Right-click context menu to check any link for phishing

const API_BASE = "http://127.0.0.1:5000";

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "phishguard-check-link",
    title: "🛡️ PhishGuard — Scan this link",
    contexts: ["link"]
  });
});

// When user right-clicks a link and selects "Scan this link"
chrome.contextMenus.onClicked.addListener(async (info) => {
  if (info.menuItemId === "phishguard-check-link") {
    const url = info.linkUrl;

    try {
      const response = await fetch(`${API_BASE}/predict`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ content: url, type: "url" })
      });

      if (!response.ok) throw new Error(`Server error: ${response.status}`);

      const data = await response.json();
      const confidence = data.confidence || 0;

      if (data.status === "Safe") {
        // Inject result into the active tab
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
          chrome.scripting.executeScript({
            target: { tabId: tabs[0].id },
            func: (msg) => alert(msg),
            args: [`✅ PhishGuard: SAFE (${confidence}% confidence)\n\n${url}`]
          });
        });
      } else {
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
          chrome.scripting.executeScript({
            target: { tabId: tabs[0].id },
            func: (msg) => alert(msg),
            args: [`🚨 PhishGuard: PHISHING THREAT (${confidence}% confidence)\n\n${url}\n\nDo NOT visit this link!`]
          });
        });
      }

    } catch (err) {
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        chrome.scripting.executeScript({
          target: { tabId: tabs[0].id },
          func: (msg) => alert(msg),
          args: ["⚠️ PhishGuard: Could not connect to the analysis server.\nEnsure the server is running: python app.py"]
        });
      });
      console.error("PhishGuard background error:", err);
    }
  }
});
