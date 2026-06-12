importScripts('/content/api.js');

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "ANALYZE_EMAIL") {
    chrome.identity.getAuthToken({ interactive: true }, async (token) => {
      if (chrome.runtime.lastError || !token) {
        sendResponse({ success: false, error: chrome.runtime.lastError.message });
        return;
      }
      
      try {
        const baseURL = await getBaseURL();
        const res = await fetch(`${baseURL}/api/analyze-email`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ message_id: request.messageId, access_token: token })
        });
        
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || "API Error");
        
        sendResponse({ success: true, data });
      } catch (error) {
        sendResponse({ success: false, error: error.message });
      }
    });
    return true; // 비동기 응답 대기
  }
});

