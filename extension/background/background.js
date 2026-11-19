importScripts('/content/api.js');

/**
 * Background Service Worker
 * - Chrome 142+ Local Network Access(LNA) 및 Content Script CORS 차단 회피를 위해
 *   모든 백엔드 API 통신(단발 JSON 및 NDJSON 스트리밍)을 Service Worker에서 중계합니다.
 */

// 1. 단발 요청 핸들러 (Gmail 분석, DB 초기화, 로그 조회)
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "ANALYZE_EMAIL") {
    chrome.identity.getAuthToken({ interactive: true }, async (token) => {
      if (chrome.runtime.lastError || !token) {
        sendResponse({
          success: false,
          error: chrome.runtime.lastError ? chrome.runtime.lastError.message : "OAuth 토큰을 획득하지 못했습니다."
        });
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
        if (!res.ok) throw new Error(data.detail || `API Error (${res.status})`);

        sendResponse({ success: true, data });
      } catch (error) {
        sendResponse({ success: false, error: error.message || "서버 통신 오류" });
      }
    });
    return true; // 비동기 응답 대기
  }

  if (request.action === "CLEAR_DB") {
    (async () => {
      try {
        const baseURL = await getBaseURL();
        const res = await fetch(`${baseURL}/api/clear-db`, {
          method: "POST",
          headers: { "Content-Type": "application/json" }
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(data.detail || `API Error (${res.status})`);
        sendResponse({ success: true, data });
      } catch (error) {
        sendResponse({ success: false, error: error.message || "서버 통신 오류" });
      }
    })();
    return true;
  }

  if (request.action === "GET_LOGS") {
    (async () => {
      try {
        const baseURL = await getBaseURL();
        const limit = request.limit || 20;
        const res = await fetch(`${baseURL}/api/logs?limit=${encodeURIComponent(limit)}`);
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || `API Error (${res.status})`);
        sendResponse({ success: true, data });
      } catch (error) {
        sendResponse({ success: false, error: error.message || "서버 통신 오류" });
      }
    })();
    return true;
  }
});

// 2. NDJSON 스트리밍 프록시 (URL Hover 분석 & 텍스트 드래그 분석)
chrome.runtime.onConnect.addListener((port) => {
  if (port.name !== "phishing-stream") return;

  let controller = null;
  let isDisconnected = false;

  const safePostMessage = (msg) => {
    if (isDisconnected) return;
    try {
      port.postMessage(msg);
    } catch (_) {
      isDisconnected = true;
    }
  };

  port.onDisconnect.addListener(() => {
    isDisconnected = true;
    if (controller) {
      controller.abort();
      controller = null;
    }
  });

  port.onMessage.addListener(async (request) => {
    if (!request || !request.action) return;

    let endpoint = "";
    if (request.action === "ANALYZE_URL") {
      endpoint = "/api/v1/analyze";
    } else if (request.action === "ANALYZE_TEXT") {
      endpoint = "/api/v1/analyze/text";
    } else {
      safePostMessage({ type: "error", message: `지원하지 않는 액션입니다: ${request.action}` });
      return;
    }

    if (controller) {
      controller.abort();
    }
    controller = new AbortController();

    try {
      const baseURL = await getBaseURL();
      const response = await fetch(`${baseURL}${endpoint}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(request.payload || {}),
        signal: controller.signal
      });

      if (!response.ok) {
        throw new Error(`서버 에러 상태코드: ${response.status}`);
      }

      if (!response.body) {
        throw new Error("스트리밍 응답 본문이 비어 있습니다.");
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";

      while (!isDisconnected) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const parts = buffer.split("\n");
        buffer = parts.pop();

        for (const part of parts) {
          if (!part.trim()) continue;
          try {
            const parsed = JSON.parse(part);
            safePostMessage({ type: "chunk", data: parsed });
          } catch (parseErr) {
            console.error("[Background] NDJSON 파싱 에러:", parseErr, part);
          }
        }
      }

      // 남은 버퍼 처리
      if (!isDisconnected && buffer.trim()) {
        try {
          const parsed = JSON.parse(buffer);
          safePostMessage({ type: "chunk", data: parsed });
        } catch (parseErr) {
          console.error("[Background] NDJSON 잔여 버퍼 파싱 에러:", parseErr, buffer);
        }
      }

      safePostMessage({ type: "done" });
    } catch (error) {
      if (error && error.name === "AbortError") {
        return; // 정상 취소 (마우스 아웃 등)
      }
      console.error("[Background] 스트리밍 API 통신 에러:", error);
      safePostMessage({
        type: "error",
        message: error.message || "서버와 통신할 수 없습니다. 서버가 켜져있는지 확인해주세요."
      });
    } finally {
      controller = null;
    }
  });
});
