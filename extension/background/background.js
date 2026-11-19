importScripts('/content/api.js');

/**
 * Background Service Worker (v2.0)
 * 1. Chrome 142+ Local Network Access(LNA) & CORS 회피용 백엔드 통신 프록시 (단발 + Port NDJSON 스트리밍)
 * 2. DeclarativeNetRequest(DNR) 기반 위험 URL 능동 차단 (세션 규칙 -> Interstitial 경고 페이지)
 * 3. Chrome Side Panel 상세 위협 대시보드 상태 동기화 및 열기 제어
 */

const DNR_RULE_ID_BASE = 10000;
const AUTO_BLOCK_THRESHOLD = 30; // 안전도 30점 이하는 위험 사이트로 자동 차단 등록
const prefetchedMessageIds = new Set();
let activePrefetchCount = 0;

function getAuthTokenAsync(interactive) {
  return new Promise((resolve) => {
    chrome.identity.getAuthToken({ interactive }, (token) => {
      if (chrome.runtime.lastError || !token) {
        resolve({ token: null, error: chrome.runtime.lastError ? chrome.runtime.lastError.message : "OAuth 토큰 없음" });
      } else {
        resolve({ token, error: null });
      }
    });
  });
}

async function syncEmailReportToSidePanel(messageId, data) {
  const riskToScore = { SAFE: 95, LOW: 85, MEDIUM: 50, HIGH: 15 };
  await saveLatestReport({
    type: "email",
    target: data.summary || `Gmail 메시지 (${messageId})`,
    safety_score: data.is_phishing
      ? Math.min(25, riskToScore[data.risk_level] ?? 20)
      : (riskToScore[data.risk_level] ?? 85),
    reason: data.reason,
    actions: data.actions || [],
    social_engineering_elements: data.social_engineering_elements || [],
    mail_summary: data.mail_summary || "",
    rag_retrieved_docs: data.rag_retrieved_docs || [],
    details: {
      vt_findings: data.vt_findings,
      static_findings: data.static_findings,
      dynamic_findings: data.dynamic_findings
    },
    engine: "cloud-backend"
  });
}

function storageGet(keys) {
  return new Promise((resolve) => chrome.storage.local.get(keys, resolve));
}

function storageSet(obj) {
  return new Promise((resolve) => chrome.storage.local.set(obj, resolve));
}

async function saveLatestReport(report) {
  try {
    await storageSet({
      latestReport: {
        ...report,
        timestamp: Date.now()
      }
    });
  } catch (err) {
    console.error("[Background] latestReport 저장 실패:", err);
  }
}

/**
 * DeclarativeNetRequest 세션 규칙 등록:
 * 위험 URL 클릭 시 /blocked/blocked.html 경고 페이지로 리다이렉트합니다.
 */
async function registerBlockedUrl(url, score, reason) {
  try {
    if (!url || !url.startsWith("http") || !chrome.declarativeNetRequest) return false;

    const { enableAutoBlock, blockedUrls = [], allowedUrls = [] } = await storageGet([
      "enableAutoBlock",
      "blockedUrls",
      "allowedUrls"
    ]);

    if (enableAutoBlock === false) return false;
    if (allowedUrls.includes(url)) return false;

    const existing = blockedUrls.find((item) => item.url === url);
    if (existing) return true;

    const usedIds = new Set(blockedUrls.map((item) => item.ruleId));
    let ruleId = DNR_RULE_ID_BASE + 1;
    while (usedIds.has(ruleId)) ruleId++;

    const safeReason = String(reason || "위험 사이트로 감지되었습니다.").slice(0, 220);
    const params = new URLSearchParams({
      url,
      score: String(score),
      reason: safeReason
    });

    await chrome.declarativeNetRequest.updateSessionRules({
      addRules: [
        {
          id: ruleId,
          priority: 1,
          action: {
            type: "redirect",
            redirect: {
              extensionPath: `/blocked/blocked.html?${params.toString()}`
            }
          },
          condition: {
            urlFilter: `|${url}|`,
            resourceTypes: ["main_frame"]
          }
        }
      ]
    });

    const updated = [
      {
        ruleId,
        url,
        score,
        reason: safeReason,
        blockedAt: Date.now()
      },
      ...blockedUrls
    ].slice(0, 50);

    await storageSet({ blockedUrls: updated });
    return true;
  } catch (err) {
    console.error("[Background] DNR 차단 규칙 등록 실패:", err);
    return false;
  }
}

async function unblockUrl(url) {
  try {
    const { blockedUrls = [], allowedUrls = [] } = await storageGet(["blockedUrls", "allowedUrls"]);
    const target = blockedUrls.find((item) => item.url === url);

    if (target && chrome.declarativeNetRequest) {
      await chrome.declarativeNetRequest.updateSessionRules({
        removeRuleIds: [target.ruleId]
      });
    }

    const remaining = blockedUrls.filter((item) => item.url !== url);
    const nextAllowed = allowedUrls.includes(url) ? allowedUrls : [...allowedUrls, url].slice(-50);
    await storageSet({ blockedUrls: remaining, allowedUrls: nextAllowed });
    return true;
  } catch (err) {
    console.error("[Background] DNR 차단 해제 실패:", err);
    return false;
  }
}

async function clearBlockedUrls() {
  try {
    const { blockedUrls = [] } = await storageGet(["blockedUrls"]);
    const ruleIds = blockedUrls.map((item) => item.ruleId).filter(Boolean);

    if (ruleIds.length > 0 && chrome.declarativeNetRequest) {
      await chrome.declarativeNetRequest.updateSessionRules({
        removeRuleIds: ruleIds
      });
    }

    await storageSet({ blockedUrls: [], allowedUrls: [] });
    return true;
  } catch (err) {
    console.error("[Background] DNR 전체 차단 해제 실패:", err);
    return false;
  }
}

// 1. 단발 요청 핸들러
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (!request || !request.action) return;

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

        // Side Panel 리포트 동기화
        const riskToScore = { SAFE: 95, LOW: 85, MEDIUM: 50, HIGH: 15 };
        await saveLatestReport({
          type: "email",
          target: data.summary || `Gmail 메시지 (${request.messageId})`,
          safety_score: data.is_phishing ? Math.min(25, riskToScore[data.risk_level] ?? 20) : (riskToScore[data.risk_level] ?? 85),
          reason: data.reason,
          actions: data.actions || [],
          social_engineering_elements: data.social_engineering_elements || [],
          mail_summary: data.mail_summary || "",
          rag_retrieved_docs: data.rag_retrieved_docs || [],
          details: {
            vt_findings: data.vt_findings,
            static_findings: data.static_findings,
            dynamic_findings: data.dynamic_findings
          },
          engine: "cloud-backend"
        });

        sendResponse({ success: true, data });
      } catch (error) {
        sendResponse({ success: false, error: error.message || "서버 통신 오류" });
      }
    });
    return true;
  }

  if (request.action === "PREFETCH_EMAIL") {
    (async () => {
      const msgId = request.messageId;
      if (!msgId || prefetchedMessageIds.has(msgId) || activePrefetchCount >= 1) {
        sendResponse({ skipped: true });
        return;
      }

      // 비대화형(팝업 없음) 토큰이 있을 때만 조용히 사전 캐싱
      const { token } = await getAuthTokenAsync(false);
      if (!token) {
        sendResponse({ skipped: true });
        return;
      }

      prefetchedMessageIds.add(msgId);
      activePrefetchCount += 1;
      try {
        const baseURL = await getBaseURL();
        await fetch(`${baseURL}/api/analyze-email`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ message_id: msgId, access_token: token })
        });
        sendResponse({ success: true });
      } catch (_) {
        prefetchedMessageIds.delete(msgId);
        sendResponse({ success: false });
      } finally {
        activePrefetchCount = Math.max(0, activePrefetchCount - 1);
      }
    })();
    return true;
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

  if (request.action === "SAVE_REPORT") {
    saveLatestReport(request.report).then(() => sendResponse({ success: true }));
    return true;
  }

  if (request.action === "UNBLOCK_URL") {
    unblockUrl(request.url).then((ok) => sendResponse({ success: ok }));
    return true;
  }

  if (request.action === "CLEAR_BLOCKED_URLS") {
    clearBlockedUrls().then((ok) => sendResponse({ success: ok }));
    return true;
  }

  if (request.action === "OPEN_SIDE_PANEL") {
    (async () => {
      try {
        const windowId =
          request.windowId ||
          (sender && sender.tab && sender.tab.windowId);
        if (chrome.sidePanel && windowId) {
          await chrome.sidePanel.open({ windowId });
          sendResponse({ success: true });
        } else {
          sendResponse({ success: false, error: "Side Panel을 열 수 있는 창 정보가 없습니다." });
        }
      } catch (err) {
        sendResponse({ success: false, error: err.message });
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

  async function processChunkSideEffects(action, payload, parsed) {
    if (action === "ANALYZE_URL" && parsed.status === "success") {
      try {
        const data = typeof parsed.data === "string" ? JSON.parse(parsed.data) : parsed.data;
        const targetUrl = data.url || (payload && payload.url) || "";
        const score = Number(data.safety_score ?? 50);
        const reason = data.reason || "";

        let autoBlocked = false;
        if (score <= AUTO_BLOCK_THRESHOLD && targetUrl) {
          autoBlocked = await registerBlockedUrl(targetUrl, score, reason);
        }

        await saveLatestReport({
          type: "url",
          target: targetUrl,
          safety_score: score,
          reason,
          actions: score <= 40 ? ["이 링크를 클릭하지 마세요.", "공식 도메인 주소를 직접 입력해 접속하세요."] : [],
          details: data.details || {},
          engine: "cloud-backend"
        });

        if (autoBlocked) {
          parsed.auto_blocked = true;
        }
      } catch (err) {
        console.error("[Background] URL 결과 후처리 오류:", err);
      }
    } else if (action === "ANALYZE_TEXT" && parsed && parsed.score !== undefined) {
      try {
        const safetyScore = Math.max(0, Math.min(100, 100 - Number(parsed.score)));
        await saveLatestReport({
          type: "text",
          target: (payload && payload.selected_text) || "",
          safety_score: safetyScore,
          reason: parsed.reason || "",
          actions: parsed.mitigation ? [parsed.mitigation] : [],
          engine: "cloud-backend"
        });
      } catch (err) {
        console.error("[Background] 텍스트 결과 후처리 오류:", err);
      }
    } else if (
      action === "ANALYZE_EMAIL_STREAM" &&
      parsed &&
      (parsed.stage === "partial" || parsed.stage === "final") &&
      parsed.data
    ) {
      try {
        await syncEmailReportToSidePanel(payload && payload.message_id, parsed.data);
      } catch (err) {
        console.error("[Background] 이메일 스트리밍 후처리 오류:", err);
      }
    }
  }

  port.onMessage.addListener(async (request) => {
    if (!request || !request.action) return;

    let endpoint = "";
    let bodyPayload = request.payload ? { ...request.payload } : {};

    if (request.action === "ANALYZE_URL") {
      endpoint = "/api/v1/analyze";
    } else if (request.action === "ANALYZE_TEXT") {
      endpoint = "/api/v1/analyze/text";
    } else if (request.action === "ANALYZE_EMAIL_STREAM") {
      endpoint = "/api/analyze-email/stream";
      // DOM Fast Path 본문이 부족할 때만 OAuth 토큰 요청 (충분하면 토큰 왕복도 생략!)
      const hasDomBody = bodyPayload.body_text && bodyPayload.body_text.trim().length >= 15;
      if (!hasDomBody) {
        const { token, error } = await getAuthTokenAsync(true);
        if (!token) {
          safePostMessage({ type: "error", message: error || "OAuth 토큰을 획득하지 못했습니다." });
          return;
        }
        bodyPayload.access_token = token;
      }
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
        body: JSON.stringify(bodyPayload),
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
            await processChunkSideEffects(request.action, request.payload, parsed);
            safePostMessage({ type: "chunk", data: parsed });
          } catch (parseErr) {
            console.error("[Background] NDJSON 파싱 에러:", parseErr, part);
          }
        }
      }

      if (!isDisconnected && buffer.trim()) {
        try {
          const parsed = JSON.parse(buffer);
          await processChunkSideEffects(request.action, request.payload, parsed);
          safePostMessage({ type: "chunk", data: parsed });
        } catch (parseErr) {
          console.error("[Background] NDJSON 잔여 버퍼 파싱 에러:", parseErr, buffer);
        }
      }

      safePostMessage({ type: "done" });
    } catch (error) {
      if (error && error.name === "AbortError") {
        return;
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
