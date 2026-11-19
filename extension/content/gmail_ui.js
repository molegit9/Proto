function initGmailAnalysis() {
  let currentMessageId = null;
  let activeRequestSeq = 0;
  let activeEmailPort = null;
  let debounceTimer = null;
  let hoverPrefetchTimer = null;
  let enableLocalAi = true;
  let prefetchCount = 0;
  const MAX_SESSION_PREFETCH = 8;
  const prefetchedIds = new Set();

  if (typeof chrome !== "undefined" && chrome.storage) {
    chrome.storage.local.get(["enableLocalAi"], (res) => {
      if (res.enableLocalAi !== undefined) enableLocalAi = res.enableLocalAi;
    });
    chrome.storage.onChanged.addListener((changes) => {
      if (changes.enableLocalAi) enableLocalAi = changes.enableLocalAi.newValue;
    });
  }

  function isEmailDetailHash(hashStr) {
    const h = typeof hashStr === "string" ? hashStr : window.location.hash;
    return h.includes("/");
  }

  function disconnectEmailStream() {
    if (activeEmailPort) {
      try {
        activeEmailPort.disconnect();
      } catch (_) {}
      activeEmailPort = null;
    }
  }

  function clearEmailViewState() {
    clearTimeout(debounceTimer);
    currentMessageId = null;
    activeRequestSeq += 1;
    disconnectEmailStream();
    if (typeof removeBanner === "function") removeBanner();
  }

  /**
   * DOM Fast Path: 현재 화면에 이미 렌더링된 메일의 발신자/제목/본문/링크를 0.01초 만에 추출하여
   * Gmail REST API 왕복(0.5~1.5초)을 생략합니다.
   */
  function extractEmailFromDom() {
    let subject = "";
    const subjectEl = document.querySelector("h2.hP");
    if (subjectEl && subjectEl.offsetParent !== null) {
      subject = (subjectEl.innerText || "").trim();
    }

    let sender = "";
    const senderEls = document.querySelectorAll(".gD");
    for (let i = senderEls.length - 1; i >= 0; i--) {
      const el = senderEls[i];
      if (el.offsetParent !== null) {
        const emailAttr = el.getAttribute("email") || "";
        const nameText = (el.getAttribute("name") || el.innerText || "").trim();
        sender = emailAttr ? `${nameText} <${emailAttr}>` : nameText;
        break;
      }
    }

    let bodyEl = null;
    const bodies = document.querySelectorAll(".a3s.aiL");
    for (let i = bodies.length - 1; i >= 0; i--) {
      if (bodies[i].offsetParent !== null) {
        bodyEl = bodies[i];
        break;
      }
    }
    if (!bodyEl && bodies.length > 0) {
      bodyEl = bodies[bodies.length - 1];
    }

    const bodyText = bodyEl ? (bodyEl.innerText || "").trim() : "";
    const links = [];
    if (bodyEl) {
      const anchorEls = bodyEl.querySelectorAll("a[href]");
      for (const a of anchorEls) {
        const href = a.href;
        if (href && href.startsWith("http") && !href.startsWith("https://mail.google.com/")) {
          links.push(href);
        }
      }
    }

    return {
      sender: sender || null,
      subject: subject || null,
      body_text: bodyText.length >= 15 ? bodyText.slice(0, 6000) : null,
      links: Array.from(new Set(links)).slice(0, 10)
    };
  }

  function checkActiveMessage() {
    if (!isEmailDetailHash()) {
      clearEmailViewState();
      return;
    }

    const messageElements = document.querySelectorAll("[data-legacy-message-id]");
    let activeId = null;
    for (let i = messageElements.length - 1; i >= 0; i--) {
      const el = messageElements[i];
      if (el.offsetParent !== null) {
        activeId = el.getAttribute("data-legacy-message-id");
        if (activeId) break;
      }
    }
    if (!activeId && messageElements.length > 0) {
      activeId = messageElements[messageElements.length - 1].getAttribute("data-legacy-message-id");
    }

    if (activeId && activeId !== currentMessageId) {
      currentMessageId = activeId;
      triggerAnalysis(currentMessageId);
    }
  }

  function scheduleCheck(delayMs = 200) {
    if (!isEmailDetailHash()) {
      clearEmailViewState();
      return;
    }
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(checkActiveMessage, delayMs);
  }

  // 1. 최신 Chrome Navigation API + hashchange (뒤로가기 시 0ms 즉시 배너 제거 & 스트림 중단)
  if ("navigation" in window && typeof window.navigation.addEventListener === "function") {
    window.navigation.addEventListener("navigate", (e) => {
      try {
        const destHash = new URL(e.destination.url).hash;
        if (!isEmailDetailHash(destHash)) {
          clearEmailViewState();
        }
      } catch (_) {}
    });
    window.navigation.addEventListener("navigatesuccess", () => scheduleCheck(160));
  }
  window.addEventListener("hashchange", () => scheduleCheck(160));
  window.addEventListener("popstate", () => scheduleCheck(120));

  // 2. Gmail 비동기 DOM 렌더링 보조용 디바운스 MutationObserver
  const observer = new MutationObserver(() => {
    if (!isEmailDetailHash()) return;
    scheduleCheck(250);
  });

  const mainRoot = document.querySelector('div[role="main"]') || document.body;
  observer.observe(mainRoot, { childList: true, subtree: true });

  // 3. 받은편지함 호버 사전 캐싱 (Prefetch): 클릭 전 0.9초 호버 시 조용히 백그라운드 캐싱
  document.addEventListener("mouseover", (e) => {
    if (isEmailDetailHash() || prefetchCount >= MAX_SESSION_PREFETCH) return;
    const row = e.target.closest("tr.zA");
    if (!row) return;

    const idCarrier = row.querySelector("[data-legacy-last-message-id], [data-legacy-message-id]");
    const msgId = idCarrier
      ? idCarrier.getAttribute("data-legacy-last-message-id") || idCarrier.getAttribute("data-legacy-message-id")
      : null;
    if (!msgId || prefetchedIds.has(msgId)) return;

    clearTimeout(hoverPrefetchTimer);
    hoverPrefetchTimer = setTimeout(() => {
      if (isEmailDetailHash() || prefetchedIds.has(msgId) || prefetchCount >= MAX_SESSION_PREFETCH) return;
      prefetchedIds.add(msgId);
      prefetchCount += 1;
      chrome.runtime.sendMessage({ action: "PREFETCH_EMAIL", messageId: msgId });
    }, 900);
  });

  document.addEventListener("mouseout", (e) => {
    if (e.target.closest("tr.zA")) {
      clearTimeout(hoverPrefetchTimer);
    }
  });

  // 초기 진입 시 1회 체크
  scheduleCheck(220);

  async function enrichWithLocalSummaryIfEmpty(data, domBodyText) {
    if (
      !data.mail_summary &&
      enableLocalAi &&
      domBodyText &&
      window.LocalAI &&
      typeof window.LocalAI.summarizeEmailLocally === "function"
    ) {
      const localSummary = await window.LocalAI.summarizeEmailLocally(domBodyText);
      if (localSummary) {
        data.mail_summary = localSummary;
        data._local_summary = true;
      }
    }
    return data;
  }

  async function triggerAnalysis(messageId) {
    const reqSeq = ++activeRequestSeq;
    disconnectEmailStream();

    if (typeof removeBanner === "function") removeBanner();
    if (typeof renderLoadingBanner === "function") renderLoadingBanner("이메일 빠른 보안 분석 시작 중...");

    // 본문 DOM이 막 그려지는 중일 수 있으므로 최대 250ms만 짧게 대기 후 DOM 추출 시도
    let domPayload = extractEmailFromDom();
    if (!domPayload.body_text) {
      await new Promise((r) => setTimeout(r, 250));
      if (reqSeq !== activeRequestSeq || messageId !== currentMessageId || !isEmailDetailHash()) {
        return;
      }
      domPayload = extractEmailFromDom();
    }

    const port = chrome.runtime.connect({ name: "phishing-stream" });
    activeEmailPort = port;
    let receivedAnyResult = false;

    port.onMessage.addListener(async (msg) => {
      if (reqSeq !== activeRequestSeq || messageId !== currentMessageId || !isEmailDetailHash()) {
        disconnectEmailStream();
        return;
      }

      if (msg.type === "chunk" && msg.data) {
        const event = msg.data;
        if (event.stage === "progress" && !receivedAnyResult) {
          if (typeof renderLoadingBanner === "function") {
            renderLoadingBanner(event.message || "분석 중...");
          }
        } else if (event.stage === "partial" && event.data) {
          receivedAnyResult = true;
          const data = await enrichWithLocalSummaryIfEmpty({ ...event.data }, domPayload.body_text);
          if (reqSeq !== activeRequestSeq || messageId !== currentMessageId || !isEmailDetailHash()) return;
          if (typeof renderResultBanner === "function") renderResultBanner(data);
        } else if (event.stage === "final" && event.data) {
          receivedAnyResult = true;
          const data = await enrichWithLocalSummaryIfEmpty({ ...event.data }, domPayload.body_text);
          if (reqSeq !== activeRequestSeq || messageId !== currentMessageId || !isEmailDetailHash()) return;
          if (typeof renderResultBanner === "function") renderResultBanner(data);
        } else if (event.stage === "error") {
          if (typeof renderErrorBanner === "function") {
            renderErrorBanner(event.message || "분석 중 서버 오류가 발생했습니다.");
          }
        }
      } else if (msg.type === "error") {
        if (!receivedAnyResult && typeof renderErrorBanner === "function") {
          renderErrorBanner(msg.message || "분석 중 통신 오류가 발생했습니다.");
        }
        disconnectEmailStream();
      } else if (msg.type === "done") {
        disconnectEmailStream();
      }
    });

    port.onDisconnect.addListener(() => {
      if (activeEmailPort === port) {
        activeEmailPort = null;
      }
    });

    port.postMessage({
      action: "ANALYZE_EMAIL_STREAM",
      payload: {
        message_id: messageId,
        sender: domPayload.sender,
        subject: domPayload.subject,
        body_text: domPayload.body_text,
        links: domPayload.links
      }
    });
  }
}
