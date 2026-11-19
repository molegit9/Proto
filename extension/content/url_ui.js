function initUrlAnalysis() {
  // 보호 대상 탑티어 도메인들
  const topBrands = ["apple.com", "naver.com", "google.com", "amazon.com", "github.com", "facebook.com", "netflix.com"];

  // 상태 관리
  let showProgress = true;
  let enableDeepScan = false;
  let enableLocalAi = true;

  if (typeof chrome !== "undefined" && chrome.storage) {
    chrome.storage.local.get(["showProgress", "enableDeepScan", "enableLocalAi"], (result) => {
      if (result.showProgress !== undefined) showProgress = result.showProgress;
      if (result.enableDeepScan !== undefined) enableDeepScan = result.enableDeepScan;
      if (result.enableLocalAi !== undefined) enableLocalAi = result.enableLocalAi;
    });
    chrome.storage.onChanged.addListener((changes) => {
      if (changes.showProgress) showProgress = changes.showProgress.newValue;
      if (changes.enableDeepScan) enableDeepScan = changes.enableDeepScan.newValue;
      if (changes.enableLocalAi) enableLocalAi = changes.enableLocalAi.newValue;
    });
  }

  // Levenshtein 거리 계산 알고리즘 (0.01초 소요)
  function calculateDistance(a, b) {
    if (!a) return b ? b.length : 0;
    if (!b) return a.length;
    const matrix = [];
    for (let i = 0; i <= b.length; i++) matrix[i] = [i];
    for (let j = 0; j <= a.length; j++) matrix[0][j] = j;
    for (let i = 1; i <= b.length; i++) {
      for (let j = 1; j <= a.length; j++) {
        if (b.charAt(i - 1) === a.charAt(j - 1)) {
          matrix[i][j] = matrix[i - 1][j - 1];
        } else {
          matrix[i][j] = Math.min(
            matrix[i - 1][j - 1] + 1,
            Math.min(matrix[i][j - 1] + 1, matrix[i - 1][j] + 1)
          );
        }
      }
    }
    return matrix[b.length][a.length];
  }

  function checkLevenshtein(domain) {
    try {
      const parts = domain.split(".");
      let baseDomain = domain;
      if (parts.length > 2) {
        baseDomain = parts.slice(-2).join(".");
      }

      for (const brand of topBrands) {
        if (baseDomain === brand) return { spoofed: false, brand, exact_match: true };
        const dist = calculateDistance(baseDomain, brand);
        if (dist > 0 && dist <= 2) {
          return { spoofed: true, brand, exact_match: false };
        }
      }
      return { spoofed: false, brand: null, exact_match: false };
    } catch (err) {
      console.error("[Phishing Detector] Levenshtein 분석 중 오류:", err);
      return { spoofed: false, brand: null, exact_match: false };
    }
  }

  let hoverTimer;
  let tooltipHost = null;
  let tooltipShadow = null;
  let tooltipCard = null;
  let activeStreamPort = null;

  const SHADOW_TOOLTIP_CSS = `
    :host {
      all: initial;
      position: absolute;
      z-index: 2147483647;
      pointer-events: none;
    }
    .tooltip-card {
      background-color: rgba(20, 24, 33, 0.96);
      backdrop-filter: blur(10px);
      color: #f8fafc;
      padding: 14px 16px;
      border-radius: 12px;
      box-shadow: 0 10px 28px rgba(0, 0, 0, 0.45);
      font-family: 'Pretendard', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      font-size: 13px;
      width: 295px;
      max-width: 90vw;
      border: 1px solid rgba(255, 255, 255, 0.12);
      border-top: 4px solid #64748b;
      animation: fadeInTooltip 0.18s ease-out forwards;
      box-sizing: border-box;
      line-height: 1.45;
    }
    @keyframes fadeInTooltip {
      from { opacity: 0; transform: translateY(5px); }
      to { opacity: 1; transform: translateY(0); }
    }
    @keyframes spin {
      from { transform: rotate(0deg); }
      to { transform: rotate(360deg); }
    }
    .tooltip-card.danger { border-top-color: #ef4444; }
    .tooltip-card.danger .score-num { color: #f87171; }
    .tooltip-card.warning { border-top-color: #f59e0b; }
    .tooltip-card.warning .score-num { color: #fbbf24; }
    .tooltip-card.safe { border-top-color: #10b981; }
    .tooltip-card.safe .score-num { color: #34d399; }
    .score {
      font-size: 14px;
      font-weight: 600;
      margin-bottom: 6px;
      color: #ffffff;
    }
    .reason {
      font-size: 13px;
      color: #cbd5e1;
      white-space: pre-line;
      word-break: break-word;
    }
    .progress-row {
      display: flex;
      align-items: center;
      gap: 8px;
      color: #e2e8f0;
      font-size: 13px;
    }
    .spinner {
      display: inline-block;
      animation: spin 1.2s linear infinite;
    }
    .footer-badges {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      margin-top: 8px;
      padding-top: 8px;
      border-top: 1px solid rgba(255, 255, 255, 0.1);
    }
    .badge {
      font-size: 11px;
      font-weight: 600;
      padding: 2px 7px;
      border-radius: 999px;
    }
    .badge-blocked {
      background: rgba(239, 68, 68, 0.2);
      color: #fca5a5;
      border: 1px solid rgba(239, 68, 68, 0.4);
    }
    .badge-nano {
      background: rgba(16, 185, 129, 0.2);
      color: #6ee7b7;
      border: 1px solid rgba(16, 185, 129, 0.4);
    }
  `;

  function ensureShadowTooltip(x, y) {
    if (!tooltipHost) {
      tooltipHost = document.createElement("div");
      tooltipHost.setAttribute("data-web-sheriff-tooltip", "true");
      tooltipShadow = tooltipHost.attachShadow({ mode: "closed" });

      const styleEl = document.createElement("style");
      styleEl.textContent = SHADOW_TOOLTIP_CSS;

      tooltipCard = document.createElement("div");
      tooltipCard.className = "tooltip-card";

      tooltipShadow.appendChild(styleEl);
      tooltipShadow.appendChild(tooltipCard);
      document.body.appendChild(tooltipHost);
    }

    // 화면 우측 벗어남 방지
    const maxX = window.scrollX + window.innerWidth - 315;
    const safeX = Math.max(window.scrollX + 10, Math.min(x + 15, maxX));
    tooltipHost.style.left = `${safeX}px`;
    tooltipHost.style.top = `${y + 15}px`;
  }

  function removeTooltip() {
    if (tooltipHost) {
      tooltipHost.remove();
      tooltipHost = null;
      tooltipShadow = null;
      tooltipCard = null;
    }
  }

  function showSafetyTooltip(x, y, safetyScore, reason, options = {}) {
    ensureShadowTooltip(x, y);

    let colorClass = "safe";
    let label = "안전함";
    if (safetyScore <= 40) {
      colorClass = "danger";
      label = "위험 (접속 금지)";
    } else if (safetyScore <= 70) {
      colorClass = "warning";
      label = "주의 요망";
    }

    tooltipCard.className = `tooltip-card ${colorClass}`;
    tooltipCard.textContent = "";

    const scoreEl = document.createElement("div");
    scoreEl.className = "score";
    scoreEl.appendChild(document.createTextNode("보안 점수: "));
    const strongEl = document.createElement("strong");
    strongEl.className = "score-num";
    strongEl.textContent = `${safetyScore}점`;
    scoreEl.appendChild(strongEl);
    scoreEl.appendChild(document.createTextNode(` / 100점 (${label})`));

    const reasonEl = document.createElement("div");
    reasonEl.className = "reason";
    // 과거 호환: 혹시 남아있는 <br> 문자열을 안전한 개행으로 치환 후 textContent 사용 (XSS 차단)
    reasonEl.textContent = String(reason || "").replace(/<br\s*\/?>/gi, "\n");

    tooltipCard.appendChild(scoreEl);
    tooltipCard.appendChild(reasonEl);

    if (options.autoBlocked || options.engine === "chrome-built-in-ai") {
      const footer = document.createElement("div");
      footer.className = "footer-badges";
      if (options.autoBlocked) {
        const b = document.createElement("span");
        b.className = "badge badge-blocked";
        b.textContent = "🛡️ 위험 링크 자동 차단됨";
        footer.appendChild(b);
      }
      if (options.engine === "chrome-built-in-ai") {
        const b = document.createElement("span");
        b.className = "badge badge-nano";
        b.textContent = "⚡ 온디바이스 AI 즉시 분석";
        footer.appendChild(b);
      }
      tooltipCard.appendChild(footer);
    }
  }

  function showProgressTooltip(x, y, message) {
    ensureShadowTooltip(x, y);
    tooltipCard.className = "tooltip-card";
    tooltipCard.textContent = "";

    const row = document.createElement("div");
    row.className = "progress-row";

    const spinner = document.createElement("span");
    spinner.className = "spinner";
    spinner.textContent = "⏳";

    const textSpan = document.createElement("span");
    textSpan.textContent = String(message || "분석 중...");

    row.appendChild(spinner);
    row.appendChild(textSpan);
    tooltipCard.appendChild(row);
  }

  function disconnectActiveStream() {
    if (activeStreamPort) {
      try {
        activeStreamPort.disconnect();
      } catch (_) {}
      activeStreamPort = null;
    }
  }

  /**
   * Background Service Worker를 통해 NDJSON 스트리밍 API를 호출합니다.
   * (Chrome 142+ Local Network Access / Content Script CORS 차단 회피)
   */
  function startBackgroundStream(action, payload, { onChunk, onError, onDone }) {
    disconnectActiveStream();

    const port = chrome.runtime.connect({ name: "phishing-stream" });
    activeStreamPort = port;
    let finished = false;

    port.onMessage.addListener((msg) => {
      if (activeStreamPort !== port) return;

      if (msg.type === "chunk") {
        if (onChunk) onChunk(msg.data);
      } else if (msg.type === "error") {
        finished = true;
        if (onError) onError(msg.message);
        disconnectActiveStream();
      } else if (msg.type === "done") {
        finished = true;
        if (onDone) onDone();
        disconnectActiveStream();
      }
    });

    port.onDisconnect.addListener(() => {
      if (activeStreamPort === port) {
        activeStreamPort = null;
      }
      if (!finished && chrome.runtime.lastError && onError) {
        onError("백그라운드 서비스 연결이 끊어졌습니다.");
      }
    });

    port.postMessage({ action, payload });
    return port;
  }

  document.addEventListener("mouseover", (e) => {
    const link = e.target.closest("a");
    if (!link) return;

    const url = link.href;
    if (!url || !url.startsWith("http")) return;

    const pageX = e.pageX;
    const pageY = e.pageY;

    hoverTimer = setTimeout(() => {
      try {
        const domain = new URL(url).hostname;
        const brandData = checkLevenshtein(domain);

        startBackgroundStream(
          "ANALYZE_URL",
          {
            url,
            is_spoofed: brandData.spoofed,
            target_brand: brandData.brand,
            is_exact_match: brandData.exact_match,
            enable_deep_scan: enableDeepScan
          },
          {
            onChunk: (result) => {
              if (result.progress) {
                if (showProgress) {
                  showProgressTooltip(pageX, pageY, result.progress);
                }
              } else if (result.status === "success") {
                const data = typeof result.data === "string" ? JSON.parse(result.data) : result.data;
                showSafetyTooltip(pageX, pageY, data.safety_score, data.reason, {
                  autoBlocked: Boolean(result.auto_blocked)
                });
              } else if (result.status === "error") {
                showSafetyTooltip(pageX, pageY, 50, `분석 실패: ${result.message}`);
              }
            },
            onError: () => {
              showSafetyTooltip(pageX, pageY, 50, "서버와 통신할 수 없습니다. 서버가 켜져있는지 확인해주세요.");
            }
          }
        );
      } catch (err) {
        console.error("[Phishing Detector] 호버 분석 초기화 에러:", err);
        showSafetyTooltip(pageX, pageY, 50, "URL 분석 요청 중 오류가 발생했습니다.");
      }
    }, 500);
  });

  document.addEventListener("mouseout", (e) => {
    const link = e.target.closest("a");
    if (!link) return;

    clearTimeout(hoverTimer);
    disconnectActiveStream();
    const selectedText = window.getSelection().toString().trim();
    if (selectedText.length === 0) removeTooltip();
  });

  document.addEventListener("mousedown", (e) => {
    if (!e.target.closest("[data-web-sheriff-tooltip]")) {
      setTimeout(() => {
        const selectedText = window.getSelection().toString().trim();
        if (selectedText.length === 0) removeTooltip();
      }, 10);
    }
  });

  // 드래그(텍스트 선택) 감지 — 온디바이스 Chrome Built-in AI 1차 스크리닝 + 백엔드 RAG 에스컬레이션
  document.addEventListener("mouseup", async (e) => {
    if (e.target.closest("[data-web-sheriff-tooltip]")) return;

    const selectedText = window.getSelection().toString().trim();
    if (selectedText.length < 10 || selectedText.length > 500) return;

    const pageX = e.pageX;
    const pageY = e.pageY;

    // 1단계: 온디바이스 Chrome Built-in AI (Gemini Nano) 우선 스크리닝
    if (enableLocalAi && window.LocalAI && typeof window.LocalAI.screenTextLocally === "function") {
      if (showProgress) {
        showProgressTooltip(pageX, pageY, "⚡ 온디바이스 AI 1차 빠른 검사 중...");
      }
      const localResult = await window.LocalAI.screenTextLocally(selectedText);
      if (localResult && !localResult.needs_escalation) {
        const safetyScore = Math.max(0, Math.min(100, 100 - localResult.risk_score));
        const bodyText = `${localResult.reason}\n🛡️ 제안: ${localResult.mitigation}`;
        showSafetyTooltip(pageX, pageY, safetyScore, bodyText, { engine: "chrome-built-in-ai" });
        chrome.runtime.sendMessage({
          action: "SAVE_REPORT",
          report: {
            type: "text",
            target: selectedText,
            safety_score: safetyScore,
            reason: localResult.reason,
            actions: [localResult.mitigation],
            engine: "chrome-built-in-ai"
          }
        });
        return;
      }
      if (localResult && localResult.needs_escalation && showProgress) {
        showProgressTooltip(pageX, pageY, "⚠️ 의심 징후 감지 — 정밀 RAG 서버로 에스컬레이션 중...");
      }
    } else if (showProgress) {
      showProgressTooltip(pageX, pageY, "분석 서버 연결 중...");
    }

    // 2단계: 백엔드 RAG + Cloud Gemini 정밀 분석
    startBackgroundStream(
      "ANALYZE_TEXT",
      { selected_text: selectedText },
      {
        onChunk: (result) => {
          if (result.progress) {
            if (showProgress) {
              showProgressTooltip(pageX, pageY, result.progress);
            }
          } else if (result && result.score !== undefined) {
            const safetyScore = Math.max(0, Math.min(100, 100 - Number(result.score)));
            const bodyText = `${result.reason}\n🛡️ 제안: ${result.mitigation || ""}`;
            showSafetyTooltip(pageX, pageY, safetyScore, bodyText);
          } else if (result.risk_level === "에러" || result.risk_level === "시스템 오류") {
            showSafetyTooltip(pageX, pageY, 50, `분석 에러: ${result.reason}`);
          }
        },
        onError: () => {
          showSafetyTooltip(pageX, pageY, 50, "서버와 통신할 수 없습니다. (API 연동 실패)");
        }
      }
    );
  });

  console.log("[Phishing Detector] v2.0 Shadow DOM + Service Worker Port + LocalAI 클라이언트 로드 완료");
}
