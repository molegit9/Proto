/**
 * Gmail 보안 분석 배너 렌더러 (v2.0)
 * - Closed Shadow DOM으로 스타일 및 DOM 격리
 * - 모든 동적 문자열에 escapeHtml() 적용하여 XSS 원천 차단
 * - Chrome Side Panel 상세 대시보드 바로가기 버튼 제공
 */

function escapeHtml(str) {
  return String(str ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

const SHADOW_BANNER_CSS = `
  :host {
    all: initial;
    display: block;
    margin: 8px 16px 12px 16px;
    font-family: 'Google Sans', 'Pretendard', Roboto, sans-serif;
    z-index: 100;
    position: relative;
    contain: layout style;
  }
  * { box-sizing: border-box; }
  .banner-content {
    padding: 16px;
    border-radius: 10px;
    border-left: 6px solid #ccc;
    background-color: #f9f9f9;
    box-shadow: 0 1px 4px rgba(0,0,0,0.12), 0 1px 2px rgba(0,0,0,0.18);
    color: #202124;
  }
  .banner-content.risk-low { border-left-color: #34A853; background-color: #e8f5e9; }
  .banner-content.risk-medium { border-left-color: #FBBC05; background-color: #fff8e1; }
  .banner-content.risk-high { border-left-color: #EA4335; background-color: #fce8e6; }
  .banner-header {
    font-size: 15px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
  }
  .main-header { cursor: pointer; user-select: none; }
  .header-right {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .sidepanel-btn {
    border: 1px solid rgba(26, 115, 232, 0.35);
    background: #ffffff;
    color: #1a73e8;
    font-size: 11px;
    font-weight: 600;
    padding: 4px 10px;
    border-radius: 16px;
    cursor: pointer;
    transition: background 0.15s;
  }
  .sidepanel-btn:hover { background: #e8f0fe; }
  .main-content {
    overflow: hidden;
    transition: max-height 0.3s ease-out, opacity 0.3s ease-out, margin 0.3s ease-out;
    opacity: 1;
    max-height: 2400px;
    margin-top: 10px;
  }
  .collapsible-main.collapsed .main-content {
    max-height: 0 !important;
    opacity: 0 !important;
    margin-top: 0 !important;
  }
  .banner-summary { font-size: 14px; margin-bottom: 8px; line-height: 1.45; }
  .banner-soc-eng {
    font-size: 13px;
    margin-bottom: 8px;
    color: #444;
    background: rgba(0,0,0,0.05);
    padding: 4px 8px;
    border-radius: 4px;
    display: inline-block;
  }
  .banner-reason { font-size: 14px; color: #333; line-height: 1.5; }
  .banner-actions { font-size: 14px; }
  .banner-actions ul { margin: 4px 0 0; padding-left: 22px; }
  .banner-actions li { margin-bottom: 4px; }
  .collapsible-section {
    margin-top: 12px;
    border-top: 1px dashed rgba(0,0,0,0.12);
    padding-top: 10px;
  }
  .collapsible-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    cursor: pointer;
    user-select: none;
  }
  .collapsible-header strong { color: #202124; font-size: 13px; }
  .toggle-icon::after {
    content: '▲';
    font-size: 11px;
    color: #5f6368;
    display: inline-block;
  }
  .collapsible-section.collapsed .toggle-icon::after,
  .collapsible-main.collapsed .main-header .toggle-icon::after {
    content: '▼';
  }
  .collapsible-content {
    margin-top: 8px;
    max-height: 700px;
    overflow: hidden;
    transition: max-height 0.25s ease-out, opacity 0.25s ease-out, margin-top 0.25s ease-out;
    opacity: 1;
  }
  .collapsible-section.collapsed .collapsible-content {
    max-height: 0;
    opacity: 0;
    margin-top: 0;
  }
  .banner-mail-summary {
    background-color: rgba(0, 0, 0, 0.03);
    padding: 12px;
    border-radius: 6px;
  }
  .summary-copy-btn {
    background: #fff;
    border: 1px solid #ccc;
    border-radius: 4px;
    padding: 4px 8px;
    cursor: pointer;
    font-size: 12px;
    color: #333;
  }
  .summary-copy-btn:hover { background: #f0f0f0; }
  .summary-body {
    font-size: 14px;
    line-height: 1.5;
    color: #333;
    white-space: pre-line;
  }
  .rag-badge {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    font-size: 11px;
    font-weight: 600;
    padding: 3px 10px;
    border-radius: 20px;
    white-space: nowrap;
  }
  .rag-badge.rag-active { background: #e8f0fe; color: #1a73e8; border: 1px solid #a8c5fa; }
  .rag-badge.rag-inactive { background: #f1f3f4; color: #5f6368; border: 1px solid #dadce0; }
  .rag-badge.deep-pending {
    background: #fef3c7;
    color: #92400e;
    border: 1px solid #fcd34d;
  }
  .rag-doc-item {
    background: rgba(26, 115, 232, 0.05);
    border: 1px solid rgba(26, 115, 232, 0.15);
    border-radius: 6px;
    padding: 8px 12px;
    margin-bottom: 8px;
  }
  .rag-doc-meta {
    display: block;
    font-size: 11px;
    font-weight: 600;
    color: #1a73e8;
    margin-bottom: 4px;
  }
  .rag-doc-snippet {
    font-size: 12px;
    color: #444;
    line-height: 1.45;
    word-break: break-word;
  }
`;

function createShadowBannerHost(innerHtml) {
  const host = document.createElement("div");
  host.id = "phishing-assistant-banner";
  const shadow = host.attachShadow({ mode: "closed" });

  const styleEl = document.createElement("style");
  styleEl.textContent = SHADOW_BANNER_CSS;

  const wrapper = document.createElement("div");
  wrapper.innerHTML = innerHtml;

  shadow.appendChild(styleEl);
  shadow.appendChild(wrapper);
  return { host, shadow };
}

function renderResultBanner(data) {
  removeBanner();

  const riskClass =
    data.risk_level === "HIGH"
      ? "risk-high"
      : data.risk_level === "MEDIUM"
      ? "risk-medium"
      : "risk-low";

  const phishingAlert = data.is_phishing ? "🚨 피싱 의심 메일입니다!" : "✅ 안전한 메일로 보입니다.";
  const isHighRisk = data.risk_level === "MEDIUM" || data.risk_level === "HIGH";
  const defaultCollapsed = isHighRisk ? "" : "collapsed";

  let actionsHtml = "";
  if (Array.isArray(data.actions) && data.actions.length > 0) {
    const listHtml = `<ul>${data.actions.map((a) => `<li>${escapeHtml(a)}</li>`).join("")}</ul>`;
    actionsHtml = createCollapsibleSection("권장 조치", listHtml, "banner-actions", defaultCollapsed);
  }

  let socEngHtml = "";
  if (Array.isArray(data.social_engineering_elements) && data.social_engineering_elements.length > 0) {
    const safeItems = data.social_engineering_elements.map((item) => escapeHtml(item)).join(", ");
    socEngHtml = `<div class="banner-soc-eng"><strong>의심 요소:</strong> ${safeItems}</div>`;
  }

  const reasonHtml = createCollapsibleSection("판정 근거", escapeHtml(data.reason), "banner-reason", defaultCollapsed);

  let mailSummaryHtml = "";
  if (data.mail_summary) {
    const localBadge = data._local_summary ? " (⚡ 온디바이스 AI)" : "";
    const summaryContent = `
      <div style="text-align: right; margin-bottom: 8px;">
        <button class="summary-copy-btn" title="요약 복사">📋 복사</button>
      </div>
      <div class="summary-body">${escapeHtml(data.mail_summary)}</div>
    `;
    mailSummaryHtml = createCollapsibleSection(`📋 메일 요약${localBadge}`, summaryContent, "banner-mail-summary", "");
  }

  let ragBadgeHtml = "";
  let ragDocsHtml = "";

  if (data.rag_used) {
    ragBadgeHtml = `
      <span class="rag-badge rag-active" title="과거 유사 위협 데이터를 기반으로 분석을 수행했습니다.">
        🧠 과거 사례: ${Number(data.rag_doc_count) || 0}개 참조
      </span>`;

    if (Array.isArray(data.rag_retrieved_docs) && data.rag_retrieved_docs.length > 0) {
      const docsListHtml = data.rag_retrieved_docs
        .map((doc, i) => {
          const labelName =
            doc.label === "2" || doc.label === "4" || doc.label === "5"
              ? "⚠️ 악성 위협"
              : doc.label === "1" || doc.label === "3"
              ? "✅ 정상"
              : `유형 ${escapeHtml(doc.label)}`;
          const similarity =
            doc.distance !== undefined
              ? `유사도: ${Math.max(0, Math.round((1 - Number(doc.distance)) * 100))}%`
              : "";
          const rawDoc = String(doc.document || "");
          const snippet = escapeHtml(rawDoc.length > 120 ? `${rawDoc.substring(0, 120)}…` : rawDoc);
          return `<div class="rag-doc-item">
            <span class="rag-doc-meta">[참고 사례 ${i + 1}] ${labelName} | 출처: ${escapeHtml(doc.source)} ${similarity ? `| ${similarity}` : ""}</span>
            <div class="rag-doc-snippet">${snippet}</div>
          </div>`;
        })
        .join("");
      ragDocsHtml = createCollapsibleSection("🔍 과거 유사 위협 사례 확인", docsListHtml, "banner-rag-docs", "collapsed");
    }
  } else {
    ragBadgeHtml = `
      <span class="rag-badge rag-inactive" title="안전한 분석을 위해 AI 실시간 문맥 추론을 수행했습니다.">
        🤖 AI 실시간 문맥 분석
      </span>`;
  }

  const pendingBadgeHtml = data.deep_scan_pending
    ? `<span class="rag-badge deep-pending" title="의심 링크를 가상 브라우저로 심층 검사 중입니다.">🕵️ 의심 링크 심층 분석 중...</span>`
    : "";

  const html = `
    <div class="banner-content ${riskClass} collapsible-main">
      <div class="banner-header main-header">
        <strong>${phishingAlert}</strong>
        <div class="header-right">
          ${pendingBadgeHtml}
          ${ragBadgeHtml}
          <button type="button" class="sidepanel-btn" title="크롬 사이드 패널에서 상세 리포트 보기">📊 상세 대시보드</button>
          <span class="toggle-icon"></span>
        </div>
      </div>
      <div class="main-content">
        <div class="banner-summary">${escapeHtml(data.summary)}</div>
        ${socEngHtml}
        ${reasonHtml}
        ${actionsHtml}
        ${ragDocsHtml}
        ${mailSummaryHtml}
      </div>
    </div>
  `;

  const { host, shadow } = createShadowBannerHost(html);
  insertBannerIntoGmail(host);

  const mainHeader = shadow.querySelector(".main-header");
  if (mainHeader) {
    mainHeader.addEventListener("click", () => {
      mainHeader.parentElement.classList.toggle("collapsed");
    });
  }

  const spBtn = shadow.querySelector(".sidepanel-btn");
  if (spBtn) {
    spBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      chrome.runtime.sendMessage({ action: "OPEN_SIDE_PANEL" });
    });
  }

  const headers = shadow.querySelectorAll(".collapsible-header");
  headers.forEach((header) => {
    header.addEventListener("click", () => {
      header.parentElement.classList.toggle("collapsed");
    });
  });

  if (data.mail_summary) {
    const copyBtn = shadow.querySelector(".summary-copy-btn");
    if (copyBtn) {
      copyBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        navigator.clipboard.writeText(data.mail_summary).then(() => {
          showToast("복사됨!");
        });
      });
    }
  }
}

function showToast(message) {
  const toast = document.createElement("div");
  toast.className = "phishing-assistant-toast";
  toast.textContent = message;
  document.body.appendChild(toast);

  setTimeout(() => toast.classList.add("show"), 10);
  setTimeout(() => {
    toast.classList.remove("show");
    setTimeout(() => toast.remove(), 300);
  }, 2000);
}

function createCollapsibleSection(title, contentHtml, additionalClass, defaultCollapsed) {
  return `
    <div class="collapsible-section ${additionalClass} ${defaultCollapsed}">
      <div class="collapsible-header">
        <strong>${escapeHtml(title)}</strong>
        <span class="toggle-icon"></span>
      </div>
      <div class="collapsible-content">
        ${contentHtml}
      </div>
    </div>
  `;
}

function renderLoadingBanner(statusMessage) {
  const msg = statusMessage || "보안 어시스턴트 분석 중...";
  const existing = document.getElementById("phishing-assistant-banner");
  if (existing && existing.dataset.loading === "true" && existing._loadingTextEl) {
    existing._loadingTextEl.textContent = `${msg} ⏳`;
    return;
  }
  removeBanner();
  const { host, shadow } = createShadowBannerHost(`
    <div class="banner-content risk-low">
      <div class="banner-header"><strong class="loading-title">${escapeHtml(msg)} ⏳</strong></div>
    </div>
  `);
  host.dataset.loading = "true";
  host._loadingTextEl = shadow.querySelector(".loading-title");
  insertBannerIntoGmail(host);
}

function renderErrorBanner(errorMessage) {
  removeBanner();
  const { host } = createShadowBannerHost(`
    <div class="banner-content risk-high">
      <div class="banner-header"><strong>분석 오류 ❌</strong></div>
      <div class="banner-summary" style="margin-top: 8px;">${escapeHtml(errorMessage)}</div>
    </div>
  `);
  insertBannerIntoGmail(host);
}

function triggerGmailLayoutRecalc() {
  // Gmail은 JS로 받은편지함 리스트 스크롤 영역(.Tm.aeJ 등)의 인라인 height를 계산합니다.
  // 배너 삽입/제거 직후 resize 이벤트를 보내 Gmail이 뷰포트 높이를 즉시 100% 재계산하도록 합니다.
  const dispatch = () => {
    try {
      window.dispatchEvent(new Event("resize"));
    } catch (_) {}
  };
  requestAnimationFrame(dispatch);
  setTimeout(dispatch, 120);
  setTimeout(dispatch, 350);
}

function removeBanner() {
  const existingList = document.querySelectorAll("#phishing-assistant-banner");
  const hadBanner = existingList.length > 0;
  existingList.forEach((el) => el.remove());
  if (hadBanner) {
    triggerGmailLayoutRecalc();
  }
}

function findVisibleEmailContainer() {
  // 현재 화면에 실제로 표시 중인(offsetParent !== null) 메일 스레드 내부 컨테이너만 선택합니다.
  // (숨겨진 캐시 DOM이나 document.body에 삽입하면 Gmail 전체 100vh 레이아웃 높이가 밀려 하단이 잘립니다.)
  const selectors = [
    'div[role="main"] .nH.hx',
    '.nH.hx',
    'div[role="main"] .aHU',
    '.nH.V8djrc.byY'
  ];

  for (const sel of selectors) {
    const candidates = document.querySelectorAll(sel);
    for (const el of candidates) {
      if (el.offsetParent !== null && el.getBoundingClientRect().height > 0) {
        return el;
      }
    }
  }

  // 마지막 보조: 현재 열린 메시지 엘리먼트 바로 위
  const msgEls = document.querySelectorAll("[data-legacy-message-id]");
  for (let i = msgEls.length - 1; i >= 0; i--) {
    const el = msgEls[i];
    if (el.offsetParent !== null) {
      return el.parentElement;
    }
  }
  return null;
}

function insertBannerIntoGmail(container) {
  // 메일 열람 화면이 아니면 절대 삽입하지 않음
  if (!window.location.hash.includes("/")) {
    return;
  }

  const emailContainer = findVisibleEmailContainer();
  if (emailContainer) {
    emailContainer.prepend(container);
  }
  // 메일 컨테이너를 찾지 못했을 때 document.body.prepend()는 Gmail 레이아웃을 깨트리므로 수행하지 않습니다.
}
