function renderResultBanner(data) {
  removeBanner();
  
  const container = document.createElement("div");
  container.id = "phishing-assistant-banner";
  
  // 위험도에 따른 시각적 차등
  const riskClass = data.risk_level === "HIGH" ? "risk-high" : 
                   (data.risk_level === "MEDIUM" ? "risk-medium" : "risk-low");
                   
  const phishingAlert = data.is_phishing ? "🚨 피싱 의심 메일입니다!" : "✅ 안전한 메일로 보입니다.";
  
  const isHighRisk = data.risk_level === "MEDIUM" || data.risk_level === "HIGH";
  const defaultCollapsed = isHighRisk ? "" : "collapsed";

  let actionsHtml = '';
  if (data.actions && data.actions.length > 0) {
    const listHtml = `<ul>${data.actions.map(a => `<li>${a}</li>`).join('')}</ul>`;
    actionsHtml = createCollapsibleSection("권장 조치", listHtml, "banner-actions", defaultCollapsed);
  }
  
  let socEngHtml = '';
  if (data.social_engineering_elements && data.social_engineering_elements.length > 0) {
    socEngHtml = `<div class="banner-soc-eng"><strong>의심 요소:</strong> ${data.social_engineering_elements.join(', ')}</div>`;
  }

  let reasonHtml = createCollapsibleSection("판정 근거", data.reason, "banner-reason", defaultCollapsed);

  let mailSummaryHtml = '';
  if (data.mail_summary) {
    const formattedSummary = data.mail_summary.replace(/\n/g, '<br>');
    const summaryContent = `
      <div style="text-align: right; margin-bottom: 8px;">
        <button class="summary-copy-btn" title="요약 복사">📋 복사</button>
      </div>
      <div class="summary-body">${formattedSummary}</div>
    `;
    // 메일 요약은 항상 펼쳐짐
    mailSummaryHtml = createCollapsibleSection("📋 메일 요약", summaryContent, "banner-mail-summary", "");
  }

  // ── RAG Done Criteria 뱃지 ──────────────────────────────────────
  let ragBadgeHtml = '';
  let ragDocsHtml = '';

  if (data.rag_used) {
    // RAG 사용됨: 뱃지 + 참조 판례 섹션
    ragBadgeHtml = `
      <span class="rag-badge rag-active" title="RAG(검색 증강 생성) 기반 분석이 적용되었습니다.">
        🧠 RAG: ${data.rag_doc_count}개 판례 참조됨
      </span>`;

    if (data.rag_retrieved_docs && data.rag_retrieved_docs.length > 0) {
      const docsListHtml = data.rag_retrieved_docs.map((doc, i) => {
        const labelName = doc.label === "2" || doc.label === "4" || doc.label === "5" ? "⚠️ 피싱/악성" :
                          doc.label === "1" || doc.label === "3" ? "✅ 정상" : `라벨 ${doc.label}`;
        const similarity = doc.distance !== undefined ? `유사도: ${(1 - doc.distance).toFixed(2) * 100 | 0}%` : '';
        const snippet = doc.document ? doc.document.substring(0, 120) + (doc.document.length > 120 ? '…' : '') : '';
        return `<div class="rag-doc-item">
          <span class="rag-doc-meta">[판례 ${i+1}] ${labelName} &nbsp;|&nbsp; 출처: ${doc.source} &nbsp;|&nbsp; ${similarity}</span>
          <div class="rag-doc-snippet">${snippet}</div>
        </div>`;
      }).join('');
      ragDocsHtml = createCollapsibleSection("🔍 RAG 참조 판례", docsListHtml, "banner-rag-docs", "collapsed");
    }
  } else {
    // RAG 미사용: 단순 LLM 판정임을 명시
    ragBadgeHtml = `
      <span class="rag-badge rag-inactive" title="Vector DB 미연결 또는 유사 판례 없음. LLM 단독 판정.">
        🤖 LLM 단독 판정
      </span>`;
  }
  // ─────────────────────────────────────────────────────────────────

  container.innerHTML = `
    <div class="banner-content ${riskClass} collapsible-main">
      <div class="banner-header main-header" style="display: flex; justify-content: space-between; align-items: center; cursor: pointer; user-select: none; margin-bottom: 0;">
        <strong>${phishingAlert}</strong>
        <div style="display: flex; align-items: center; gap: 8px;">
          ${ragBadgeHtml}
          <span class="toggle-icon"></span>
        </div>
      </div>
      <div class="main-content" style="overflow: hidden; transition: max-height 0.3s ease-out, opacity 0.3s ease-out, margin 0.3s ease-out; opacity: 1; max-height: 2000px; margin-top: 8px;">
        <div class="banner-summary">${data.summary}</div>
        ${socEngHtml}
        ${reasonHtml}
        ${actionsHtml}
        ${ragDocsHtml}
        ${mailSummaryHtml}
      </div>
    </div>
  `;

  
  insertBannerIntoGmail(container);

  // 메인 배너 토글 이벤트
  const mainHeader = container.querySelector('.main-header');
  if (mainHeader) {
    mainHeader.addEventListener('click', () => {
      const mainBanner = mainHeader.parentElement;
      mainBanner.classList.toggle('collapsed');
    });
  }

  // 토글 이벤트 리스너 추가
  const headers = container.querySelectorAll('.collapsible-header');
  headers.forEach(header => {
    header.addEventListener('click', () => {
      const section = header.parentElement;
      section.classList.toggle('collapsed');
    });
  });

  if (data.mail_summary) {
    const copyBtn = container.querySelector('.summary-copy-btn');
    if (copyBtn) {
      copyBtn.addEventListener('click', (e) => {
        e.stopPropagation(); // 이벤트 버블링 방지
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
  toast.innerText = message;
  document.body.appendChild(toast);
  
  setTimeout(() => toast.classList.add("show"), 10);
  setTimeout(() => {
    toast.classList.remove("show");
    setTimeout(() => toast.remove(), 300);
  }, 2000);
}

function createCollapsibleSection(title, content, additionalClass, defaultCollapsed) {
  return `
    <div class="collapsible-section ${additionalClass} ${defaultCollapsed}">
      <div class="collapsible-header">
        <strong>${title}</strong>
        <span class="toggle-icon"></span>
      </div>
      <div class="collapsible-content">
        ${content}
      </div>
    </div>
  `;
}

function renderLoadingBanner() {
  removeBanner();
  const container = document.createElement("div");
  container.id = "phishing-assistant-banner";
  container.innerHTML = `
    <div class="banner-content risk-low">
      <div class="banner-header"><strong>보안 어시스턴트 분석 중... ⏳</strong></div>
    </div>
  `;
  insertBannerIntoGmail(container);
}

function renderErrorBanner(errorMessage) {
  removeBanner();
  const container = document.createElement("div");
  container.id = "phishing-assistant-banner";
  container.innerHTML = `
    <div class="banner-content risk-high">
      <div class="banner-header"><strong>분석 오류 ❌</strong></div>
      <div class="banner-summary">${errorMessage}</div>
    </div>
  `;
  insertBannerIntoGmail(container);
}

function removeBanner() {
  const existing = document.getElementById("phishing-assistant-banner");
  if (existing) existing.remove();
}

function insertBannerIntoGmail(container) {
  // Gmail 메일 본문 상단 영역을 찾아 삽입 (.nH.V8djrc.byY 는 환경에 따라 달라질 수 있음)
  const emailContainer = document.querySelector('.nH.V8djrc.byY') || document.querySelector('.nH.hx'); 
  if (emailContainer) {
    emailContainer.prepend(container);
  } else {
    // 적절한 컨테이너를 찾지 못한 경우 body 상단에 렌더링 (디버깅 용도)
    document.body.prepend(container);
  }
}
