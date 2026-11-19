document.addEventListener("DOMContentLoaded", async () => {
  // 1. 탭 전환
  const tabs = document.querySelectorAll(".sp-tab");
  const panels = document.querySelectorAll(".sp-panel");
  tabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      tabs.forEach((t) => t.classList.remove("active"));
      panels.forEach((p) => p.classList.remove("active"));
      tab.classList.add("active");
      const target = document.getElementById(tab.dataset.tab);
      if (target) target.classList.add("active");
    });
  });

  // 2. Chrome Built-in AI 지원 상태 진단
  const aiPill = document.getElementById("ai-status-pill");
  if (window.LocalAI && typeof window.LocalAI.getCapabilities === "function") {
    const caps = await window.LocalAI.getCapabilities();
    const hasPrompt = caps.promptApi === "available" || caps.promptApi === "readily";
    const hasSummary = caps.summarizerApi === "available" || caps.summarizerApi === "readily";
    if (hasPrompt || hasSummary) {
      aiPill.textContent = "⚡ Gemini Nano 활성";
      aiPill.className = "pill pill-nano";
      aiPill.title = `Prompt API: ${caps.promptApi}, Summarizer API: ${caps.summarizerApi}`;
    } else {
      aiPill.textContent = "☁️ Cloud AI 모드";
      aiPill.className = "pill pill-muted";
      aiPill.title = `로컬 내장 AI 미지원/미다운로드 (Prompt: ${caps.promptApi}, Summarizer: ${caps.summarizerApi})`;
    }
  } else {
    aiPill.textContent = "☁️ Cloud AI 모드";
  }

  // 3. 리포트 렌더링
  function renderReport(report) {
    const emptyEl = document.getElementById("empty-report");
    const contentEl = document.getElementById("report-content");
    if (!report) {
      emptyEl.classList.remove("hidden");
      contentEl.classList.add("hidden");
      return;
    }

    emptyEl.classList.add("hidden");
    contentEl.classList.remove("hidden");

    const score = Math.max(0, Math.min(100, Number(report.safety_score ?? 50)));
    let level = "safe";
    let verdictText = "안전함";
    if (score <= 40) {
      level = "danger";
      verdictText = "위험 (접속 금지)";
    } else if (score <= 70) {
      level = "warning";
      verdictText = "주의 요망";
    }

    const scoreCard = document.getElementById("score-card");
    scoreCard.className = `score-card ${level}`;

    const typeLabels = {
      url: "🔗 URL 호버 분석",
      text: "📝 텍스트 드래그 분석",
      email: "📧 Gmail 메일 분석"
    };
    document.getElementById("report-type-badge").textContent = typeLabels[report.type] || "보안 분석";
    document.getElementById("report-time").textContent = report.timestamp
      ? new Date(report.timestamp).toLocaleTimeString("ko-KR")
      : "-";
    document.getElementById("report-score").textContent = String(score);

    const verdictEl = document.getElementById("report-verdict");
    verdictEl.textContent = verdictText;
    verdictEl.className = `verdict-pill ${level}`;

    document.getElementById("score-bar-fill").style.width = `${score}%`;
    document.getElementById("report-target").textContent = report.target || "(대상 정보 없음)";
    document.getElementById("report-reason").textContent = String(report.reason || "판정 근거 없음").replace(/<br\s*\/?>/gi, "\n");

    const engineTag = document.getElementById("report-engine-tag");
    engineTag.textContent = report.engine === "chrome-built-in-ai"
      ? "⚡ 처리 엔진: Chrome Built-in AI (온디바이스 Gemini Nano)"
      : "☁️ 처리 엔진: 웹보안관 하이브리드 백엔드 (Gemini + RAG + Sandbox)";

    // 권장 조치
    const actionsCard = document.getElementById("card-actions");
    const actionsList = document.getElementById("report-actions-list");
    actionsList.textContent = "";
    const actions = Array.isArray(report.actions) ? report.actions.filter(Boolean) : [];
    if (actions.length > 0) {
      actionsCard.classList.remove("hidden");
      actions.forEach((act) => {
        const li = document.createElement("li");
        li.textContent = String(act);
        actionsList.appendChild(li);
      });
    } else {
      actionsCard.classList.add("hidden");
    }

    // 사회공학 요소
    const socCard = document.getElementById("card-soc-eng");
    const socTags = document.getElementById("soc-eng-tags");
    socTags.textContent = "";
    const elements = Array.isArray(report.social_engineering_elements) ? report.social_engineering_elements.filter(Boolean) : [];
    if (elements.length > 0) {
      socCard.classList.remove("hidden");
      elements.forEach((el) => {
        const chip = document.createElement("span");
        chip.className = "tag-chip";
        chip.textContent = String(el);
        socTags.appendChild(chip);
      });
    } else {
      socCard.classList.add("hidden");
    }

    // 정밀 분석 기술 상세
    const techCard = document.getElementById("card-technical");
    const techContainer = document.getElementById("technical-details");
    techContainer.textContent = "";
    const rows = [];

    const details = report.details || {};
    if (details.domain_age) {
      rows.push(["도메인 생성일(RDAP)", details.domain_age]);
    }
    if (details.vt_findings) {
      const vt = details.vt_findings;
      if (vt.status) {
        rows.push(["VirusTotal 상태", vt.status]);
      } else if (vt.scanned !== undefined) {
        rows.push(["VirusTotal 검사 링크", `${vt.scanned}건 (악성 ${vt.malicious_found || 0}건)`]);
      }
    }
    const dynList = Array.isArray(details.dynamic_findings)
      ? details.dynamic_findings
      : details.dynamic_findings
      ? [details.dynamic_findings]
      : [];

    dynList.forEach((dyn, idx) => {
      const prefix = dynList.length > 1 ? `[링크 ${idx + 1}] ` : "";
      if (dyn.final_url && dyn.final_url !== dyn.original_url) {
        rows.push([`${prefix}최종 리다이렉트`, dyn.final_url]);
      }
      const flags = [];
      if (dyn.is_redirected) flags.push("리다이렉트");
      if (dyn.has_password_field) flags.push("비밀번호 입력란");
      if (dyn.has_hidden_form) flags.push("히든 폼");
      if (dyn.screenshot_captured) flags.push("시각 분석(Vision) 완료");
      rows.push([`${prefix}가상브라우저 탐지`, flags.length > 0 ? flags.join(", ") : "특이사항 없음"]);
      if (Array.isArray(dyn.redirect_chain) && dyn.redirect_chain.length > 0) {
        rows.push([`${prefix}리다이렉트 횟수`, `${dyn.redirect_chain.length}회`]);
      }
    });

    if (rows.length > 0) {
      techCard.classList.remove("hidden");
      rows.forEach(([k, v]) => {
        const row = document.createElement("div");
        row.className = "kv-row";
        const keyEl = document.createElement("span");
        keyEl.className = "kv-key";
        keyEl.textContent = k;
        const valEl = document.createElement("span");
        valEl.className = "kv-val";
        valEl.textContent = String(v);
        row.appendChild(keyEl);
        row.appendChild(valEl);
        techContainer.appendChild(row);
      });
    } else {
      techCard.classList.add("hidden");
    }

    // RAG 유사 사례
    const ragCard = document.getElementById("card-rag");
    const ragList = document.getElementById("rag-docs-list");
    ragList.textContent = "";
    const docs = Array.isArray(report.rag_retrieved_docs) ? report.rag_retrieved_docs : [];
    if (docs.length > 0) {
      ragCard.classList.remove("hidden");
      docs.forEach((doc, i) => {
        const item = document.createElement("div");
        item.className = "rag-item";

        const meta = document.createElement("div");
        meta.className = "rag-meta";
        const sim = doc.distance !== undefined ? `유사도 ${Math.max(0, Math.round((1 - doc.distance) * 100))}%` : "";
        meta.textContent = `[참고 사례 ${i + 1}] 출처: ${doc.source || "DB"} ${sim ? `| ${sim}` : ""}`;

        const snippet = document.createElement("div");
        snippet.className = "rag-snippet";
        const txt = String(doc.document || "");
        snippet.textContent = txt.length > 160 ? `${txt.slice(0, 160)}…` : txt;

        item.appendChild(meta);
        item.appendChild(snippet);
        ragList.appendChild(item);
      });
    } else {
      ragCard.classList.add("hidden");
    }

    // 메일 요약
    const sumCard = document.getElementById("card-mail-summary");
    const sumEl = document.getElementById("report-mail-summary");
    if (report.mail_summary) {
      sumCard.classList.remove("hidden");
      sumEl.textContent = report.mail_summary;
    } else {
      sumCard.classList.add("hidden");
    }
  }

  // 4. 차단 URL 목록 렌더링
  function renderBlockedUrls(blockedList) {
    const items = Array.isArray(blockedList) ? blockedList : [];
    document.getElementById("blocked-count").textContent = String(items.length);

    const emptyEl = document.getElementById("blocked-empty");
    const listEl = document.getElementById("blocked-list");
    listEl.textContent = "";

    if (items.length === 0) {
      emptyEl.classList.remove("hidden");
      return;
    }

    emptyEl.classList.add("hidden");
    items.forEach((entry) => {
      const card = document.createElement("div");
      card.className = "blocked-item";

      const urlEl = document.createElement("div");
      urlEl.className = "blocked-item-url";
      urlEl.textContent = entry.url;

      const reasonEl = document.createElement("div");
      reasonEl.className = "blocked-item-reason";
      reasonEl.textContent = `점수 ${entry.score}점 — ${entry.reason || "위험 사이트"}`;

      const footer = document.createElement("div");
      footer.className = "blocked-item-footer";

      const timeEl = document.createElement("span");
      timeEl.className = "blocked-item-time";
      timeEl.textContent = entry.blockedAt ? new Date(entry.blockedAt).toLocaleTimeString("ko-KR") : "";

      const unblockBtn = document.createElement("button");
      unblockBtn.className = "btn-unblock";
      unblockBtn.textContent = "차단 해제";
      unblockBtn.addEventListener("click", () => {
        chrome.runtime.sendMessage({ action: "UNBLOCK_URL", url: entry.url });
      });

      footer.appendChild(timeEl);
      footer.appendChild(unblockBtn);
      card.appendChild(urlEl);
      card.appendChild(reasonEl);
      card.appendChild(footer);
      listEl.appendChild(card);
    });
  }

  document.getElementById("clear-blocked-btn").addEventListener("click", () => {
    chrome.runtime.sendMessage({ action: "CLEAR_BLOCKED_URLS" });
  });

  // 5. 초기 로드 + 실시간 스토리지 구독
  chrome.storage.local.get(["latestReport", "blockedUrls"], (res) => {
    renderReport(res.latestReport || null);
    renderBlockedUrls(res.blockedUrls || []);
  });

  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== "local") return;
    if (changes.latestReport) {
      renderReport(changes.latestReport.newValue || null);
    }
    if (changes.blockedUrls) {
      renderBlockedUrls(changes.blockedUrls.newValue || []);
    }
  });
});
