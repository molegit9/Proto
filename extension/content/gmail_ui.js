function initGmailAnalysis() {
  let currentUrlHash = "";
  let currentMessageId = null;

  const observer = new MutationObserver(() => {
    const hash = window.location.hash;
    
    // 이메일 열람 화면 해시 패턴인지 확인 (예: #inbox/FMfc... 등 슬래시 포함)
    if (!hash.includes('/')) {
      currentUrlHash = hash;
      currentMessageId = null;
      if (typeof removeBanner === 'function') removeBanner();
      return;
    }
    
    // DOM에서 실제 Gmail API가 사용하는 Hex 형태의 message ID 추출
    const messageElements = document.querySelectorAll('[data-legacy-message-id]');
    if (messageElements.length > 0) {
      // 스레드로 묶인 여러 메시지 중 가장 마지막(최신) 메시지 ID를 사용
      const activeId = messageElements[messageElements.length - 1].getAttribute('data-legacy-message-id');
      
      if (activeId && activeId !== currentMessageId) {
        currentMessageId = activeId;
        currentUrlHash = hash;
        triggerAnalysis(currentMessageId);
      }
    }
  });

  // body를 감시하여 URL hash 변경이나 페이지(DOM) 전환 감지
  observer.observe(document.body, { childList: true, subtree: true });

  async function triggerAnalysis(messageId) {
    if (typeof removeBanner === 'function') removeBanner();
    if (typeof renderLoadingBanner === 'function') renderLoadingBanner();

    chrome.runtime.sendMessage(
      { action: "ANALYZE_EMAIL", messageId },
      (response) => {
        // response가 없는 경우 (통신 끊김 등) 예외 처리
        if (chrome.runtime.lastError || !response) {
          console.error(chrome.runtime.lastError);
          if (typeof renderErrorBanner === 'function') renderErrorBanner("분석 중 통신 오류가 발생했습니다.");
          return;
        }
        if (!response.success) {
          console.error(response.error);
          if (typeof renderErrorBanner === 'function') renderErrorBanner(response.error || "분석 중 서버 오류가 발생했습니다.");
          return;
        }
        if (typeof renderResultBanner === 'function') renderResultBanner(response.data);
      }
    );
  }
}
