document.addEventListener("DOMContentLoaded", () => {
  const params = new URLSearchParams(window.location.search);
  const targetUrl = params.get("url") || "";
  const score = params.get("score") || "10";
  const reason = params.get("reason") || "웹보안관 분석 결과 피싱 또는 악성 위험이 높은 사이트로 감지되었습니다.";

  document.getElementById("blocked-url").textContent = targetUrl || "(알 수 없음)";
  document.getElementById("blocked-score").textContent = `${score}점 / 100점 (위험)`;
  document.getElementById("blocked-reason").textContent = reason;

  document.getElementById("go-back-btn").addEventListener("click", () => {
    if (window.history.length > 1) {
      window.history.back();
    } else {
      window.close();
    }
  });

  const proceedBtn = document.getElementById("proceed-btn");
  if (!targetUrl || !targetUrl.startsWith("http")) {
    proceedBtn.style.display = "none";
    return;
  }

  proceedBtn.addEventListener("click", () => {
    proceedBtn.disabled = true;
    proceedBtn.textContent = "차단 해제 처리 중...";

    chrome.runtime.sendMessage({ action: "UNBLOCK_URL", url: targetUrl }, () => {
      window.location.replace(targetUrl);
    });
  });
});
