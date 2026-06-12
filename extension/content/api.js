const REMOTE_SERVER_IP = "12.34.56.78"; // <SERVER_IP> - 원격 서버 고정 IP로 대체 가능

async function getBaseURL() {
  return new Promise((resolve) => {
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      chrome.storage.local.get(['useLocalServer', 'remoteServerIp'], (result) => {
        // 기본값: 로컬 서버 사용 (true)
        const useLocal = result.useLocalServer !== false;
        if (useLocal) {
          resolve("http://localhost:8000");
        } else {
          const remoteIp = result.remoteServerIp || REMOTE_SERVER_IP;
          if (remoteIp.startsWith("http://") || remoteIp.startsWith("https://")) {
            resolve(remoteIp);
          } else if (remoteIp.includes(".") && !/^[0-9.]+$/.test(remoteIp)) {
            // 도메인 주소(예: localtunnel, ngrok 등)인 경우 기본적으로 https://를 붙여줌
            resolve(`https://${remoteIp}`);
          } else {
            resolve(`http://${remoteIp}:8000`);
          }
        }
      });
    } else {
      resolve("http://localhost:8000");
    }
  });
}
