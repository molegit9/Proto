document.addEventListener('DOMContentLoaded', () => {
    const toggle = document.getElementById('serverModeToggle');
    const statusDesc = document.getElementById('server-status-desc');
    const apiEndpoint = document.getElementById('apiEndpoint');
    const remoteIpInput = document.getElementById('remoteIpInput');

    const defaultIp = (typeof REMOTE_SERVER_IP !== 'undefined') ? REMOTE_SERVER_IP : '12.34.56.78';

    // 설정값 불러오기
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
        chrome.storage.local.get(['useLocalServer', 'remoteServerIp'], (result) => {
            const useLocal = result.useLocalServer !== false;
            const savedIp = result.remoteServerIp || defaultIp;
            
            toggle.checked = !useLocal; // 로컬이면 토글 해제, 원격이면 토글 설정
            remoteIpInput.value = savedIp;
            
            updateUI(!useLocal, savedIp);
        });
    } else {
        remoteIpInput.value = defaultIp;
        updateUI(false, defaultIp);
    }

    // 서버 전환 설정 저장하기
    toggle.addEventListener('change', (e) => {
        const useRemote = e.target.checked;
        const currentIp = remoteIpInput.value.trim() || defaultIp;
        if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
            chrome.storage.local.set({ useLocalServer: !useRemote }, () => {
                updateUI(useRemote, currentIp);
            });
        } else {
            updateUI(useRemote, currentIp);
        }
    });

    // 원격 IP 값 변경 시 실시간 저장 및 UI 업데이트
    remoteIpInput.addEventListener('input', (e) => {
        const currentIp = e.target.value.trim() || defaultIp;
        if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
            chrome.storage.local.set({ remoteServerIp: currentIp }, () => {
                updateUI(toggle.checked, currentIp);
            });
        } else {
            updateUI(toggle.checked, currentIp);
        }
    });

    function updateUI(useRemote, ip) {
        const targetIp = ip || defaultIp;
        if (useRemote) {
            statusDesc.innerText = "원격 API 서버(SERVER)를 사용합니다.";
            apiEndpoint.innerText = `http://${targetIp}:8000`;
        } else {
            statusDesc.innerText = "로컬 개발용 API 서버(localhost)를 사용합니다.";
            apiEndpoint.innerText = "http://localhost:8000";
        }
    }
});
