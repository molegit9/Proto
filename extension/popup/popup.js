document.addEventListener('DOMContentLoaded', () => {
    // 0. Update Server Mode Badge
    const serverBadge = document.getElementById('server-badge');
    if (serverBadge && typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
        chrome.storage.local.get(['useLocalServer'], function(result) {
            const useLocal = result.useLocalServer !== false;
            if (useLocal) {
                serverBadge.innerText = 'LOCAL';
                serverBadge.className = 'server-badge local';
            } else {
                serverBadge.innerText = 'SERVER';
                serverBadge.className = 'server-badge server';
            }
        });
    }

    // 1. Tab Switching
    const tabs = document.querySelectorAll('.tab-btn');
    const contents = document.querySelectorAll('.tab-content');

    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            tabs.forEach(t => t.classList.remove('active'));
            contents.forEach(c => c.classList.remove('active'));

            tab.classList.add('active');
            const targetId = tab.getAttribute('data-target');
            document.getElementById(targetId).classList.add('active');

            if (targetId === 'tab-history') {
                loadLogs();
            }
        });
    });

    // 2. Settings (Toggle)
    const toggle = document.getElementById('progressToggle');
    const deepScanToggle = document.getElementById('deepScanToggle');
    
    if (typeof chrome !== 'undefined' && chrome.storage) {
        chrome.storage.local.get(['showProgress', 'enableDeepScan'], function(result) {
            if (result.showProgress !== undefined) {
                toggle.checked = result.showProgress;
            } else {
                toggle.checked = true; // default
            }
            
            if (result.enableDeepScan !== undefined) {
                deepScanToggle.checked = result.enableDeepScan;
            } else {
                deepScanToggle.checked = false; // default
            }
        });
        
        toggle.addEventListener('change', (e) => {
            chrome.storage.local.set({ showProgress: e.target.checked });
        });
        
        deepScanToggle.addEventListener('change', (e) => {
            chrome.storage.local.set({ enableDeepScan: e.target.checked });
        });
    }

    // 3. Settings (Clear DB) - Service Worker 경유
    document.getElementById('clearBtn').addEventListener('click', async () => {
        const btn = document.getElementById('clearBtn');
        const msg = document.getElementById('statusMsg');
        
        btn.disabled = true;
        btn.innerText = "서버 통신 중...";
        
        chrome.runtime.sendMessage({ action: "CLEAR_DB" }, (response) => {
            if (!chrome.runtime.lastError && response && response.success) {
                btn.style.display = 'none';
                msg.style.display = 'block';
                setTimeout(() => { window.close(); }, 1500); 
            } else {
                alert('백엔드 서버에 연결할 수 없거나 에러가 발생했습니다. 서버 동작 여부를 확인하세요.');
                btn.disabled = false;
                btn.innerText = "데이터베이스(DB) 초기화";
            }
        });
    });

    // 4. Load Logs - Service Worker 경유
    async function loadLogs() {
        const container = document.getElementById('logs-container');
        container.textContent = '';
        const loadingEl = document.createElement('div');
        loadingEl.id = 'logs-loading';
        loadingEl.textContent = '기록을 불러오는 중...';
        container.appendChild(loadingEl);
        
        chrome.runtime.sendMessage({ action: "GET_LOGS", limit: 20 }, (response) => {
            if (chrome.runtime.lastError || !response || !response.success) {
                console.error('Failed to load logs:', chrome.runtime.lastError || (response && response.error));
                container.textContent = '';
                const errEl = document.createElement('div');
                errEl.id = 'logs-error';
                errEl.textContent = '서버와 통신할 수 없습니다.';
                container.appendChild(errEl);
                return;
            }

            const logs = response.data && response.data.logs;
            container.textContent = '';
            
            if (!logs || logs.length === 0) {
                const emptyEl = document.createElement('div');
                emptyEl.id = 'logs-loading';
                emptyEl.textContent = '최근 분석 기록이 없습니다.';
                container.appendChild(emptyEl);
                return;
            }

            logs.forEach(log => {
                const isEmail = log.type === 'email';
                const icon = isEmail ? '📧' : '🔗';
                const title = isEmail ? (log.subject || '제목 없음') : (log.content || 'URL 없음');
                
                let badgeClass = 'badge-warning';
                let badgeText = '주의';
                
                if (isEmail) {
                    if (log.is_phishing || log.risk_level === 'HIGH') {
                        badgeClass = 'badge-danger';
                        badgeText = '위험';
                    } else if (log.risk_level === 'LOW' || log.risk_level === 'SAFE') {
                        badgeClass = 'badge-safe';
                        badgeText = '안전';
                    } else {
                        badgeClass = 'badge-warning';
                        badgeText = '주의';
                    }
                } else {
                    const statusStr = String(log.status || '').toUpperCase();
                    if (statusStr.includes('DANGER') || statusStr === '10' || statusStr === '20') {
                        badgeClass = 'badge-danger';
                        badgeText = '위험';
                    } else if (statusStr.includes('SAFE') || statusStr === '100' || statusStr === '90') {
                        badgeClass = 'badge-safe';
                        badgeText = '안전';
                    } else {
                        badgeClass = 'badge-warning';
                        badgeText = '주의';
                    }
                }

                let timeStr = '시간 정보 없음';
                if (log.timestamp) {
                    try {
                        const dateObj = new Date(log.timestamp.replace(' ', 'T') + 'Z');
                        timeStr = dateObj.toLocaleString('ko-KR');
                    } catch(e) {}
                }
                
                const item = document.createElement('div');
                item.className = 'log-item';

                const header = document.createElement('div');
                header.className = 'log-header';

                const titleWrap = document.createElement('div');
                titleWrap.className = 'log-title';
                titleWrap.appendChild(document.createTextNode(`${icon} `));

                const titleSpan = document.createElement('span');
                titleSpan.style.cssText = 'white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 200px;';
                titleSpan.title = title;
                titleSpan.textContent = title;
                titleWrap.appendChild(titleSpan);

                const badge = document.createElement('div');
                badge.className = `log-badge ${badgeClass}`;
                badge.textContent = badgeText;

                header.appendChild(titleWrap);
                header.appendChild(badge);

                const reasonEl = document.createElement('div');
                reasonEl.className = 'log-reason';
                reasonEl.textContent = (log.reason || '분석 요약 없음').replace(/<[^>]*>/g, ' ');

                const timeEl = document.createElement('div');
                timeEl.className = 'log-time';
                timeEl.textContent = timeStr;

                item.appendChild(header);
                item.appendChild(reasonEl);
                item.appendChild(timeEl);
                container.appendChild(item);
            });
        });
    }
});
