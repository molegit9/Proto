# CHANGELOG (변경 이력)

이 프로젝트의 기능 추가 및 시스템 변경 이력을 기록하는 문서입니다.

---

## 📅 [2026-06-12] 0612 추가사항 - Gemini GA 모델 업데이트, 익스텐션 원격 IP 동적 설정 & 배치 파일 최적화 & 로컬 서버 다운로드 가이드 탑재

### 1. 크롬 익스텐션 (Chrome Extension)
*   **설정 페이지 내 로컬 서버 다운로드 및 실행 가이드 추가**
    *   `extension/options/options.html`과 `options.css`를 업데이트하여, 사용자가 익스텐션을 사용할 때 로컬에서도 손쉽게 구동할 수 있도록 원격 깃허브 저장소의 ZIP 파일 다운로드 링크 및 3단계 구동 가이드를 고품격 UI로 추가.
*   **원격 서버 IP 동적 설정 입력창 추가**
    *   `extension/options/options.html`, `options.js` 설정을 수정하여 원격 서버 IP를 코드 수정 없이 옵션 UI에서 직접 입력해 동적으로 변경할 수 있도록 원격 IP 입력 폼 구현.
    *   `extension/content/api.js`의 `getBaseURL()` 함수가 브라우저에 저장된 동적 IP 설정을 실시간 참조하여 연결할 수 있도록 수정.
*   **Storage API 교체로 동기화 안정성 강화**
    *   비동기 딜레이 및 동기화 권한 제약이 있을 수 있는 `chrome.storage.sync` 대신, 브라우저 로컬 즉시 동기화가 보장되는 `chrome.storage.local`로 모든 설정값(서버 모드, 원격 IP 등) 관리 API 교체.
    *   수정된 파일: `api.js`, `options.js`, `popup.js`
*   **CORS 및 콘텐츠 스크립트 로드 오류 조치**
    *   `manifest.json` 내 일반 웹페이지 매칭 스크립트 목록에 `content/api.js` 유틸이 누락되어 `getBaseURL()` 호출 시 ReferenceError가 나던 문제 해결.
    *   `backend/app/main.py` 내의 CORS 설정을 업데이트하여 일반 웹사이트 Origin(예: `https?://.*`)에서 백엔드 로컬 API로의 비동기 fetch를 허용하도록 `allow_origin_regex` 정규식 확장 조치.


### 2. FastAPI 백엔드 서버 (FastAPI Backend Server)
*   **Gemini 3.1 Flash Lite GA 모델 업데이트**
    *   Gemini 3.1 Flash Lite 프리뷰 종료 및 정식 출시(GA) 이행에 맞춰 백엔드 내의 모든 모델명 지정을 `gemini-3.1-flash-lite-preview`에서 `gemini-3.1-flash-lite`로 마이그레이션.
    *   수정된 파일: `gemini_client.py`, `gemini_service.py`, `routes.py`
*   **서버 실행 배치 파일 (start_server.bat) 오류 수정 및 구조 평탄화**
    *   배치 파일 내 한글 주석과 소괄호 중첩으로 인해 Windows `cmd.exe` 기본 인코딩(CP949) 파서가 오동작하여 문법 에러 및 창이 강제 종료되던 현상 조치. 모든 주석을 영문 ASCII(`REM`)로 교체하고 조건절 내의 불필요한 괄호를 완전히 제거하여 구문 평탄화.
    *   윈도우 환경에서 Uvicorn 다중 프로세스 가동 시 포트/소켓 충돌을 일으키는 `WinError 10022`를 방지하기 위해 `--workers 2` 옵션을 빼고 1개의 단일 워커로 안전 구동되도록 변경.
    *   기본 Python 터미널의 출력 버퍼링으로 로그가 먹통이 되는 현상을 없애기 위해 Python 구동 명령어에 `-u` (unbuffered) 옵션을 추가하고, 서버 출력을 `server.log`로 리다이렉트하여 숨기던 구문을 지워 실시간으로 터미널 창에 로그가 찍히도록 개선.
*   **서버 IP 자동 감지 기능 탑재**
    *   `start_server.bat` 파일 실행 시, 현재 서버 컴퓨터에 활성화된 IPv4 주소들을 자동으로 감지하여 콘솔 시작 시 큰 박스 안에 출력해 줌으로써 원격 시연 시 IP 확인 및 입력을 고도로 단순화.
*   **이모지 출력 에러 해결**
    *   Windows 터미널 또는 리다이렉트 출력 시 특정 인코딩 로케일로 인해 `UnicodeEncodeError`를 일으키던 RAG 서비스 소스코드([rag_service.py](file:///c:/Dev/Proto/backend/app/services/rag_service.py)) 상의 `🚀` 이모지 문자를 로그 및 프린트 문에서 제거.

---

## 📅 [2026-06-10] 0610 추가사항 - 서버 모드 설정 토글 & Windows 배포 구성

### 1. 크롬 익스텐션 (Chrome Extension)
*   **서버 모드 옵션 설정 페이지 추가**
    *   `extension/options/options.html`, `options.css`, `options.js` 파일을 신규 작성하여 익스텐션 설정(옵션) 페이지 구현.
    *   "로컬 서버 사용" / "원격 서버 사용" 스위치 토글을 제공하며 설정값은 `chrome.storage.sync`에 영구 저장되도록 연동.
*   **API 엔드포인트 중앙화 (공통 유틸리티)**
    *   `extension/content/api.js` 파일을 수정하여 동적으로 `baseURL`을 반환하는 공통 유틸 함수 `getBaseURL()` 구현.
    *   `REMOTE_SERVER_IP` 상수를 상단에 격리하여, 실제 고정 IP 배포 시 이 상수값만 변경하면 모든 호출부가 일괄 적용되도록 수정.
*   **동적 API 호출 연동**
    *   `background.js` (서비스 워커)에서 `importScripts('/content/api.js')`를 호출하여 공통 유틸을 로드하고, `getBaseURL()`을 사용하여 API 요청을 전송하도록 수정.
    *   `content/url_ui.js` (컨텐츠 스크립트)의 하이퍼링크 호버 분석 및 드래그 텍스트 분석 API 주소를 하드코딩 대신 `getBaseURL()`로 동적 래핑.
*   **팝업 상단 서버 모드 뱃지 표시**
    *   `popup.html`, `popup.css`, `popup.js`를 수정하여 팝업창 상단 우측에 현재 설정 모드 상태를 나타내는 직관적인 보안 뱃지(로컬: 회색 `LOCAL`, 원격: 초록 `SERVER`) 추가.
*   **매니페스트 설정 등록**
    *   `manifest.json`에 `"options_ui"`(설정 탭)을 정식 등록하고, 원격 서버 연결 지원을 위해 `host_permissions` 권한 추가.

### 2. FastAPI 백엔드 서버 (FastAPI Backend Server)
*   **Windows 실행 배치 파일 구현**
    *   `backend/start_server.bat` 스크립트를 작성하여 윈도우 환경에서 더블클릭만으로 서버를 즉시 시작할 수 있도록 환경 구축.
    *   배치 파일 실행 시 내부적으로 `venv\Scripts\activate.bat`가 존재하는지 체크하여 가상환경을 우선 자동 활성화하고, 없을 경우 시스템 Python 환경으로 구동하는 자가 검사(Fallback) 로직 추가.
    *   `.env` 파일을 줄별로 파싱하여 CMD 세션 환경 변수로 주석(#) 필터링 처리 후 로딩.
    *   서버 콘솔 출력을 텍스트 파일인 `server.log`로 리다이렉트 및 저장하도록 구현.
*   **Windows 백그라운드 서비스 및 스케줄러 배포 가이드 추가**
    *   `backend/README_DEPLOY_WINDOWS.md` 파일을 신규 생성.
    *   **NSSM(Non-Sucking Service Manager)**을 사용한 Windows 서비스 등록 절차 및 **작업 스케줄러(Task Scheduler)**를 사용한 부팅 시 백업 실행 방법을 명령어 단계별로 상세히 기술.
*   **CORS 보안 설정 최적화 및 연동 지원**
    *   `backend/app/main.py` 내의 CORS 설정을 변경하여 `allow_origins=["*"]` 대신 `allow_origin_regex=r"chrome-extension://.*"` 정규식 매칭을 추가.
    *   브라우저의 `credentials: true` 적용 시 Wildcard(`*`) 차단 충돌 문제를 해결하고 모든 크롬 익스텐션 ID origin을 안전하게 허용하도록 보안 조치.
*   **의존성 패키지 정리**
    *   `requirements.txt`에 실제로 파이썬 임포트 트레이싱 기준으로 쓰이는 패키지만 남겨 정리.
    *   미사용 패키지(`aiosqlite`, `google-auth` 등)를 제외하고 실제 사용 중인 `google-generativeai` 및 `tldextract` 명시.
