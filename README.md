# 웹보안관 (WebSecurityGuard) v2.0

LLM, RAG, 가상 브라우저(Playwright)를 결합한 피싱 탐지 Chrome 확장프로그램입니다.  
일반 웹페이지 링크 호버 검사, 의심 문구 드래그 검사, 위험 사이트 자동 차단, Gmail 메일 분석을 하나의 FastAPI 백엔드와 Chrome Extension(MV3)으로 처리합니다.

> 현재 브랜치(`feat/chrome-modernization`)는 기존 v1.0에서 크롬 최신 정책(LNA/CORS), Side Panel, DNR 자동 차단, Playwright 풀링, 최신 Gemini 모델 및 속도 개선 작업을 반영한 버전입니다.

시연 영상 (v1.0 기준):
- https://youtu.be/SfNGCjKW3M0
- https://youtu.be/S8i36zZRL7k

---

## 주요 기능

### 1. 일반 웹페이지 실시간 검사
- **링크 호버 분석**: 링크 위에 마우스를 0.5초 올리면 타이포스쿼팅(Levenshtein), VirusTotal, RDAP 도메인 생성일을 조회한 뒤 안전도 점수(0~100)를 Shadow DOM 툴팁으로 띄웁니다.
- **텍스트 드래그 분석**: 의심 문구(10~500자)를 드래그하면 ChromaDB의 과거 피싱/스팸 사례(RAG)를 검색해 Gemini가 사기 여부를 판별합니다. 지원하는 크롬에서는 내장 Gemini Nano(`LanguageModel`)로 1차 스크리닝을 먼저 거친 뒤 필요할 때만 서버로 넘깁니다.
- **2-Tier 동적·화면 정밀 분석**: 정밀 분석 모드를 켜거나 퍼블릭 호스팅(`github.io`, `vercel.app` 등) 링크일 경우, 정적 HTML 검사 후 풀링된 Playwright(New Headless)로 숨겨진 폼·리다이렉트를 추적하고 뷰포트 스크린샷을 찍어 Gemini Vision으로 브랜드 사칭 여부까지 확인합니다.
- **위험 링크 자동 차단 (DNR)**: 30점 이하 위험 URL은 `declarativeNetRequest` 세션 규칙에 자동 등록되어, 실수로 클릭하면 경고 페이지(`blocked/blocked.html`)로 이동합니다.

### 2. Gmail 메일 분석
- **DOM Fast Path + 2단계 스트리밍**: 열람 중인 메일의 발신자·제목·본문·링크를 DOM에서 바로 읽어 분석을 시작하며(본문이 없을 때만 Gmail API 사용), `/api/analyze-email/stream`으로 진행 상태와 1차 판정 배너를 먼저 띄운 뒤 의심 링크가 있을 때만 Playwright 결과를 이어서 반영합니다.
- **판정 + 요약 1회 통합 호출**: 보안 판정과 메일 본문 3~4줄 요약을 단일 Gemini Structured Output 호출로 같이 받아 응답 시간을 줄였습니다.
- **받은편지함 호버 프리페치**: 메일 목록에서 행 위에 0.9초 이상 마우스를 올리면 백그라운드로 미리 캐싱해 두고 클릭 시 바로 표시합니다.
- **RAG 참조 판례 표시**: 유사도가 기준치 이내인 과거 피싱 사례를 참고한 경우 배너에 참조 개수와 출처/유사도/스니펫을 함께 보여줍니다.

### 3. Side Panel 상세 대시보드
- 팝업이나 Gmail 배너의 **상세 대시보드** 버튼을 누르면 우측 크롬 사이드 패널이 열립니다.
- 최근 분석 항목의 안전도 게이지, 판정 근거, 권장 조치, RDAP/VT/Playwright 탐지 내역, RAG 참고 사례, 그리고 현재 세션에서 자동 차단된 URL 목록(개별/전체 해제 가능)을 확인할 수 있습니다.

---

## 프로젝트 구조

```text
c:\Dev\Plus\
├── extension/
│   ├── manifest.json             # MV3 권한 (sidePanel, declarativeNetRequest 등) & OAuth 설정
│   ├── background/
│   │   └── background.js         # Service Worker (Port 스트리밍 프록시, DNR 차단, Side Panel 동기화)
│   ├── content/
│   │   ├── content.js            # Gmail / 일반 웹 분기
│   │   ├── api.js                # 로컬/원격 서버 BaseURL 관리
│   │   ├── local_ai.js           # Chrome Built-in AI (LanguageModel / Summarizer) 연동
│   │   ├── url_ui.js             # Shadow DOM 툴팁, 호버/드래그 스트리밍
│   │   ├── gmail_ui.js           # Navigation API 감지, DOM 추출, 스트리밍, 호버 프리페치
│   │   └── gmail_banner.js       # Shadow DOM 배너 렌더링 및 레이아웃 복구
│   ├── sidepanel/                # 사이드 패널 대시보드 (HTML/CSS/JS)
│   ├── blocked/                  # DNR 위험 사이트 차단 경고 페이지 (HTML/JS)
│   ├── popup/                    # 설정 토글 및 최근 분석 기록
│   └── options/                  # 로컬/원격 서버 전환 및 IP 입력
│
├── backend/
│   ├── start_server.bat          # Windows 실행 스크립트 (로컬 / Localtunnel 선택)
│   └── app/
│       ├── main.py               # FastAPI 진입점 (DB/RAG 초기화, Playwright/HTTP 풀 종료)
│       ├── api/routes.py         # API 라우터
│       ├── core/config.py        # 환경변수 설정 (모델명, Playwright 옵션, DB 경로)
│       ├── schemas/email.py      # 이메일 요청/응답 스키마
│       └── services/
│           ├── analyzer.py       # Gmail 2단계 스트리밍 분석 파이프라인
│           ├── browser_analyzer.py # Playwright BrowserPoolManager (New Headless + 스크린샷)
│           ├── gemini_service.py # google-genai 3단 Fallback + Structured Outputs
│           ├── http_client.py    # 공유 httpx.AsyncClient
│           ├── link_sandbox.py   # 신뢰 도메인 스킵, 에스컬레이션 조건, 정적 검사
│           ├── rag_service.py    # ChromaDB 비동기 검색 (asyncio.to_thread)
│           ├── virustotal_service.py
│           ├── gmail_client.py
│           ├── parser.py
│           └── database.py       # SQLite 캐시 및 로그
│
├── test/                         # 시연용 테스트 HTML (0_launcher.html ~ 5_demo_scenario.html)
├── .env.example
├── requirements.txt
└── CHANGELOG.md
```

---

## 설치 및 실행

### 사전 준비
- Python 3.10 이상 (3.12 권장)
- Google Chrome
- Gemini API 키, VirusTotal API 키

### 1. 백엔드 세팅
```powershell
pip install -r requirements.txt
playwright install chromium
copy .env.example backend\.env
```

`backend/.env`에 키와 모델 설정을 입력합니다. (무료 티어 한도 기준 기본값)
```env
GEMINI_API_KEY=여기에_키_입력
VIRUSTOTAL_API_KEY=여기에_키_입력
DATABASE_URL=sqlite:///./security_logs.db
RAG_DATASET_PATH=./data/merged_security_dataset.csv
CHROMA_DB_PATH=./chroma_db

GEMINI_PRIMARY_MODEL=gemini-3.5-flash-lite
GEMINI_SECONDARY_MODEL=gemini-3.1-flash-lite
GEMINI_FALLBACK_MODEL=gemma-4-31b-it
GEMINI_SUMMARY_MODEL=gemma-4-31b-it

PLAYWRIGHT_USE_NEW_HEADLESS=true
PLAYWRIGHT_CAPTURE_SCREENSHOT=true
PLAYWRIGHT_MAX_CONCURRENT_CONTEXTS=3
```

### 2. 서버 실행
- `backend\start_server.bat` 더블클릭
  - 로컬 테스트: Localtunnel 질문에 `n` (또는 Enter) -> `http://localhost:8000`
  - 외부 원격 시연: `y` 입력 -> 백엔드 실행 후 `npx localtunnel --port 8000` 주소 발급
- 터미널 직접 실행 시:
  ```powershell
  cd backend
  uvicorn app.main:app --host 0.0.0.0 --port 8000
  ```

### 3. 크롬 확장프로그램 로드
1. `chrome://extensions/` 열기 -> 우측 상단 **개발자 모드** 켜기
2. **압축해제된 확장 프로그램 로드** -> `extension/` 폴더 선택
3. 원격 서버에 붙일 때는 확장 아이콘 우클릭 -> **옵션**에서 원격 모드로 바꾸고 Localtunnel 주소나 같은 네트워크 IPv4 입력

---

## 테스트 방법
- **서버 확인**: `http://localhost:8000/health` 접속 시 `{"status":"ok", ...}` 확인
- **웹 시연 런처**: `https://molegit9.github.io/Proto/test/0_launcher.html` 접속 (또는 루트에서 `python -m http.server 3000` 실행 후 `http://localhost:3000/test/0_launcher.html`)
- **Gmail 테스트**: `https://mail.google.com`에서 메일 열람 후 상단 배너 및 사이드 패널 확인

---

## API 목록

| Method | Path | 형식 | 설명 |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/analyze-email/stream` | NDJSON | Gmail 2단계 스트리밍 분석 (DOM Fast Path 지원) |
| `POST` | `/api/analyze-email` | JSON | Gmail 단일 응답 분석 (프리페치/하위호환) |
| `POST` | `/api/v1/analyze` | NDJSON | URL 호버 분석 |
| `POST` | `/api/v1/analyze/text` | NDJSON | 드래그 텍스트 RAG 분석 |
| `GET` | `/api/logs` | JSON | 최근 분석 로그 조회 |
| `POST` | `/api/clear-db` | JSON | SQLite 캐시/로그 초기화 (ChromaDB 유지) |
| `GET` | `/health` | JSON | 서버 상태 확인 |

---

## 참고 / 주의사항
- `backend/.env`, `chroma_db/`, 데이터셋 `.csv`는 `.gitignore` 대상입니다.
- 현재 `extension/manifest.json`의 `"key"`는 기존 Google OAuth 클라이언트 ID(`llkiflkpnhnideaiaahogokcmcoffpjp`)와 호환되도록 유지 중입니다. 외부 배포 시에는 새 키쌍을 발급해 공개키만 넣고 OAuth 클라이언트를 다시 등록해야 합니다.
