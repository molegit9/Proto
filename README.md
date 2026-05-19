# 🛡️ Phishing Security Assistant (통합 보안 어시스턴트)

> **LLM + RAG 기반 올인원 피싱 탐지 Chrome Extension**  
> 일반 웹페이지 URL/텍스트 분석부터 Gmail 이메일 심층 분석까지 하나의 통합 시스템으로 처리합니다.

과거 분리되어 있던 `MailReader`(Gmail 심층 분석)와 `Zp`(제로샷 실시간 웹 검사기)를 단일 FastAPI 백엔드 + Chrome Extension으로 통합한 프로젝트입니다.

---
https://youtu.be/SfNGCjKW3M0

https://youtu.be/S8i36zZRL7k 

## 🌟 주요 기능 (Key Features)

### 1. 일반 웹페이지 실시간 보안 (Zero-shot Detector)

| 기능 | 설명 |
|------|------|
| **URL 호버 검사** | 링크에 0.5초 이상 마우스를 올리면 즉시 작동 — 타이포스쿼팅 탐지, VirusTotal 악성 여부, RDAP 도메인 생성일을 병렬 조회 후 LLM이 최종 안전도(0~100점)를 툴팁으로 표시 |
| **텍스트 드래그 검사** | 의심 문구를 드래그하면 ChromaDB 벡터 DB에서 유사 피싱 판례를 검색(RAG)하고 Gemini가 사회공학적 사기 여부를 판정 |
| **2-Tier 정밀 분석** | ① 정적 HTML 검사 → ② Playwright 브라우저로 투명 폼(Hidden Form), 리다이렉션 등 동적 악성 행위 렌더링 추적 |

### 2. Gmail 심층 분석 (Deep Email Analysis)

- **안전한 DOM 정제** — 숨김 텍스트·악성 스크립트를 제거하여 LLM 교란 방지
- **RAG 판례 검색** — ChromaDB에 적재된 피싱/스팸 데이터셋을 벡터 검색, LLM 프롬프트에 컨텍스트로 주입
- **2단계 링크 검사** (Tier 1 VirusTotal+정적 / Tier 2 Playwright 동적)
- **비침해적 UI 배너** — 위험 수준(안전/주의/위험)에 따른 시각적 배너 + 메일 요약 렌더링

### 3. RAG Done Criteria (시연용 검증 지표)

> **"그냥 LLM만 돌린 건지, RAG를 거친 건지"를 결과 화면에서 바로 확인할 수 있습니다.**

Gmail 분석 결과 배너에 다음 정보가 표시됩니다:

| 상태 | 뱃지 | 의미 |
|------|------|------|
| RAG 사용됨 | 🧠 **RAG: N개 판례 참조됨** (파란 뱃지) | Vector DB에서 유사 판례를 검색해 LLM 프롬프트에 주입 |
| RAG 미사용 | 🤖 **LLM 단독 판정** (회색 뱃지) | Vector DB 미연결 또는 유사 판례 없음 |

**`🔍 RAG 참조 판례`** 섹션을 펼치면 각 판례의 라벨(피싱/정상), 출처, 유사도(%)와 실제 텍스트 스니펫이 표시됩니다.

API 응답 JSON에도 포함됩니다:
```json
{
  "rag_used": true,
  "rag_doc_count": 3,
  "rag_retrieved_docs": [
    { "document": "...", "label": "2", "source": "phishing_dataset", "distance": 0.0821 }
  ]
}
```

### 4. 통합 로그 대시보드 (Popup) & 전문가용 Raw DB

- **일반 대시보드:** 이메일/URL/텍스트 분석 이력(최근 20건)을 한눈에 조회 가능합니다.
- **전문가용 원본 DB (`raw_data`):** 동적 분석(Playwright DOM 이벤트, 히든 폼 탐지) 및 정적 검사 결과의 원본 JSON 페이로드가 백엔드 SQLite DB에 영구 저장됩니다. (VS Code SQLite Viewer 등으로 분석 가능)
- **DB 안전 초기화:** 확장 프로그램 팝업에서 DB 캐시를 비우더라도, 일반 로그(SQLite)만 삭제되며 **RAG 판례 학습 데이터(ChromaDB)는 절대 초기화되지 않고 안전하게 보존**됩니다.

---

## 🏗 아키텍처 (Architecture)

```text
c:\Dev\Plus\
├── extension/                     # Chrome Extension (프론트엔드)
│   ├── manifest.json              # 통합 권한 및 OAuth 설정
│   ├── background/                # OAuth 토큰 발급 및 백엔드 통신 중계
│   └── content/
│       ├── content.js             # 진입점
│       ├── gmail_ui.js            # Gmail MutationObserver & 메시지 ID 추출
│       ├── gmail_banner.js        # 분석 결과 배너 렌더링 (RAG 뱃지 포함)
│       ├── url_ui.js              # URL 호버 / 텍스트 드래그 UI
│       └── banner.css             # 배너 스타일
│
└── backend/                       # FastAPI 백엔드
    ├── requirements.txt
    ├── .env.example               # 환경변수 템플릿 (API 키 미포함)
    └── app/
        ├── main.py                # 서버 진입점 & DB/벡터DB 초기화 (Lifespan)
        ├── api/routes.py          # 모든 API 엔드포인트
        ├── core/config.py         # Pydantic Settings (환경변수 관리)
        └── services/
            ├── analyzer.py        # 이메일 분석 파이프라인 오케스트레이션
            ├── rag_service.py     # ChromaDB 벡터 검색 (query_rag_with_meta)
            ├── gemini_service.py  # Gemini LLM 호출 (모델 Fallback 포함)
            ├── virustotal_service.py
            ├── link_sandbox.py    # 정적 URL 분석
            ├── browser_analyzer.py # Playwright 동적 분석 (투명 폼, 리다이렉션 추적)
            └── database.py        # SQLite 로깅 (raw_data 원본 로그, rag_doc_count 포함)
├── test/                          # 로컬 검증용 피싱 시뮬레이터 HTML (정상, 타이포스쿼팅, 동적 우회, 사회공학)
```

---

## 🚀 설치 및 실행 (Quick Start)

### 사전 요구사항

- Python **3.10** 이상
- Google Chrome 브라우저
- Gemini API 키 ([Google AI Studio](https://aistudio.google.com/))
- VirusTotal API 키 ([VirusTotal](https://www.virustotal.com/))

---

### Step 1. 백엔드 실행

```bash
# 1. 백엔드 폴더 이동
cd backend

# 2. 의존성 설치
pip install -r requirements.txt

# 3. 환경변수 파일 생성 (.env.example 복사 후 값 채우기)
copy .env.example .env
```

`.env` 파일 내용:
```env
GEMINI_API_KEY=여기에_Gemini_API_키_입력
VIRUSTOTAL_API_KEY=여기에_VirusTotal_API_키_입력
DATABASE_URL=sqlite:///./security_logs.db
RAG_DATASET_PATH=./data/merged_security_dataset.csv
CHROMA_DB_PATH=./chroma_db
```

```bash
# 4. 서버 실행
uvicorn app.main:app --reload
# → http://localhost:8000 에서 대기
```

> **RAG 활성화 조건**: `RAG_DATASET_PATH`에 지정된 CSV 파일(`content`, `label`, `source` 컬럼 필요)이 존재해야 Vector DB가 초기화됩니다. 없으면 LLM 단독 모드로 동작합니다.

---

### Step 2. Chrome Extension 설치

> **참고:** 확장 프로그램 ID 불일치 문제를 해결하기 위해 `manifest.json` 내부에 RSA 공개키(`key`)가 하드코딩되어 있습니다. 따라서 팀원 간 로컬 환경이 달라도 동일한 Extension ID가 보장됩니다.

1. `chrome://extensions/` 접속
2. **개발자 모드** 켜기
3. **'압축해제된 확장 프로그램 로드'** → `extension/` 폴더 선택
4. 생성된 확장 프로그램 **ID(32자리)** 복사

---

### Step 3. Google OAuth 설정 (Gmail 분석용)

1. [Google Cloud Console](https://console.cloud.google.com/) → 새 프로젝트 생성
2. **Gmail API** 사용 설정
3. **OAuth 동의 화면** → 범위: `https://www.googleapis.com/auth/gmail.readonly` 추가 + 본인 계정 등록
4. **사용자 인증 정보 → OAuth 클라이언트 ID** 생성 (유형: Chrome 앱, 확장 프로그램 ID 입력)
5. 생성된 **클라이언트 ID** → `extension/manifest.json`의 `"oauth2" > "client_id"` 에 붙여넣기
6. 확장 프로그램 페이지에서 **새로고침(↻)**

---

## 🧪 동작 확인 (Testing)

| 시나리오 | 확인 방법 |
|----------|-----------|
| **서버 헬스 체크** | `http://localhost:8000/health` 접속 → `{"status":"ok"}` |
| **Gmail 분석** | Gmail에서 임의의 메일 오픈 → 상단 배너에 판정 결과 + 🧠/🤖 RAG 뱃지 확인 |
| **URL 호버** | 임의의 웹페이지에서 링크 위에 0.5초 이상 마우스 올리기 → 툴팁 보안 경고 |
| **텍스트 드래그** | 의심 문구(10자 이상) 드래그 → RAG 판례 기반 위험도 팝업 |
| **로그 대시보드** | 확장 아이콘 클릭 → **[기록]** 탭에서 최근 분석 이력 확인 |

---

## 📋 API 엔드포인트

| Method | Path | 설명 |
|--------|------|------|
| `POST` | `/api/analyze-email` | Gmail 이메일 전체 분석 (RAG 메타데이터 포함 응답) |
| `POST` | `/api/v1/analyze` | URL 호버 분석 (NDJSON 스트리밍) |
| `POST` | `/api/v1/analyze/text` | 드래그 텍스트 RAG 분석 (NDJSON 스트리밍) |
| `GET`  | `/api/logs` | 최근 분석 로그 조회 |
| `POST` | `/api/clear-db` | 분석 로그 DB 초기화 |
| `GET`  | `/health` | 서버 상태 확인 |

---

## 🔐 보안 주의사항

- **`.env` 파일은 절대 공개 저장소에 업로드하지 마세요.** `.gitignore`에 이미 포함되어 있습니다.
- API 키는 반드시 환경변수(`.env`)를 통해 주입하세요.
- ChromaDB 벡터 DB(`chroma_db/`)와 학습 데이터셋(`.csv`)도 용량 및 라이선스 이유로 Git에서 제외됩니다.
