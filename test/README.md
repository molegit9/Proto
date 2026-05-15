# SecurityGuard 시연용 테스트 페이지

로컬에서 열어서 익스텐션 시연에 사용하세요.
(서버 불필요 — 파일을 Chrome에서 직접 열기 가능)

---

## 시나리오별 설명

### 🟢 1_normal_portal.html — 정상 사이트
- NAVERR 포털 사이트 (정상 도메인 패턴)
- 링크 호버 → SAFE 판정 예상
- **시연 포인트**: 정상 동작 기준선 확인

---

### 🔴 2_url_typosquatting.html — URL 타이포스쿼팅 탐지
- `naver-account-secure.xyz` 도메인 시뮬레이션
- 내부 링크들이 악성 도메인 패턴 포함
- **탐지 경로**: Levenshtein 거리 계산 → 로컬 즉시 탐지
- **시연 포인트**: VT 조회 전에 로컬에서 먼저 잡힘 → "VT 없이도 탐지 가능" 어필

---

### 🟣 3_social_engineering_text.html — 소셜엔지니어링 텍스트 드래그
- 카카오뱅크 사칭 긴급 공지 + 국세청 사칭 문자
- **탐지 경로**: 텍스트 드래그 → Gemini 분석
- **시연 포인트**: VT는 URL만 검사, 텍스트는 못 잡음 → Gemini가 단독으로 탐지
- 드래그 테스트 3종:
  1. 긴급성 + 계정 정지 협박
  2. 당첨 사기 + 개인정보 요구
  3. 국세청 사칭 + 악성 URL

---

### 🟠 4_dynamic_analysis_target.html — 동적 분석 탐지 대상
- 쿠팡 사칭 쇼핑몰 (`coopang-deals.xyz`)
- 겉보기엔 정상처럼 보이지만 숨겨진 요소 포함:
  - `display:none` hidden form (쿠키 수집용)
  - tracking pixel (외부 도메인)
  - 난독화 JS 패턴
  - 모든 버튼 → `coopang-deals.xyz`로 리디렉션
- **탐지 경로**:
  - 1단계(정적): 도메인 패턴 탐지
  - 2단계(동적/정밀검사): 숨겨진 form, tracking pixel 탐지
- **시연 포인트**: "정밀검사 ON/OFF 차이" 비교 시연에 최적

---

## 추천 시연 순서

```
1. 1_normal_portal.html 링크 호버 → ✅ SAFE (기준선)
2. 2_url_typosquatting.html 링크 호버 → 🔴 로컬 Levenshtein 즉시 탐지
3. 3_social_engineering_text.html 텍스트 드래그 → 🔴 Gemini 탐지 (VT 없이)
4. 4_dynamic_analysis_target.html
   - 정밀검사 OFF → ⚠️ 도메인만 탐지
   - 정밀검사 ON  → 🔴 숨겨진 요소까지 추가 탐지
```

## 핵심 메시지

| 시나리오 | VT | Gemini | 로컬 | 동적 |
|---------|-----|--------|------|------|
| 정상    | SAFE | SAFE | - | - |
| 타이포스쿼팅 | ❓미탐지 가능 | DANGER | **즉시탐지** | - |
| 소셜엔지니어링 | ❌불가 | **DANGER** | - | - |
| 동적 숨김 요소 | ❓미탐지 | DANGER | - | **추가탐지** |
