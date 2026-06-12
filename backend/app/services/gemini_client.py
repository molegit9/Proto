import google.generativeai as genai
import json
from app.core.config import settings

genai.configure(api_key=settings.GEMINI_API_KEY)

async def analyze_with_gemini(text: str, sender: str, subject: str, link_findings: dict) -> dict:
    """Gemini를 이용해 피싱 여부 판정 및 JSON 스키마 기반 응답 생성"""
    if not settings.GEMINI_API_KEY or settings.GEMINI_API_KEY == "YOUR_GEMINI_API_KEY":
        return fallback_response("GEMINI_API_KEY가 설정되지 않았습니다.")

    model = genai.GenerativeModel('gemini-3.1-flash-lite')
    
    prompt = f"""
    당신은 피싱 이메일 전문 보안 분석가입니다. 아래 메일 정보를 분석하고 반드시 지정된 JSON 형식으로만 응답하세요.
    
    [입력 데이터]
    - 발신자: {sender}
    - 제목: {subject}
    - 본문 텍스트: {text}
    - 링크 검사 결과: {link_findings}
    
    [응답 JSON 스키마 형식]
    {{
      "is_phishing": boolean,
      "risk_level": "SAFE" | "LOW" | "MEDIUM" | "HIGH",
      "summary": "간단한 1~2줄 요약",
      "social_engineering_elements": ["긴급성", "계정 탈취", "도메인 불일치 등 (없으면 빈 배열)"],
      "actions": ["링크 클릭 금지", "발신자 확인 등 사용자 권장 조치 (없으면 빈 배열)"],
      "reason": "판정 근거에 대한 명확한 설명"
    }}
    """
    
    try:
        response = model.generate_content(prompt)
        cleaned_text = response.text.replace('```json', '').replace('```', '').strip()
        return json.loads(cleaned_text)
    except Exception as e:
        print(f"Gemini API Error: {e}")
        return fallback_response(str(e))

def fallback_response(reason: str):
    return {
        "is_phishing": False,
        "risk_level": "LOW",
        "summary": "AI 분석 결과를 파싱하는데 실패했거나 API 키가 없습니다.",
        "social_engineering_elements": [],
        "actions": [],
        "reason": f"분석 보류: {reason}"
    }

async def summarize_email(visible_text: str) -> str:
    """메일 본문을 3~5줄 bullet point로 요약"""
    if not settings.GEMINI_API_KEY or settings.GEMINI_API_KEY == "YOUR_GEMINI_API_KEY":
        return ""

    model = genai.GenerativeModel('gemini-3.1-flash-lite')
    
    prompt = f"""시스템 지시사항:
당신은 이메일 내용을 있는 그대로 요약하는 도구입니다.
규칙:
1. 메일에 실제로 적혀 있는 내용만 요약한다.
2. 당신의 판단, 의견, 경고, 보안 권장사항은 절대 포함하지 않는다.
3. "~하시기 바랍니다", "~주의하세요" 같은 조언성 문장은 쓰지 않는다.
4. 메일에 링크가 포함된 경우, 링크의 도메인이나 목적지 URL을 bullet에 명시한다.
5. 한국어로 작성한다.

사용자 요청:
아래 메일 본문을 3~5줄 bullet point로 요약해줘.
메일에 있는 링크, 첨부파일, 버튼 텍스트 등 구체적인 내용을 포함해.
각 줄은 '•'로 시작해.

[메일 본문]
{visible_text}"""
    
    try:
        response = model.generate_content(prompt)
        return response.text.strip()
    except Exception as e:
        print(f"Gemini Summarize Error: {e}")
        return ""
