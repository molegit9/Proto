from google import genai
import json
from datetime import datetime
from app.core.config import settings

def fallback_response(reason: str):
    return {
        "is_phishing": False,
        "risk_level": "LOW",
        "summary": "AI 분석 결과를 파싱하는데 실패했거나 API 키가 없습니다.",
        "social_engineering_elements": [],
        "actions": [],
        "reason": f"분석 보류: {reason}"
    }

async def analyze_with_gemini(text: str, sender: str, subject: str, link_findings: dict, rag_context: str = None) -> dict:
    """Gemini를 이용해 피싱 여부 판정 및 JSON 스키마 기반 응답 생성"""
    if not settings.GEMINI_API_KEY or settings.GEMINI_API_KEY == "YOUR_GEMINI_API_KEY":
        return fallback_response("GEMINI_API_KEY가 설정되지 않았습니다.")

    try:
        client = genai.Client(api_key=settings.GEMINI_API_KEY)
    except Exception as e:
        print(f"Gemini Client Init Error: {e}")
        return fallback_response("내부 시스템 설정 문제로 현재 평가를 수행할 수 없습니다.")

    rag_section = f"\n[유사 위협 사례]\n{rag_context}\n" if rag_context else ""

    prompt = f"""
    당신은 피싱 이메일 전문 보안 분석가입니다. 아래 메일 정보를 분석하고 반드시 지정된 JSON 형식으로만 응답하세요.
    
    [입력 데이터]
    - 발신자: {sender}
    - 제목: {subject}
    - 본문 텍스트: {text}
    - 링크 검사 결과: {link_findings}{rag_section}
    
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
        response = await client.aio.models.generate_content(
            model='gemini-3.1-flash-lite',
            contents=prompt
        )
        cleaned_text = response.text.replace('```json', '').replace('```', '').strip()
        return json.loads(cleaned_text)
    except Exception as e:
        error_msg = str(e)
        if "429" in error_msg or "RESOURCE_EXHAUSTED" in error_msg:
            print(f"Gemini API Quota Exceeded (gemini-3.1-flash-lite): {e}\nFallback 동작: gemma-3-27b 모델로 재시도합니다.")
            try:
                fallback_response_obj = await client.aio.models.generate_content(
                    model='gemma-3-27b',
                    contents=prompt
                )
                cleaned_text = fallback_response_obj.text.replace('```json', '').replace('```', '').strip()
                return json.loads(cleaned_text)
            except Exception as fallback_e:
                print(f"Fallback gemma-3-27b Error: {fallback_e}")
                return fallback_response("현재 연속된 분석 요청으로 인해 메인 AI와 보조 AI의 무료 검사 횟수를 모두 초과했습니다. 약 1분 뒤 다시 시도해 주세요.")
        
        print(f"Gemini API Error: {e}")
        return fallback_response(str(e))

async def summarize_email(visible_text: str) -> str:
    """메일 본문을 3~5줄 bullet point로 요약"""
    if not settings.GEMINI_API_KEY or settings.GEMINI_API_KEY == "YOUR_GEMINI_API_KEY":
        return ""

    try:
        client = genai.Client(api_key=settings.GEMINI_API_KEY)
    except Exception as e:
        print(f"Gemini Client Init Error: {e}")
        return ""

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
        response = await client.aio.models.generate_content(
            model='gemini-3.1-flash-lite',
            contents=prompt
        )
        return response.text.strip()
    except Exception as e:
        error_msg = str(e)
        if "429" in error_msg or "RESOURCE_EXHAUSTED" in error_msg:
            print(f"Gemini API Quota Exceeded (gemini-3.1-flash-lite): {e}\nFallback 동작: gemma-3-27b 모델로 재시도합니다.")
            try:
                fallback_response_obj = await client.aio.models.generate_content(
                    model='gemma-3-27b',
                    contents=prompt
                )
                return fallback_response_obj.text.strip()
            except Exception as fallback_e:
                print(f"Fallback gemma-3-27b Error: {fallback_e}")
                return ""
        
        print(f"Gemini Summarize Error: {e}")
        return ""

async def analyze_content(action_type: str, content: str) -> dict:
    try:
        client = genai.Client(api_key=settings.GEMINI_API_KEY)
    except Exception as e:
        print(f"Gemini Client Init Error (e.g., Missing API key): {e}")
        return {
            "status": "WARNING",
            "reason": "내부 시스템 설정 문제로 현재 평가를 수행할 수 없습니다.",
            "is_error": True
        }

    current_time_str = datetime.now().strftime("%Y년 %m월 %d일 %H시 %M분")
    
    prompt = f"""
    당신은 보안 취약계층을 돕는 친절한 전문가입니다. '인증서 만료', 'XSS' 같은 어려운 기술 용어는 절대 쓰지 말고, 중학생도 이해할 수 있는 쉬운 비유와 일상어로 답변하세요.
    
    현재 시스템 날짜와 시간은 {current_time_str} 입니다. 내용에 포함된 날짜가 과거인지 미래인지 판단할 때 반드시 이 현재 시간을 기준으로 절대적으로 계산하세요! (예: 정상적인 메일이나 문자의 과거 날짜를 미래로 착각하여 스팸이라 오해하지 않도록 매우 주의)
    
    사용자가 다음 작업을 수행했습니다.
    작업 유형: {action_type} (hover는 링크에 마우스를 올린 것, drag는 텍스트를 드래그한 것)
    내용: {content}
    
    이 내용이 피싱 사이트나 악성 스크립트, 사기성 정보 등 보안상 위험한지 분석해주세요.
    반드시 다음 형식의 순수한 JSON 으로만 응답해주세요. 시작과 끝에 마크다운 기호를 붙이지 마세요.
    {{
        "status": "SAFE" | "WARNING" | "DANGER",
        "reason": "쉬운 이유 설명"
    }}
    """
    
    try:
        response = await client.aio.models.generate_content(
            model='gemini-3.1-flash-lite',
            contents=prompt,
            config={"response_mime_type": "application/json"}
        )
        
        result = json.loads(response.text)
        
        if result.get("status") not in ["SAFE", "WARNING", "DANGER"]:
            result["status"] = "WARNING"
            result["reason"] = "상태를 명확하게 판단할 수 없습니다. 주의해서 확인해주세요."
            
        return result
    except Exception as e:
        error_msg = str(e)
        if "429" in error_msg or "RESOURCE_EXHAUSTED" in error_msg:
            print(f"Gemini API Quota Exceeded (gemini-3.1-flash-lite): {e}\nFallback 동작: gemma-3-27b 모델로 재시도합니다.")
            
            try:
                fallback_response_obj = await client.aio.models.generate_content(
                    model='gemma-3-27b',
                    contents=prompt,
                    config={"response_mime_type": "application/json"}
                )
                
                result = json.loads(fallback_response_obj.text)
                if result.get("status") not in ["SAFE", "WARNING", "DANGER"]:
                    result["status"] = "WARNING"
                    result["reason"] = "상태를 명확하게 판단할 수 없습니다. 주의해서 확인해주세요."
                    
                return result
            except Exception as fallback_e:
                print(f"Fallback gemma-3-27b Error: {fallback_e}")
                return {
                    "status": "WARNING",
                    "reason": "현재 연속된 분석 요청으로 인해 메인 AI와 보조 AI의 무료 검사 횟수를 모두 초과했습니다. 약 1분 뒤 다시 시도해 주세요.",
                    "is_error": True
                }
            
        print(f"Gemini API Error: {e}")
        return {
            "status": "WARNING",
            "reason": "현재 분석 시스템에 일시적인 오류가 발생했습니다. 접속이나 이용에 주의해 주세요.",
            "is_error": True
        }
