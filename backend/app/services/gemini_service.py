from google import genai
from google.genai import types
from pydantic import BaseModel, Field
from typing import List, Literal, Optional, Type, TypeVar
import json
from datetime import datetime

from app.core.config import settings

T = TypeVar("T", bound=BaseModel)


# ── Gemini Structured Outputs용 Pydantic 스키마 ──────────────────────────────
class EmailAnalysisSchema(BaseModel):
    is_phishing: bool = Field(description="피싱/사기 메일 여부")
    risk_level: Literal["SAFE", "LOW", "MEDIUM", "HIGH"] = Field(description="위험 등급")
    summary: str = Field(description="간단한 1~2줄 보안 판정 요약")
    mail_summary: str = Field(
        default="",
        description="메일 실제 본문 내용을 판단/조언 없이 있는 그대로 3~4줄 bullet('• '로 시작)으로 객관적 요약 (링크 도메인 포함)",
    )
    social_engineering_elements: List[str] = Field(
        default_factory=list,
        description="긴급성, 계정 탈취, 도메인 불일치 등 사회공학적 위협 요소 목록",
    )
    actions: List[str] = Field(
        default_factory=list,
        description="링크 클릭 금지, 발신자 확인 등 사용자 권장 조치 목록",
    )
    reason: str = Field(description="판정 근거에 대한 명확한 설명")


class UrlAnalysisSchema(BaseModel):
    safety_score: int = Field(ge=0, le=100, description="안전도 점수 (100=완전 안전, 0=심각한 피싱)")
    reason: str = Field(description="중학생도 이해할 수 있는 쉬운 일상어 1~2문장 설명")


class TextAnalysisSchema(BaseModel):
    risk_level: Literal["안전", "주의", "위험"] = Field(description="위험도 등급")
    score: int = Field(ge=0, le=100, description="위험도 점수 (0=안전, 100=매우 위험)")
    reason: str = Field(description="중학생도 이해할 수 있는 쉬운 일상어 1~2문장 판정 이유")
    mitigation: str = Field(description="사용자를 위한 한 줄 행동 권고")


class ContentAnalysisSchema(BaseModel):
    status: Literal["SAFE", "WARNING", "DANGER"] = Field(description="보안 상태")
    reason: str = Field(description="쉬운 이유 설명")


def _extract_json_dict(raw_text: str) -> dict:
    """Fallback 모델(Gemma 등)이 마크다운 코드블록을 포함해 응답할 경우를 대비한 안전 파서."""
    cleaned = (raw_text or "").replace("```json", "").replace("```", "").strip()
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start != -1 and end != -1 and end >= start:
        cleaned = cleaned[start : end + 1]
    return json.loads(cleaned)


def _is_retryable_model_error(err: Exception) -> bool:
    msg = str(err).upper()
    return any(
        token in msg
        for token in ("429", "RESOURCE_EXHAUSTED", "503", "UNAVAILABLE", "404", "NOT_FOUND", "OVERLOADED")
    )


async def generate_structured_with_fallback(
    client: genai.Client,
    contents: list | str,
    schema: Type[T],
    fallback_json_hint: str,
    safety_settings: Optional[list] = None,
) -> T:
    """
    무료 티어 최적화 3단 Fallback 호출기:
      1순위: GEMINI_PRIMARY_MODEL   (gemini-3.5-flash-lite, RPD 500, Structured Output + Vision)
      2순위: GEMINI_SECONDARY_MODEL (gemini-3.1-flash-lite, RPD 500, Structured Output + Vision)
      3순위: GEMINI_FALLBACK_MODEL  (gemma-4-31b-it,       RPD 14.4K, 텍스트 전용 JSON 안전 파싱)
    """
    gemini_models = [
        settings.GEMINI_PRIMARY_MODEL,
        settings.GEMINI_SECONDARY_MODEL,
    ]

    last_error: Optional[Exception] = None
    for idx, model_name in enumerate(gemini_models):
        if not model_name:
            continue
        try:
            config_kwargs = {
                "response_mime_type": "application/json",
                "response_schema": schema,
            }
            if safety_settings:
                config_kwargs["safety_settings"] = safety_settings

            response = await client.aio.models.generate_content(
                model=model_name,
                contents=contents,
                config=types.GenerateContentConfig(**config_kwargs),
            )
            return schema.model_validate_json(response.text)
        except Exception as e:
            last_error = e
            if _is_retryable_model_error(e):
                print(f"[AI Fallback] {model_name} 호출 실패({type(e).__name__}), 다음 모델로 전환합니다: {e}")
                continue
            raise

    # 3순위: Gemma 4 31B (RPD 14.4K, TPM 16K 제한 고려하여 텍스트만 추출 및 길이 제한)
    fallback_model = settings.GEMINI_FALLBACK_MODEL
    if fallback_model:
        try:
            if isinstance(contents, list):
                text_parts = [c for c in contents if isinstance(c, str)]
                prompt_text = "\n".join(text_parts)
            else:
                prompt_text = str(contents)

            # Gemma 4 무료 티어 TPM(16K) 초과 방지를 위해 과도하게 긴 프롬프트 절단
            trimmed_prompt = prompt_text[:8000] + f"\n\n반드시 순수 JSON 형식으로만 응답하세요: {fallback_json_hint}"
            fallback_obj = await client.aio.models.generate_content(
                model=fallback_model,
                contents=trimmed_prompt,
            )
            raw_dict = _extract_json_dict(fallback_obj.text)
            return schema.model_validate(raw_dict)
        except Exception as fallback_e:
            print(f"[AI Fallback] 최종 보조 모델({fallback_model})도 실패했습니다: {fallback_e}")
            raise fallback_e from last_error

    if last_error:
        raise last_error
    raise RuntimeError("사용 가능한 Gemini 모델이 설정되지 않았습니다.")


def fallback_response(reason: str) -> dict:
    return {
        "is_phishing": False,
        "risk_level": "LOW",
        "summary": "AI 분석 결과를 파싱하는데 실패했거나 API 키가 없습니다.",
        "social_engineering_elements": [],
        "actions": [],
        "reason": f"분석 보류: {reason}",
    }


async def analyze_with_gemini(
    text: str,
    sender: str,
    subject: str,
    link_findings: dict,
    rag_context: Optional[str] = None,
    screenshots: Optional[List[bytes]] = None,
) -> dict:
    """Gemini Structured Outputs(JSON Schema) + 3단 Fallback 기반 피싱 메일 판정."""
    if not settings.GEMINI_API_KEY or settings.GEMINI_API_KEY == "YOUR_GEMINI_API_KEY":
        return fallback_response("GEMINI_API_KEY가 설정되지 않았습니다.")

    try:
        client = genai.Client(api_key=settings.GEMINI_API_KEY)
    except Exception as e:
        print(f"Gemini Client Init Error: {e}")
        return fallback_response("내부 시스템 설정 문제로 현재 평가를 수행할 수 없습니다.")

    rag_section = f"\n[유사 위협 사례]\n{rag_context}\n" if rag_context else ""
    vision_note = (
        "\n[시각적 분석 지침]\n첨부된 스크린샷은 메일 내 의심 링크의 실제 렌더링 화면입니다. "
        "브랜드 로고 사칭, 가짜 로그인 폼, 시각적 위장 여부를 함께 평가하세요.\n"
        if screenshots
        else ""
    )

    prompt = f"""
    당신은 피싱 이메일 전문 보안 분석가입니다. 아래 메일 정보를 분석하고 지정된 JSON 스키마에 맞춰 응답하세요.
    - mail_summary 필드에는 메일에 실제로 적힌 내용만 3~4줄('• ' 시작, 한국어, 판단/경고 없이 객관적 사실과 링크 도메인 포함)로 요약하세요.
    - 나머지 필드(is_phishing, risk_level, summary, social_engineering_elements, actions, reason)에는 보안 판정 결과를 작성하세요.

    [입력 데이터]
    - 발신자: {sender}
    - 제목: {subject}
    - 본문 텍스트: {text[:3500]}
    - 링크 검사 결과: {link_findings}{rag_section}{vision_note}
    """

    contents: list = [prompt]
    if screenshots:
        for img_bytes in screenshots[:2]:
            if img_bytes:
                contents.append(types.Part.from_bytes(data=img_bytes, mime_type="image/png"))

    try:
        parsed = await generate_structured_with_fallback(
            client=client,
            contents=contents,
            schema=EmailAnalysisSchema,
            fallback_json_hint=(
                '{"is_phishing": bool, "risk_level": "SAFE"|"LOW"|"MEDIUM"|"HIGH", '
                '"summary": str, "mail_summary": "• ...\\n• ...", '
                '"social_engineering_elements": [str], "actions": [str], "reason": str}'
            ),
        )
        return parsed.model_dump()
    except Exception as e:
        if _is_retryable_model_error(e):
            return fallback_response(
                "현재 연속된 분석 요청으로 인해 메인 AI와 보조 AI의 무료 검사 횟수를 모두 초과했습니다. 약 1분 뒤 다시 시도해 주세요."
            )
        print(f"Gemini API Error: {e}")
        return fallback_response(str(e))


async def summarize_email(visible_text: str) -> str:
    """
    메일 본문을 3~5줄 bullet point로 요약.
    - 무료 RPD 14,400회인 GEMINI_SUMMARY_MODEL(gemma-4-31b-it)을 우선 사용해
      메인 Gemini 3.5 Flash Lite(RPD 500)의 할당량을 피싱 정밀 판정에 아껴 씁니다.
    """
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
{visible_text[:3000]}"""

    candidate_models = [
        settings.GEMINI_SUMMARY_MODEL,
        settings.GEMINI_PRIMARY_MODEL,
        settings.GEMINI_SECONDARY_MODEL,
    ]
    seen = set()
    for model_name in candidate_models:
        if not model_name or model_name in seen:
            continue
        seen.add(model_name)
        try:
            response = await client.aio.models.generate_content(
                model=model_name,
                contents=prompt,
            )
            if response and response.text:
                return response.text.strip()
        except Exception as e:
            print(f"[Summarize Fallback] {model_name} 요약 실패: {e}")
            continue

    return ""


async def analyze_content(action_type: str, content: str) -> dict:
    try:
        client = genai.Client(api_key=settings.GEMINI_API_KEY)
    except Exception as e:
        print(f"Gemini Client Init Error (e.g., Missing API key): {e}")
        return {
            "status": "WARNING",
            "reason": "내부 시스템 설정 문제로 현재 평가를 수행할 수 없습니다.",
            "is_error": True,
        }

    current_time_str = datetime.now().strftime("%Y년 %m월 %d일 %H시 %M분")

    prompt = f"""
    당신은 보안 취약계층을 돕는 친절한 전문가입니다. '인증서 만료', 'XSS' 같은 어려운 기술 용어는 절대 쓰지 말고, 중학생도 이해할 수 있는 쉬운 비유와 일상어로 답변하세요.

    현재 시스템 날짜와 시간은 {current_time_str} 입니다. 내용에 포함된 날짜가 과거인지 미래인지 판단할 때 반드시 이 현재 시간을 기준으로 절대적으로 계산하세요!

    사용자가 다음 작업을 수행했습니다.
    작업 유형: {action_type} (hover는 링크에 마우스를 올린 것, drag는 텍스트를 드래그한 것)
    내용: {content}

    이 내용이 피싱 사이트나 악성 스크립트, 사기성 정보 등 보안상 위험한지 분석해주세요.
    """

    try:
        parsed = await generate_structured_with_fallback(
            client=client,
            contents=prompt,
            schema=ContentAnalysisSchema,
            fallback_json_hint='{"status": "SAFE"|"WARNING"|"DANGER", "reason": str}',
        )
        return parsed.model_dump()
    except Exception as e:
        if _is_retryable_model_error(e):
            return {
                "status": "WARNING",
                "reason": "현재 연속된 분석 요청으로 인해 메인 AI와 보조 AI의 무료 검사 횟수를 모두 초과했습니다. 약 1분 뒤 다시 시도해 주세요.",
                "is_error": True,
            }
        print(f"Gemini API Error: {e}")
        return {
            "status": "WARNING",
            "reason": "현재 분석 시스템에 일시적인 오류가 발생했습니다. 접속이나 이용에 주의해 주세요.",
            "is_error": True,
        }
