"""
레거시 호환 래퍼 모듈.
구버전 deprecated SDK(google-generativeai)를 제거하고 google-genai 기반 gemini_service로 통합합니다.
"""
from app.services.gemini_service import (
    analyze_with_gemini,
    summarize_email,
    fallback_response,
    EmailAnalysisSchema,
    UrlAnalysisSchema,
    TextAnalysisSchema,
)

__all__ = [
    "analyze_with_gemini",
    "summarize_email",
    "fallback_response",
    "EmailAnalysisSchema",
    "UrlAnalysisSchema",
    "TextAnalysisSchema",
]
