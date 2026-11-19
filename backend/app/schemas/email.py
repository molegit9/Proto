from pydantic import BaseModel
from typing import List, Dict, Optional, Any


class EmailAnalyzeRequest(BaseModel):
    message_id: str
    access_token: Optional[str] = None
    # DOM 직접 추출 Fast Path (제공 시 Gmail REST API 왕복 생략)
    sender: Optional[str] = None
    subject: Optional[str] = None
    body_text: Optional[str] = None
    links: Optional[List[str]] = None


class EmailAnalyzeResponse(BaseModel):
    is_phishing: bool
    risk_level: str  # "SAFE" | "LOW" | "MEDIUM" | "HIGH"
    summary: str
    mail_summary: Optional[str] = None
    social_engineering_elements: List[str]
    actions: List[str]
    reason: str
    # 분석 상세 결과 첨부
    vt_findings: Optional[Dict[str, Any]] = None
    static_findings: Optional[List[Dict[str, Any]]] = None
    dynamic_findings: Optional[List[Dict[str, Any]]] = None
    # RAG Done Criteria — 시연용: RAG 실제 사용 여부 및 참조 판례
    rag_used: bool = False
    rag_doc_count: int = 0
    rag_retrieved_docs: Optional[List[Dict[str, Any]]] = None
    # 스트리밍 상태 표시용 (1차 빠른 판정 시 True, 최종 완료 시 False)
    deep_scan_pending: bool = False
