import httpx
import base64
import json

async def fetch_email_raw(message_id: str, access_token: str) -> dict:
    headers = {"Authorization": f"Bearer {access_token}"}
    url = f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{message_id}?format=full"
    
    async with httpx.AsyncClient() as client:
        response = await client.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        
        # 확인 용도로 API 원본 응답을 JSON 파일로 저장합니다.
        with open("raw_email_sample.json", "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        
    payload = data.get("payload", {})
    headers_list = payload.get("headers", [])
    
    sender = next((h["value"] for h in headers_list if h["name"] == "From"), "Unknown")
    subject = next((h["value"] for h in headers_list if h["name"] == "Subject"), "No Subject")
    
    body_html = ""
    parts = payload.get("parts", [payload])
    
    def find_html_part(parts_list):
        for part in parts_list:
            if part.get("mimeType") == "text/html":
                return part.get("body", {}).get("data", "")
            elif "parts" in part:
                res = find_html_part(part["parts"])
                if res: return res
        return ""
        
    body_data = find_html_part(parts)
    
    if body_data:
        body_html = base64.urlsafe_b64decode(body_data).decode("utf-8", errors="ignore")
            
    return {
        "sender": sender,
        "subject": subject,
        "body_html": body_html
    }
