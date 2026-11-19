import base64
from app.services.http_client import get_http_client


async def fetch_email_raw(message_id: str, access_token: str) -> dict:
    headers = {"Authorization": f"Bearer {access_token}"}
    url = f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{message_id}?format=full"

    client = get_http_client()
    response = await client.get(url, headers=headers, timeout=5.0)
    response.raise_for_status()
    data = response.json()

    payload = data.get("payload", {})
    headers_list = payload.get("headers", [])

    sender = next((h["value"] for h in headers_list if h["name"].lower() == "from"), "Unknown")
    subject = next((h["value"] for h in headers_list if h["name"].lower() == "subject"), "No Subject")

    parts = payload.get("parts", [payload])

    def find_part(parts_list, mime_type):
        for part in parts_list:
            if part.get("mimeType") == mime_type:
                return part.get("body", {}).get("data", "")
            elif "parts" in part:
                res = find_part(part["parts"], mime_type)
                if res:
                    return res
        return ""

    body_data = find_part(parts, "text/html") or find_part(parts, "text/plain")
    body_html = ""
    if body_data:
        body_html = base64.urlsafe_b64decode(body_data).decode("utf-8", errors="ignore")

    return {
        "sender": sender,
        "subject": subject,
        "body_html": body_html,
    }
