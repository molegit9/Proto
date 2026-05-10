from bs4 import BeautifulSoup
import re

def sanitize_email_dom(html: str) -> str:
    """스크립트, 스타일, 숨김 요소 제거하여 안전한 HTML로 정제"""
    if not html:
        return ""
    soup = BeautifulSoup(html, "html.parser")
    
    # CSS 숨김 요소, 크기 0 요소 제거
    hidden_patterns = re.compile(r'display:\s*none|visibility:\s*hidden|font-size:\s*0(?:px|pt)?', re.IGNORECASE)
    for hidden in soup.find_all(style=hidden_patterns):
        hidden.decompose()
        
    for tag in soup(["script", "style", "meta", "link", "noscript"]):
        tag.decompose()
        
    return str(soup)

def extract_visible_text(clean_html: str) -> str:
    """정제된 HTML에서 visible text 추출"""
    soup = BeautifulSoup(clean_html, "html.parser")
    return soup.get_text(separator=' ', strip=True)

def extract_links(html: str) -> list[str]:
    """메일 본문에서 URL 추출"""
    soup = BeautifulSoup(html, "html.parser")
    links = [a.get('href') for a in soup.find_all('a', href=True) if a.get('href') and a.get('href').startswith('http')]
    return list(set(links))
