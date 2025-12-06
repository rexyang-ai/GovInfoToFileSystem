import requests
from lxml import html, etree
import json
import re

def clean_text(text):
    if not text:
        return ""
    return re.sub(r'\s+', ' ', text).strip()

def generate_xpath(element, tree):
    """
    Generate a robust XPath for an element.
    """
    if element is None:
        return ""
    try:
        return element.getroottree().getpath(element)
    except:
        return ""

def find_best_title(tree):
    """
    Find the main title element using heuristics.
    """
    # 1. Get the document title for reference
    doc_title = ""
    titles = tree.xpath('//title')
    if titles:
        doc_title = clean_text(titles[0].text_content())
        # Remove site name separators often found in titles
        if '|' in doc_title:
            doc_title = doc_title.split('|')[0].strip()
        elif '-' in doc_title:
            parts = doc_title.split('-')
            if len(parts[0]) > 5:
                doc_title = parts[0].strip()
        elif '_' in doc_title:
            doc_title = doc_title.split('_')[0].strip()
    
    # 2. Look for H1
    h1s = tree.xpath('//h1')
    if h1s:
        # If single H1, likely it
        if len(h1s) == 1:
            return generate_xpath(h1s[0], tree)
    
        # If multiple, match against doc_title
        best_h1 = None
        
        for h1 in h1s:
            text = clean_text(h1.text_content())
            if not text:
                continue
            
            # Check overlap with doc_title
            if doc_title and (text in doc_title or doc_title in text):
                return generate_xpath(h1, tree)
            
            # Prefer H1 with reasonable length
            if 10 < len(text) < 150:
                best_h1 = h1
        
        if best_h1 is not None:
            return generate_xpath(best_h1, tree)
        
        # Fallback to first H1
        return generate_xpath(h1s[0], tree)
    
    # 3. Look for H2/H3 with 'title' in class/id
    candidates = tree.xpath('//h2 | //h3 | //div[contains(@class, "title")] | //div[contains(@id, "title")]')
    best_candidate = None
    
    for c in candidates:
        text = clean_text(c.text_content())
        if not text:
            continue
            
        if doc_title and (text in doc_title or doc_title in text):
            return generate_xpath(c, tree)
            
        if 10 < len(text) < 150:
            if best_candidate is None:
                best_candidate = c
                
    if best_candidate is not None:
        return generate_xpath(best_candidate, tree)

    # 4. Fallback to title tag
    if titles:
        return generate_xpath(titles[0], tree)

    return "/html/head/title"

def sniff_page(url):
    """
    Fetches the page and attempts to guess the title and content XPaths.
    """
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.encoding = response.apparent_encoding
        
        if response.status_code != 200:
            return None, f"Failed to fetch page: Status {response.status_code}"
            
        tree = html.fromstring(response.content)
        
        # 1. Guess Title XPath
        title_xpath = find_best_title(tree)
                
        # 2. Guess Content XPath
        content_xpath = ""
        
        # Candidate tags for content container
        candidates = tree.xpath('//article | //div | //section | //td')
        best_candidate = None
        max_score = 0
        
        for candidate in candidates:
            # Score based on text length of p children
            ps = candidate.xpath('.//p')
            if not ps:
                continue
            
            text_len = sum(len(clean_text(p.text_content())) for p in ps)
            
            # Simple heuristic: text length
            score = text_len
            
            if score > max_score:
                max_score = score
                best_candidate = candidate
                
        if best_candidate is not None:
            content_xpath = generate_xpath(best_candidate, tree)
        else:
            content_xpath = "/html/body"
            
        return {
            "title_xpath": title_xpath,
            "content_xpath": content_xpath,
            "request_headers": json.dumps(headers)
        }, None
        
    except Exception as e:
        return None, str(e)
