import requests
from lxml import html
import json

def fetch_content(url, rule):
    """
    Fetches and parses content from a URL using a given rule.
    
    Args:
        url (str): The URL to crawl.
        rule (dict): The rule dictionary containing 'title_xpath', 'content_xpath', 'request_headers'.
        
    Returns:
        dict: {
            'success': bool,
            'title': str,
            'content': str,
            'html_content': str,
            'error': str (optional)
        }
    """
    try:
        headers = {}
        if rule.get('request_headers'):
            try:
                headers = json.loads(rule['request_headers'])
            except:
                pass
        
        # Default UA if missing
        if 'User-Agent' not in headers:
            headers['User-Agent'] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            
        response = requests.get(url, headers=headers, timeout=15)
        
        # Encoding validation and normalization
        encoding = 'utf-8' # Default
        try:
            import chardet
            detection = chardet.detect(response.content)
            if detection['encoding'] and detection['confidence'] > 0.6:
                encoding = detection['encoding']
            else:
                encoding = response.apparent_encoding or 'utf-8'
        except ImportError:
            encoding = response.apparent_encoding or 'utf-8'
        except Exception:
            pass
            
        # Force decode to unicode
        try:
            html_text = response.content.decode(encoding, errors='replace')
        except:
            html_text = response.text # Fallback to requests' auto-decoding

        tree = html.fromstring(html_text)
        
        # Clean script and style tags before extraction
        for element in tree.xpath('//script | //style'):
            element.drop_tree()
        
        title = ""
        content = ""
        
        # Extract Title
        if rule.get('title_xpath'):
            try:
                titles = tree.xpath(rule['title_xpath'])
                if titles:
                    if isinstance(titles[0], str):
                         title = titles[0].strip()
                    else:
                         title = titles[0].text_content().strip()
            except Exception as e:
                print(f"Title extraction error: {e}")
        
        # Title Fallback
        if not title:
            try:
                # Try standard title tag
                t = tree.xpath('//title/text()')
                if t: title = t[0].strip()
                # Or first h1
                if not title:
                    h1 = tree.xpath('//h1/text()')
                    if h1: title = h1[0].strip()
            except:
                pass
                
        # Extract Content
        if rule.get('content_xpath'):
            try:
                contents = tree.xpath(rule['content_xpath'])
                if contents:
                    target_node = contents[0]
                    if isinstance(target_node, str):
                         content = target_node.strip()
                    else:
                         # Clean specific node again just in case? 
                         # (Already cleaned globally)
                         
                         # Get text content
                         raw_text = target_node.text_content()
                         
                         # Normalize whitespace
                         lines = [line.strip() for line in raw_text.splitlines() if line.strip()]
                         content = '\n'.join(lines)
                         
            except Exception as e:
                print(f"Content extraction error: {e}")
        
        return {
            'success': True,
            'title': title,
            'content': content,
            'html_content': html_text 
        }
        
    except Exception as e:
        return {'success': False, 'error': str(e)}
