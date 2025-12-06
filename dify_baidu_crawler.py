import urllib.request
import urllib.parse
import urllib.error
import re
import json
import gzip
import io

def main(arg1: str) -> dict:
    """
    Dify Code Execution Entry Point
    :param arg1: Search Keyword (e.g., "成都")
    :return: Dict with results in "result" key
    """
    keyword = arg1
    if not keyword:
        keyword = "成都"

    base_url = "https://www.baidu.com/s"
    
    params = {
        "wd": keyword
    }
    
    # Encode query parameters
    query_string = urllib.parse.urlencode(params)
    full_url = f"{base_url}?{query_string}"
    
    # Headers - Removed 'br' to avoid need for brotli package
    # Removed complex cookies to avoid session binding issues
    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "Host": "www.baidu.com",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.97 Safari/537.36 Core/1.116.586.400 QQBrowser/19.8.6883.400",
        "Cookie": "BIDUPSID=D48AC21A701043225723F7B0416A45A5; PSTM=1749868400; BAIDUID=D48AC21A70104322974B66FAE2F73383:SL=0:NR=10:FG=1;"
    }

    try:
        req = urllib.request.Request(full_url, headers=headers)
        
        # Set timeout in open
        with urllib.request.urlopen(req, timeout=15) as response:
            # Check if response is compressed
            encoding = response.info().get('Content-Encoding')
            content = response.read()
            
            if encoding == 'gzip':
                content = gzip.decompress(content)
            elif encoding == 'deflate':
                # Handle deflate (sometimes raw deflate, sometimes zlib)
                try:
                    content = gzip.decompress(content)
                except:
                    import zlib
                    content = zlib.decompress(content)
            
            # Decode content
            # Try to detect charset or default to utf-8
            charset = response.info().get_param('charset', 'utf-8')
            try:
                html_content = content.decode(charset)
            except UnicodeDecodeError:
                html_content = content.decode('utf-8', errors='ignore')
            
            results = parse_baidu_search_results_regex(html_content)
            
            return {
                "result": results
            }
            
    except urllib.error.HTTPError as e:
        print(f"HTTP Error: {e.code}")
        return {
            "result": []
        }
    except Exception as e:
        print(f"Exception: {e}")
        return {
            "result": []
        }

def clean_html_tag(text):
    """Remove html tags from string"""
    if not text:
        return ""
    # Replace <br> with newline
    text = re.sub(r'<br\s*/?>', '\n', text, flags=re.I)
    # Remove all other tags
    text = re.sub(r'<[^>]+>', '', text)
    # Unescape HTML entities (basic ones)
    text = text.replace('&nbsp;', ' ').replace('&lt;', '<').replace('&gt;', '>').replace('&amp;', '&').replace('&quot;', '"')
    
    # Remove specific garbage characters often found in Baidu results
    text = re.sub(r'[\ue000-\uf8ff]', '', text)
    
    # Collapse whitespace
    text = re.sub(r'\s+', ' ', text).strip()
    return text

def parse_baidu_search_results_regex(html_content):
    parsed_results = []
    
    # Find all h3 blocks which contain the Title and URL
    # Updated regex to be more permissive
    h3_pattern = r'<h3[^>]*>[\s\S]*?<a[^>]*href\s*=\s*["\'](.*?)["\'][^>]*>([\s\S]*?)</a>[\s\S]*?</h3>'
    
    matches = list(re.finditer(h3_pattern, html_content))
    
    for i, match in enumerate(matches):
        url = match.group(1)
        raw_title = match.group(2)
        title = clean_html_tag(raw_title)
        
        if not title or not url:
            continue
            
        item = {
            "title": title,
            "url": url,
            "summary": "",
            "cover_url": ""
        }
        
        # Define the search window for summary and image
        start_pos = match.end()
        end_pos = matches[i+1].start() if i < len(matches) - 1 else len(html_content)
        
        window_size = min(end_pos - start_pos, 5000)
        search_window = html_content[start_pos : start_pos + window_size]
        
        # 1. Extract Image
        img_match = re.search(r'<img[^>]*src\s*=\s*["\'](http[^"\']+)["\']', search_window)
        if img_match:
            item["cover_url"] = img_match.group(1)
            
        # 2. Extract Summary
        summary_pattern = r'<div[^>]*class\s*=\s*["\'][^"\']*(?:c-abstract|content-right|c-span18|c-span24|line-clamp)[^"\']*["\'][^>]*>([\s\S]*?)</div>'
        summary_match = re.search(summary_pattern, search_window)
        
        if summary_match:
            item["summary"] = clean_html_tag(summary_match.group(1))
        else:
            # Fallback
            clean_window = re.sub(r'<(script|style)[^>]*>[\s\S]*?</\1>', '', search_window, flags=re.I)
            text_only = clean_html_tag(clean_window)
            
            if len(text_only) > 10:
                item["summary"] = text_only[:200] + "..."
        
        parsed_results.append(item)

    return parsed_results

if __name__ == "__main__":
    # Local test
    print("Testing with keyword '上海' (Urllib Version)...")
    result = main("上海")
    print(json.dumps(result, ensure_ascii=False, indent=2))
