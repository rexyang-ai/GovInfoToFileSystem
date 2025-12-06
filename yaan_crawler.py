import requests
import urllib.parse
from bs4 import BeautifulSoup
import json
import time
import re

def search_yaan(keyword):
    base_url = "https://www.yaan.gov.cn/search.html"
    
    params = {
        "cbz": "1",
        "q": keyword
    }
    
    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "Cookie": "mozi-assist={%22show%22:false%2C%22audio%22:false%2C%22speed%22:%22middle%22%2C%22zomm%22:1%2C%22cursor%22:false%2C%22pointer%22:false%2C%22bigtext%22:false%2C%22overead%22:false}; Hm_lvt_901228b544acbbc9f1fcc6332a966db7=1764471647; HMACCOUNT=96C6662EE9AB0ADD; Hm_lvt_4d11e2350c196677b9e519a08a4841e2=1764471647; JSESSIONID=45C6CDD2CD1C26D2CA5A7F52A6F8E67C; Hm_lpvt_901228b544acbbc9f1fcc6332a966db7=1764488077; Hm_lpvt_4d11e2350c196677b9e519a08a4841e2=1764488077; CT6T=38a550; CT6TS=tlgHBIBZ-tNGHego2SLg6ZBVj5HQwGUNTue5SbXLGsU",
        "Host": "www.yaan.gov.cn",
        "Pragma": "no-cache",
        "Sec-Ch-Ua": '"Not)A;Brand";v="24", "Chromium";v="116"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"Windows"',
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.97 Safari/537.36 Core/1.116.586.400 QQBrowser/19.8.6883.400"
    }

    try:
        print(f"Searching for: {keyword}")
        full_url = f"{base_url}?cbz=1&q={urllib.parse.quote(keyword)}"
        print(f"Target URL: {full_url}")
        
        response = requests.get(base_url, params=params, headers=headers)
        response.encoding = 'utf-8' # Explicitly set encoding if needed
        
        print(f"Status Code: {response.status_code}")
        
        if response.status_code == 200:
            # Preliminary Parse
            results = parse_yaan_results(response.text)
            print(f"Found {len(results)} results.")
            return {"result": results}
        else:
            print("Failed to retrieve data.")
            return {"result": []}

    except Exception as e:
        print(f"An error occurred: {e}")
        return {"result": []}

def parse_yaan_results(html_content):
    soup = BeautifulSoup(html_content, 'html.parser')
    parsed_results = []
    
    # Locate the results list
    results_container = soup.select_one('div.sou-ul02 > ul')
    if not results_container:
        return parsed_results
        
    items = results_container.find_all('li', recursive=False)
    
    for item in items:
        try:
            result_data = {
                "title": "",
                "url": "",
                "summary": "",
                "cover_url": "", # Not commonly found in this layout, but we'll look
                "date": ""
            }
            
            # 1. Title
            h1 = item.find('h1')
            if h1 and h1.find('a'):
                result_data["title"] = h1.find('a').get_text().strip()
                
                # Fallback URL from title link
                href = h1.find('a').get('href', '')
                if href.startswith('/'):
                    result_data["url"] = "https://www.yaan.gov.cn" + href
                else:
                    result_data["url"] = href

            # 2. URL & Date & Source (from h2)
            h2 = item.find('h2')
            if h2:
                spans = h2.find_all('span')
                # Usually the first span is URL, second is Date. 
                # But sometimes source is text node before spans.
                
                for span in spans:
                    text = span.get_text().strip()
                    # Check if it looks like a URL
                    if text.startswith('http') or text.startswith('www'):
                        result_data["url"] = text
                    # Check if it looks like a date (YYYY-MM-DD)
                    elif re.match(r'\d{4}-\d{2}-\d{2}', text):
                        result_data["date"] = text
            
            # 3. Summary
            p = item.find('p')
            if p:
                result_data["summary"] = p.get_text().strip()
                
            # 4. Cover URL (Try to find img)
            # The snippet doesn't show images in the list, but let's check just in case
            img = item.find('img')
            if img:
                src = img.get('src')
                if src:
                    if src.startswith('/'):
                        result_data["cover_url"] = "https://www.yaan.gov.cn" + src
                    else:
                        result_data["cover_url"] = src

            # Filter out invalid results
            if result_data["title"]:
                parsed_results.append(result_data)
                
        except Exception as e:
            print(f"Error parsing item: {e}")
            continue

    return parsed_results

if __name__ == "__main__":
    import re # Ensure re is imported for the regex check in parse function
    search_yaan("四川农业大学")
