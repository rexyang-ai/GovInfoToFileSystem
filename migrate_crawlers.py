from app.database.db import get_db_connection
import json

def migrate():
    conn = get_db_connection()
    
    # 1. Yaan Government
    yaan_name = "雅安市政府"
    yaan_url = "https://www.yaan.gov.cn/search.html?cbz=1&q={keyword}"
    yaan_headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.97 Safari/537.36"
    }
    
    # XPath based on yaan_crawler.py logic
    # list: div.sou-ul02 > ul > li
    yaan_list = "//div[contains(@class, 'sou-ul02')]/ul/li"
    yaan_title = ".//h1/a"
    yaan_link = ".//h1/a/@href"
    yaan_date = ".//h2/span[contains(text(), '-')]" # Heuristic for YYYY-MM-DD
    
    # Check and Insert Yaan
    exists = conn.execute("SELECT id FROM crawl_sources WHERE name = ?", (yaan_name,)).fetchone()
    if not exists:
        conn.execute('''
            INSERT INTO crawl_sources (name, url, headers, list_selector, title_selector, link_selector, date_selector)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (yaan_name, yaan_url, json.dumps(yaan_headers), yaan_list, yaan_title, yaan_link, yaan_date))
        print(f"Added {yaan_name}")
    else:
        # Update to ensure latest config
        conn.execute('''
            UPDATE crawl_sources 
            SET url=?, headers=?, list_selector=?, title_selector=?, link_selector=?, date_selector=?
            WHERE name=?
        ''', (yaan_url, json.dumps(yaan_headers), yaan_list, yaan_title, yaan_link, yaan_date, yaan_name))
        print(f"Updated {yaan_name}")

    # 2. Baidu General Search (Replacing dify_baidu_crawler)
    baidu_name = "百度全网搜索"
    baidu_url = "https://www.baidu.com/s?wd={keyword}"
    baidu_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.97 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Cookie": "BIDUPSID=D48AC21A701043225723F7B0416A45A5;" # Minimal cookie
    }
    
    # XPath for Baidu General
    # This is tricky as Baidu changes. We use a common pattern.
    baidu_list = "//div[contains(@class, 'result') and contains(@class, 'c-container')]"
    baidu_title = ".//h3/a"
    baidu_link = ".//h3/a/@href"
    baidu_date = ".//span[contains(@class, 'c-color-gray2')]" # Sometimes works
    
    exists = conn.execute("SELECT id FROM crawl_sources WHERE name = ?", (baidu_name,)).fetchone()
    if not exists:
        conn.execute('''
            INSERT INTO crawl_sources (name, url, headers, list_selector, title_selector, link_selector, date_selector)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (baidu_name, baidu_url, json.dumps(baidu_headers), baidu_list, baidu_title, baidu_link, baidu_date))
        print(f"Added {baidu_name}")
    else:
         conn.execute('''
            UPDATE crawl_sources 
            SET url=?, headers=?, list_selector=?, title_selector=?, link_selector=?, date_selector=?
            WHERE name=?
        ''', (baidu_url, json.dumps(baidu_headers), baidu_list, baidu_title, baidu_link, baidu_date, baidu_name))
         print(f"Updated {baidu_name}")

    conn.commit()
    conn.close()

if __name__ == '__main__':
    migrate()
