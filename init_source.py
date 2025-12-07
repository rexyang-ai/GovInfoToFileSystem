from app.database.db import init_db, get_db_connection
import json

# Initialize DB to create the new table
init_db()

conn = get_db_connection()

# Baidu News Source
name = "百度新闻搜索"
url = "https://www.baidu.com/s?rtt=1&bsst=1&cl=2&tn=news&ie=utf-8&pn=10&word={keyword}"
headers_str = """
Accept: 
text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7 
Accept-Encoding: 
gzip, deflate, br 
Accept-Language: 
zh-CN,zh;q=0.9 
Cache-Control: 
no-cache 
Connection: 
keep-alive 
Cookie: 
BIDUPSID=D48AC21A701043225723F7B0416A45A5; PSTM=1749868400; BD_UPN=1a314753; MAWEBCUID=web_YJdcNWbgVAvBDdOlAjnOFGURksbLStlKretXHCZPDmkKBoCWao; newlogin=1; BDUSS=Bsb0RmVWp3c0NmMHNwOVpnVTZpSUU1Rn5IU1c1S29EVVJQYVI0ZWFnWEhDazVwSVFBQUFBJCQAAAAAAAAAAAEAAACr7QECeWFuZ2FodWkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMd9JmnHfSZpNX; BDUSS_BFESS=Bsb0RmVWp3c0NmMHNwOVpnVTZpSUU1Rn5IU1c1S29EVVJQYVI0ZWFnWEhDazVwSVFBQUFBJCQAAAAAAAAAAAEAAACr7QECeWFuZ2FodWkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMd9JmnHfSZpNX; H_WISE_SIDS_BFESS=60279_63146_66117_66219_66192_66164_66283_66255_66393_66529_66561_66585_66591_66600_66605_66640_66651_66663_66674_66690_66696_66710_66716_66742_66776_66789_66793_66803_66799_66599_66815_66827; BAIDUID=F90B346AE74BA31BBA803D1E9ED5A329:SL=0:NR=10:FG=1; BAIDUID_BFESS=F90B346AE74BA31BBA803D1E9ED5A329:SL=0:NR=10:FG=1; MCITY=-%3A; BDRCVFR[S_ukKV6dOkf]=mk3SLVN4HKm; H_PS_PSSID=60279_63146_66117_66219_66192_66164_66283_66255_66393_66529_66561_66585_66591_66600_66605_66651_66663_66674_66690_66696_66710_66716_66742_66776_66789_66793_66803_66799_66599_66815_66827_66854; PAD_BROWSER=1; BA_HECTOR=0h0g200k8h240kal00818020858l801kj77ng25; ZFY=:BbjM:A1IBjzvZvV4stKekEFIixozKxmgJlX2ZrIwt9J0:C; BD_CK_SAM=1; delPer=0; BDORZ=FFFB88E999055A3F8A630C64834BD6D0; baikeVisitId=1517a56e-4545-4313-bbc5-3b478747d8e3; PSINO=7; arialoadData=false; ab_sr=1.0.1_OGI2ZDUxMzQ2MzAyMTE1YWEyMjFkZWY1OTZlYmQxZGU0ZDViYmVhOWQ3ZWNjNjg5ZTliMGY2NTI0OTcxNTI2OGQxZDZiNmEwY2Y0MWU5MzA5NGQxOGIxMDlmZjM3YWNhODE1Nzg5NGJjYjNlYTBiMzk0Yjg1M2ExZWNjMDExZWNhYTZlOTdmYmI4NTRiYTQ0NzliOWE1OGQ1ZjUyOTIzMDVmMTBkZDMwMjczODYzMjA3M2YxYmE1ZmI4MmMxZGI1ZTBiNWU0MTUyMmIzOGJmOTBmZjhkMWJjZjdhNDBjNWE=; sug=3; sugstore=0; ORIGIN=0; SMARTINPUT=1; bdime=0; pcMainBoxRec=1; H_PS_645EC=9ccflPRzt0A7TnXHiXJ3OdSziTHQ7rJXw8j4%2BLK7pzKgB%2FaY1p6J%2FaXnAICZFQEsndM; H_WISE_SIDS=60279_63146_66117_66219_66192_66164_66283_66255_66393_66529_66561_66585_66591_66600_66605_66651_66663_66674_66690_66696_66710_66716_66742_66776_66789_66793_66803_66799_66599_66815_66827_66854; BDRCVFR[C0p6oIjvx-c]=IOl8Feir8NCfjb3njDsnj64gvwM; BDSVRTM=869 
Host: 
www.baidu.com 
Pragma: 
no-cache 
Referer: 
https://www.baidu.com/s?rtt=1&bsst=1&cl=2&tn=news&ie=utf-8&word=123  
Sec-Ch-Ua: 
"Not)A;Brand";v="24", "Chromium";v="116" 
Sec-Ch-Ua-Mobile: 
?0 
Sec-Ch-Ua-Platform: 
"Windows" 
Sec-Fetch-Dest: 
document 
Sec-Fetch-Mode: 
navigate 
Sec-Fetch-Site: 
same-origin 
Sec-Fetch-User: 
?1 
Upgrade-Insecure-Requests: 
1 
User-Agent: 
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.97 Safari/537.36 Core/1.116.591.400 QQBrowser/19.9.6957.400 
"""

def parse_headers(header_str):
    headers = {}
    lines = header_str.split('\n')
    current_key = None
    for line in lines:
        line = line.strip()
        if not line: continue
        if ':' in line:
            parts = line.split(':', 1)
            key = parts[0].strip()
            value = parts[1].strip()
            headers[key] = value
            current_key = key
        elif current_key:
            headers[current_key] += " " + line
    return json.dumps(headers)

headers_json = parse_headers(headers_str)

# Selectors (Best guess for Baidu News)
list_selector = "//div[contains(@class, 'result-op')]"
title_selector = ".//h3[contains(@class, 'c-title')]/a"
link_selector = ".//h3[contains(@class, 'c-title')]/a/@href"
date_selector = ".//span[contains(@class, 'c-color-gray2')]"

# Check if exists
exists = conn.execute("SELECT id FROM crawl_sources WHERE name = ?", (name,)).fetchone()

if not exists:
    conn.execute('''
        INSERT INTO crawl_sources (name, url, headers, list_selector, title_selector, link_selector, date_selector)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (name, url, headers_json, list_selector, title_selector, link_selector, date_selector))
    print("Added Baidu News Source")
else:
    # Update
    conn.execute('''
        UPDATE crawl_sources 
        SET url=?, headers=?, list_selector=?, title_selector=?, link_selector=?, date_selector=?
        WHERE name=?
    ''', (url, headers_json, list_selector, title_selector, link_selector, date_selector, name))
    print("Updated Baidu News Source")

conn.commit()
conn.close()
