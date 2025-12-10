import requests
from lxml import html
import json
import urllib.parse
import traceback
import gzip
import io

class CrawlerManager:
    def __init__(self, db_connection):
        self.conn = db_connection

    def get_enabled_sources(self):
        return self.conn.execute("SELECT * FROM crawl_sources WHERE is_enabled = 1").fetchall()

    def execute_source(self, source_id, keyword):
        if not self.conn:
             return {"error": "Database connection not initialized"}
        source = self.conn.execute("SELECT * FROM crawl_sources WHERE id = ?", (source_id,)).fetchone()
        if not source:
            return {"error": "Source not found"}
        
        return self.execute_source_with_config(dict(source), keyword)

    def execute_source_with_config(self, source, keyword, max_pages=1, max_items=1000, progress_callback=None):
        try:
            all_results = []
            
            # 分页设置
            pagination_param = source.get('pagination_param')
            pagination_step = int(source.get('pagination_step') or 0)
            start_value = int(source.get('start_value') or 0)
            
            # 如果未配置分页，强制 max_pages 为 1
            if not pagination_param:
                max_pages = 1
                
            for page_idx in range(max_pages):
                # 如果已收集足够的项目，则停止
                if len(all_results) >= max_items:
                    break
                
                # 请求前报告进度（例如“开始第 X 页”）
                if progress_callback:
                    progress_callback(len(all_results), max_items, page_idx + 1, max_pages, all_results)
                
                # 1. 准备 URL
                url_template = source['url']
                if "{keyword}" in url_template:
                    base_url = url_template.replace("{keyword}", urllib.parse.quote(keyword))
                else:
                    base_url = url_template # 如果没有占位符则回退
                
                # 追加分页
                if pagination_param:
                    current_val = start_value + (page_idx * pagination_step)
                    separator = '&' if '?' in base_url else '?'
                    url = f"{base_url}{separator}{pagination_param}={current_val}"
                else:
                    url = base_url
                
                # 2. 准备请求头
                headers = {}
                if source['headers']:
                    try:
                        raw_headers = json.loads(source['headers'])
                        # 清理请求头以去除首尾空格
                        for k, v in raw_headers.items():
                            if isinstance(v, str):
                                headers[k.strip()] = v.strip()
                            else:
                                headers[k.strip()] = v
                    except:
                        pass
                
                # 3. 发起请求
                try:
                    response = requests.get(url, headers=headers, timeout=15)
                    response.raise_for_status()
                    
                    # 处理编码
                    response.encoding = response.apparent_encoding 
                    
                    # 使用最终 URL 进行相对链接解析（以防重定向）
                    final_url = response.url

                    # 4. 解析
                    tree = html.fromstring(response.content)
                    
                    page_results = []
                    
                    list_selector = source['list_selector']
                    if list_selector:
                        items = tree.xpath(list_selector)
                        if not items:
                            break
                            
                        for item in items:
                            if len(all_results) + len(page_results) >= max_items:
                                break
                                
                            try:
                                # 提取标题
                                title = ""
                                if source['title_selector']:
                                    t_els = item.xpath(source['title_selector'])
                                    if t_els:
                                        if isinstance(t_els[0], str):
                                            title = t_els[0]
                                        else:
                                            title = t_els[0].text_content()
                                
                                # 提取链接
                                link = ""
                                if source['link_selector']:
                                    l_els = item.xpath(source['link_selector'])
                                    if l_els:
                                        link = l_els[0]
                                        # 处理相对 URL
                                        if link and not link.startswith('http'):
                                            link = urllib.parse.urljoin(final_url, link)
                                
                                # 提取日期（可选）
                                date_str = ""
                                if source['date_selector']:
                                    d_els = item.xpath(source['date_selector'])
                                    if d_els:
                                        if isinstance(d_els[0], str):
                                            date_str = d_els[0]
                                        else:
                                            date_str = d_els[0].text_content()
                                
                                # 提取封面图片（可选 + 启发式）
                                cover_url = ""
                                # 1. 如果提供了选择器，尝试使用
                                if source.get('cover_selector'):
                                    c_els = item.xpath(source['cover_selector'])
                                    if c_els:
                                        if isinstance(c_els[0], str):
                                            cover_url = c_els[0]
                                        else:
                                            # 先尝试 src 属性，然后尝试文本
                                            cover_url = c_els[0].get('src', '') or c_els[0].text_content()
                                
                                # 2. 启发式回退：查找项目中的第一张图片
                                if not cover_url:
                                    imgs = item.xpath('.//img/@src')
                                    if imgs:
                                        cover_url = imgs[0]
                                
                                # 处理封面的相对 URL
                                if cover_url and not cover_url.startswith('http') and not cover_url.startswith('data:'):
                                    cover_url = urllib.parse.urljoin(final_url, cover_url)

                                if title and link:
                                    page_results.append({
                                        "title": title.strip(),
                                        "url": link.strip(),
                                        "date": date_str.strip(),
                                        "source": source['name'],
                                        "cover_url": cover_url.strip(),
                                        "summary": "" 
                                    })
                            except Exception as e:
                                print(f"Error parsing item: {e}")
                                continue
                        
                        all_results.extend(page_results)
                        
                        # 页面处理后报告进度
                        if progress_callback:
                            progress_callback(len(all_results), max_items, page_idx + 1, max_pages, all_results)
                        
                    else:
                        break
                
                except Exception as e:
                    print(f"Error requesting page {page_idx}: {e}")
                    break

            return {"result": all_results}

        except Exception as e:
            traceback.print_exc()
            return {"error": str(e), "result": []}
