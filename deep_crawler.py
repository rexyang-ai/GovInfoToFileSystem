import requests
from lxml import html
import json

def fetch_content(url, rule):
    """
    根据给定的规则从 URL 获取并解析内容。
    支持：
    - 标准 Requests + LXML (默认)
    - API 模式 (如果 content_xpath 以 'API:' 开头)
    - DOM 模式 (使用 Playwright) (如果 content_xpath 以 'DOM:' 开头)
    """
    content_xpath = rule.get('content_xpath', '')
    
    # --- 模式 1: API 采集 ---
    if content_xpath and content_xpath.startswith('API:'):
        api_url = content_xpath[4:]
        try:
            headers = {}
            if rule.get('request_headers'):
                try: headers = json.loads(rule['request_headers'])
                except: pass
            
            response = requests.get(api_url, headers=headers, timeout=15)
            return {
                'success': True,
                'title': 'API 结果',
                'content': response.text,
                'html_content': response.text,
                'publish_time': '',
                'source': ''
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    # --- 模式 2: DOM 采集 (Playwright) ---
    elif content_xpath and content_xpath.startswith('DOM:'):
        target_xpath = content_xpath[4:]
        try:
            from playwright.sync_api import sync_playwright
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()
                
                # 设置请求头
                if rule.get('request_headers'):
                    try: 
                        headers = json.loads(rule['request_headers'])
                        page.set_extra_http_headers(headers)
                    except: pass
                
                page.goto(url, timeout=30000)
                try:
                    page.wait_for_load_state('networkidle', timeout=10000)
                except:
                    pass # 如果 networkidle 超时则继续
                
                title = page.title()
                content = ""
                html_content = page.content()
                
                if target_xpath:
                    try:
                        # 等待选择器
                        page.wait_for_selector(target_xpath, timeout=5000)
                        element = page.locator(target_xpath).first
                        content = element.inner_text()
                    except:
                        content = "未找到元素或超时"
                else:
                    content = page.inner_text('body')

                # 提取发布时间 (DOM)
                publish_time = ""
                if rule.get('publish_time_xpath'):
                    try:
                        # 假设 XPath 或 CSS 选择器
                        pt_xpath = rule['publish_time_xpath']
                        if page.locator(pt_xpath).count() > 0:
                            publish_time = page.locator(pt_xpath).first.inner_text().strip()
                    except:
                        pass

                # 提取来源 (DOM)
                source = ""
                if rule.get('source_xpath'):
                    try:
                        s_xpath = rule['source_xpath']
                        if page.locator(s_xpath).count() > 0:
                            source = page.locator(s_xpath).first.inner_text().strip()
                    except:
                        pass

                browser.close()
                
                return {
                    'success': True,
                    'title': title,
                    'content': content,
                    'html_content': html_content,
                    'publish_time': publish_time,
                    'source': source
                }
        except ImportError:
            return {'success': False, 'error': "未安装 Playwright。请运行: pip install playwright && playwright install"}
        except Exception as e:
            return {'success': False, 'error': f"Playwright 错误: {str(e)}"}

    # --- 模式 3: 标准 Requests + LXML ---
    try:
        headers = {}
        if rule.get('request_headers'):
            try:
                headers = json.loads(rule['request_headers'])
            except:
                pass
        
        # 如果缺少 UA，则使用默认值
        if 'User-Agent' not in headers:
            headers['User-Agent'] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            
        response = requests.get(url, headers=headers, timeout=15)
        
        # 编码验证和标准化
        encoding = 'utf-8' # 默认
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
            
        # 强制解码为 unicode
        try:
            html_text = response.content.decode(encoding, errors='replace')
        except:
            html_text = response.text # 回退到 requests 的自动解码

        tree = html.fromstring(html_text)
        
        # 提取前清理 script 和 style 标签
        for element in tree.xpath('//script | //style'):
            element.drop_tree()
        
        title = ""
        content = ""
        
        # 提取标题
        if rule.get('title_xpath'):
            try:
                titles = tree.xpath(rule['title_xpath'])
                if titles:
                    if isinstance(titles[0], str):
                         title = titles[0].strip()
                    else:
                         title = titles[0].text_content().strip()
            except Exception as e:
                print(f"标题提取错误: {e}")
        
        # 标题回退策略
        if not title:
            try:
                # 尝试标准 title 标签
                t = tree.xpath('//title/text()')
                if t: title = t[0].strip()
                # 或者第一个 h1
                if not title:
                    h1 = tree.xpath('//h1/text()')
                    if h1: title = h1[0].strip()
            except:
                pass
                
        # 提取内容
        if rule.get('content_xpath'):
            try:
                contents = tree.xpath(rule['content_xpath'])
                if contents:
                    target_node = contents[0]
                    if isinstance(target_node, str):
                         content = target_node.strip()
                    else:
                         # 获取文本内容
                         raw_text = target_node.text_content()
                         
                         # 标准化空白字符
                         lines = [line.strip() for line in raw_text.splitlines() if line.strip()]
                         content = '\n'.join(lines)
                         
            except Exception as e:
                print(f"内容提取错误: {e}")

        # 提取发布时间
        publish_time = ""
        if rule.get('publish_time_xpath'):
             try:
                times = tree.xpath(rule['publish_time_xpath'])
                if times:
                    if isinstance(times[0], str):
                         publish_time = times[0].strip()
                    else:
                         publish_time = times[0].text_content().strip()
             except Exception as e:
                print(f"时间提取错误: {e}")

        # 提取来源
        source = ""
        if rule.get('source_xpath'):
             try:
                sources = tree.xpath(rule['source_xpath'])
                if sources:
                    if isinstance(sources[0], str):
                         source = sources[0].strip()
                    else:
                         source = sources[0].text_content().strip()
             except Exception as e:
                print(f"来源提取错误: {e}")
        
        return {
            'success': True,
            'title': title,
            'content': content,
            'html_content': html_text,
            'publish_time': publish_time,
            'source': source
        }
        
    except Exception as e:
        return {'success': False, 'error': str(e)}
