from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, Response, stream_with_context
from openai import OpenAI
import httpx
from app.analysis_agent import stream_chat_with_data
from app.crawler_manager import CrawlerManager
from app.database.db import get_db_connection
import dify_baidu_crawler
import yaan_crawler
import sniffer
import deep_crawler
import os
import json
import datetime
import concurrent.futures
import threading
import uuid
import time
from urllib.parse import urlparse

# Global dictionary to store crawl tasks
crawl_tasks = {}
executor = concurrent.futures.ThreadPoolExecutor(max_workers=5)

def search_task_runner(task_id, selected_sources, keyword, max_pages, max_items):
    """
    Background task to run the crawler and update progress.
    """
    try:
        crawl_tasks[task_id]['status'] = 'running'
        results = []
        
        # Helper to update progress
        def progress_callback(current_count, limit_items, current_page, limit_pages):
            # This callback comes from a single source execution.
            # Since we might run multiple sources in parallel, this simple callback 
            # might overwrite progress from other sources if not careful.
            # For now, we'll just sum up results or update "last activity".
            # A better way: accumulate counts in the task object.
            # But execute_source_with_config is running in this thread (if sequential) 
            # or sub-threads (if parallel).
            
            # If we run sources sequentially in this background task:
            crawl_tasks[task_id]['progress'] = f"正在采集... (当前页: {current_page}/{limit_pages}, 已采集: {len(results) + current_count})"
            crawl_tasks[task_id]['current_count'] = len(results) + current_count
            # Note: This count is slightly off because 'results' is from previous sources, 
            # and 'current_count' is from current source.
            pass

        # We need a way to aggregate progress if we run multiple sources.
        # For simplicity, let's run sources SEQUENTIALLY in this background thread 
        # so we can accurately report progress.
        
        conn = get_db_connection()
        crawler_manager = CrawlerManager(None) # Connection not needed for execute_source_with_config if we pass config
        
        total_sources = len(selected_sources)
        
        for idx, source_id in enumerate(selected_sources):
            source_row = conn.execute("SELECT * FROM crawl_sources WHERE id = ?", (source_id,)).fetchone()
            if not source_row:
                continue
                
            source_config = dict(source_row)
            source_name = source_config.get('name', 'Unknown')
            
            crawl_tasks[task_id]['progress'] = f"正在采集 [{source_name}] ({idx+1}/{total_sources})..."
            
            # Define a specific callback for this source to update global task state
            def specific_callback(curr_c, max_c, curr_p, max_p, current_results=None):
                total_so_far = len(results) + curr_c
                crawl_tasks[task_id]['current_count'] = total_so_far
                crawl_tasks[task_id]['progress'] = f"正在采集 [{source_name}] ({idx+1}/{total_sources}): 第 {curr_p}/{max_p} 页, 累计 {total_so_far} 条"
                if current_results:
                     crawl_tasks[task_id]['results'] = results + current_results
            
            # Run crawler
            res = crawler_manager.execute_source_with_config(
                source_config, 
                keyword, 
                max_pages, 
                max_items, 
                progress_callback=specific_callback
            )
            
            if res and 'result' in res:
                results.extend(res['result'])
                
        conn.close()
        
        crawl_tasks[task_id]['results'] = results
        crawl_tasks[task_id]['current_count'] = len(results)
        crawl_tasks[task_id]['status'] = 'completed'
        crawl_tasks[task_id]['progress'] = f"采集完成，共找到 {len(results)} 条数据"
        
    except Exception as e:
        print(f"Task {task_id} error: {e}")
        crawl_tasks[task_id]['status'] = 'failed'
        crawl_tasks[task_id]['error'] = str(e)


def parse_headers_to_json(header_str):
    """
    Parses a header string (JSON or raw text) into a JSON string.
    Supports raw copy-paste from browser DevTools (Key: Value or Key:\\nValue).
    """
    if not header_str:
        return "{}"
    
    header_str = header_str.strip()
    
    # 1. Try to parse as JSON first
    try:
        # If it's already JSON, ensure it's a dict
        parsed = json.loads(header_str)
        if isinstance(parsed, dict):
            return json.dumps(parsed) 
    except:
        pass
        
    # 2. Parse as raw text
    headers = {}
    lines = header_str.split('\n')
    current_key = None
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
            
        if line.endswith(':'):
             # Case: "Key:" on one line, value on next
             current_key = line[:-1].strip()
        elif ':' in line:
             # Case: "Key: Value" on same line
             # If we have a current_key pending, it means the previous key had no value or was malformed.
             # We'll just overwrite/ignore the previous key for now or assume empty string?
             # Let's assume if we see a new Key: Value, the previous pending key is done.
             
             # Handle "Key: Value"
             parts = line.split(':', 1)
             key = parts[0].strip()
             value = parts[1].strip()
             headers[key] = value
             current_key = None 
        else:
             # No colon. Must be value for current_key
             if current_key:
                 headers[current_key] = line
                 current_key = None
             else:
                 # No current key? Skip or handle specific cases
                 pass
                 
    return json.dumps(headers)

def extract_domain(url):
    if not url:
        return ''
    try:
        parsed_uri = urlparse(url)
        return '{uri.netloc}'.format(uri=parsed_uri)
    except:
        return url

app = Flask(__name__, template_folder='app/templates', static_folder='app/static')
app.secret_key = 'super_secret_key_for_demo_only'  # Change for prod

def extract_domain(url):
    if not url:
        return ''
    try:
        parsed_uri = urlparse(url)
        return '{uri.netloc}'.format(uri=parsed_uri)
    except:
        return url

@app.template_filter('get_domain')
def get_domain(url):
    return extract_domain(url)

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        if user and user['password'] == password:
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('dashboard'))
        else:
            flash('登录失败：用户名或密码错误', 'error')
            
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', username=session['username'])

@app.route('/crawler-manager')
def crawler_manager():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('crawler_manager.html', username=session['username'])

@app.route('/api/sources/full')
def api_list_sources_full():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    page = request.args.get('page', 1, type=int)
    keyword = request.args.get('keyword', '', type=str)
    per_page = request.args.get('per_page', 20, type=int)
    offset = (page - 1) * per_page
    
    conn = get_db_connection()
    
    if keyword:
        sources = conn.execute("SELECT * FROM crawl_sources WHERE name LIKE ? OR url LIKE ? ORDER BY id DESC LIMIT ? OFFSET ?", 
                             (f'%{keyword}%', f'%{keyword}%', per_page, offset)).fetchall()
        total = conn.execute("SELECT COUNT(*) FROM crawl_sources WHERE name LIKE ? OR url LIKE ?", 
                           (f'%{keyword}%', f'%{keyword}%')).fetchone()[0]
    else:
        sources = conn.execute("SELECT * FROM crawl_sources ORDER BY id DESC LIMIT ? OFFSET ?", (per_page, offset)).fetchall()
        total = conn.execute("SELECT COUNT(*) FROM crawl_sources").fetchone()[0]
        
    conn.close()
    
    return jsonify({
        'items': [dict(s) for s in sources],
        'total': total,
        'page': page,
        'per_page': per_page,
        'total_pages': (total + per_page - 1) // per_page
    })

@app.route('/api/sources', methods=['POST'])
def create_source():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
        
    data = request.get_json()
    
    try:
        conn = get_db_connection()
        conn.execute('''
            INSERT INTO crawl_sources (name, url, headers, list_selector, title_selector, link_selector, date_selector, cover_selector, is_enabled, pagination_param, pagination_step, start_value)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            data['name'], 
            data['url'], 
            parse_headers_to_json(data.get('headers', '{}')), 
            data.get('list_selector'), 
            data.get('title_selector'), 
            data.get('link_selector'), 
            data.get('date_selector'),
            data.get('cover_selector'),
            data.get('is_enabled', True),
            data.get('pagination_param'),
            data.get('pagination_step', 0),
            data.get('start_value', 0)
        ))
        conn.commit()
        conn.close()
        return jsonify({'message': 'Created successfully'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/sources/<int:id>', methods=['GET', 'PUT', 'DELETE'])
def manage_source(id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
        
    conn = get_db_connection()
    
    if request.method == 'GET':
        source = conn.execute("SELECT * FROM crawl_sources WHERE id = ?", (id,)).fetchone()
        conn.close()
        if not source:
            return jsonify({'error': 'Not found'}), 404
        return jsonify(dict(source))
        
    elif request.method == 'PUT':
        data = request.get_json()
        try:
            conn.execute('''
                UPDATE crawl_sources 
                SET name=?, url=?, headers=?, list_selector=?, title_selector=?, link_selector=?, date_selector=?, cover_selector=?, is_enabled=?, pagination_param=?, pagination_step=?, start_value=?
                WHERE id=?
            ''', (
                data['name'], 
                data['url'], 
                parse_headers_to_json(data.get('headers', '{}')), 
                data.get('list_selector'), 
                data.get('title_selector'), 
                data.get('link_selector'), 
                data.get('date_selector'),
                data.get('cover_selector'),
                data.get('is_enabled', True),
                data.get('pagination_param'),
                data.get('pagination_step', 0),
                data.get('start_value', 0),
                id
            ))
            conn.commit()
            conn.close()
            return jsonify({'message': 'Updated successfully'})
        except Exception as e:
            conn.close()
            return jsonify({'error': str(e)}), 500
            
    elif request.method == 'DELETE':
        try:
            conn.execute("DELETE FROM crawl_sources WHERE id = ?", (id,))
            conn.commit()
            conn.close()
            return jsonify({'message': 'Deleted successfully'})
        except Exception as e:
            conn.close()
            return jsonify({'error': str(e)}), 500

@app.route('/search', methods=['POST'])
def search():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
        
    data = request.get_json()
    keyword = data.get('keyword', '')
    selected_sources = data.get('sources', [])
    max_pages = int(data.get('max_pages', 1))
    max_items = int(data.get('max_items', 100))
    
    if not keyword:
        return jsonify({'error': 'Keyword is required'}), 400
        
    # Create a Task
    task_id = str(uuid.uuid4())
    crawl_tasks[task_id] = {
        'status': 'initializing',
        'progress': '正在初始化...',
        'current_count': 0,
        'total_planned': max_items,
        'results': []
    }
    
    # Start background task
    executor.submit(search_task_runner, task_id, selected_sources, keyword, max_pages, max_items)
    
    return jsonify({'task_id': task_id})

@app.route('/search/status/<task_id>')
def search_status(task_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
        
    task = crawl_tasks.get(task_id)
    if not task:
        return jsonify({'error': 'Task not found'}), 404
        
    response = {
        'status': task['status'],
        'progress': task.get('progress', ''),
        'current_count': task.get('current_count', 0),
        'total_planned': task.get('total_planned', 0),
        'result': task.get('results', [])
    }
    
    if task['status'] == 'failed':
        response['error'] = task.get('error')
        
    return jsonify(response)

@app.route('/save', methods=['POST'])
def save_data():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
        
    data = request.get_json()
    items = data.get('items', [])
    keyword = data.get('keyword', '')
    
    if not items:
        return jsonify({'message': 'No items to save'}), 200
        
    conn = get_db_connection()
    insert_count = 0
    update_count = 0
    successful_urls = []
    
    # We will iterate through items and try to save them one by one.
    # To avoid partial failures blocking others, we'll try/except inside the loop.
    # Note: SQLite transaction behavior. If we want partial success, we can just commit at the end, 
    # but if an error occurs (like unique constraint), we should handle it.
    # Since we check for existence first, unique constraint on URL shouldn't trigger unless race condition.
    
    try:
        for item in items:
            try:
                url = item.get('url')
                if not url:
                    continue
                    
                # Check if exists
                existing = conn.execute('SELECT id FROM crawled_data WHERE url = ?', (url,)).fetchone()
                
                if existing:
                    conn.execute('''
                        UPDATE crawled_data 
                        SET title = ?, summary = ?, cover_url = ?, search_keyword = ?
                        WHERE id = ?
                    ''', (item.get('title'), item.get('summary'), item.get('cover_url'), keyword, existing['id']))
                    update_count += 1
                else:
                    conn.execute('''
                        INSERT INTO crawled_data (title, url, summary, cover_url, search_keyword)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (item.get('title'), url, item.get('summary'), item.get('cover_url'), keyword))
                    insert_count += 1
                
                successful_urls.append(url)
                
            except Exception as e:
                print(f"Error saving item {item.get('url')}: {e}")
                # Continue to next item
                continue
                
        conn.commit()
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()
        
    return jsonify({
        'message': f'保存操作完成。新增 {insert_count} 条，更新 {update_count} 条。',
        'insert_count': insert_count,
        'update_count': update_count,
        'successful_urls': successful_urls
    })

@app.route('/warehouse')
def warehouse():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    keyword = request.args.get('keyword', '')
    date_filter = request.args.get('date', '')
    page = request.args.get('page', 1, type=int)
    per_page = 20
    offset = (page - 1) * per_page
    
    # Base query
    where_clause = " WHERE 1=1"
    params = []
    
    if keyword:
        where_clause += " AND (title LIKE ? OR summary LIKE ? OR search_keyword LIKE ?)"
        params.extend([f'%{keyword}%', f'%{keyword}%', f'%{keyword}%'])
        
    if date_filter:
        where_clause += " AND date(created_at) = ?"
        params.append(date_filter)
        
    conn = get_db_connection()
    
    # Count total
    count_query = "SELECT COUNT(*) FROM crawled_data" + where_clause
    total = conn.execute(count_query, params).fetchone()[0]
    
    # Fetch paginated items
    query = "SELECT * FROM crawled_data" + where_clause + " ORDER BY created_at DESC LIMIT ? OFFSET ?"
    params.extend([per_page, offset])
    rows = conn.execute(query, params).fetchall()
    
    items = []
    for row in rows:
        item = dict(row)
        domain = extract_domain(item['url'])
        rule = conn.execute('SELECT rule_name FROM crawling_rules WHERE domain = ?', (domain,)).fetchone()
        item['rule_name'] = rule['rule_name'] if rule else None
        item['has_rules'] = True if rule else False
        items.append(item)

    conn.close()
    
    return render_template('warehouse.html', items=items, total=total, page=page, per_page=per_page, total_pages=(total + per_page - 1) // per_page, username=session['username'])

@app.route('/sniff', methods=['POST'])
def sniff():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    url = data.get('url')
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
        
    # Attempt to find matching source for headers
    conn = get_db_connection()
    sources = conn.execute("SELECT url, headers FROM crawl_sources").fetchall()
    conn.close()
    
    target_domain = extract_domain(url)
    custom_headers = None
    matched_source_url = None
    
    for s in sources:
        s_url = s['url']
        s_domain = extract_domain(s_url)
        # Check if domains match (exact or subdomain)
        if target_domain == s_domain or target_domain.endswith('.' + s_domain) or s_domain.endswith('.' + target_domain):
             if s['headers']:
                 custom_headers = s['headers']
                 matched_source_url = s_url
                 break
    
    # 1. Sniff the page
    result, error = sniffer.sniff_page(url, custom_headers)
    
    if error:
        return jsonify({'error': error}), 500
        
    # 2. Return data for confirmation (DO NOT SAVE YET)
    # Use final_url from sniffer result if available (handles redirects)
    final_url = result.get('final_url', url)
    domain = extract_domain(final_url)
    
    result['domain'] = domain
    result['rule_name'] = f"规则_{domain}"
    if matched_source_url:
         result['matched_source'] = matched_source_url
    
    return jsonify({'message': '嗅探成功', 'data': result})

@app.route('/rule/save', methods=['POST'])
def save_rule():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
        
    data = request.get_json()
    url = data.get('url')
    rule_name = data.get('rule_name')
    title_xpath = data.get('title_xpath')
    content_xpath = data.get('content_xpath')
    request_headers = parse_headers_to_json(data.get('request_headers'))
    
    if not url or not rule_name:
        return jsonify({'error': 'Missing required fields'}), 400
        
    domain = extract_domain(url)
    conn = get_db_connection()
    try:
        # Check if rule exists for this domain
        existing = conn.execute("SELECT id FROM crawling_rules WHERE domain = ?", (domain,)).fetchone()
        
        if existing:
            conn.execute('''
                UPDATE crawling_rules 
                SET rule_name = ?, url_pattern = ?, title_xpath = ?, content_xpath = ?, request_headers = ?, created_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (rule_name, url, title_xpath, content_xpath, request_headers, existing['id']))
        else:
            conn.execute('''
                INSERT INTO crawling_rules (rule_name, domain, url_pattern, title_xpath, content_xpath, request_headers)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (rule_name, domain, url, title_xpath, content_xpath, request_headers))
        
        conn.commit()
        return jsonify({'message': '规则已成功保存'})
        
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/rules')
def rules():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    
    page = request.args.get('page', 1, type=int)
    keyword = request.args.get('keyword', '', type=str)
    per_page = 20
    offset = (page - 1) * per_page

    conn = get_db_connection()
    
    where_clause = ""
    params = []
    if keyword:
        where_clause = "WHERE rule_name LIKE ? OR domain LIKE ?"
        params = [f'%{keyword}%', f'%{keyword}%']
    
    count_query = f"SELECT COUNT(*) FROM crawling_rules {where_clause}"
    total = conn.execute(count_query, params).fetchone()[0]

    query = f"SELECT * FROM crawling_rules {where_clause} ORDER BY created_at DESC LIMIT ? OFFSET ?"
    params.extend([per_page, offset])
    
    rules = conn.execute(query, params).fetchall()
    conn.close()
    
    return render_template('rules.html', rules=rules, total=total, page=page, per_page=per_page, total_pages=(total + per_page - 1) // per_page, username=session.get('username'))

@app.route('/rules/get/<int:rule_id>')
def get_rule(rule_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
        
    conn = get_db_connection()
    rule = conn.execute('SELECT * FROM crawling_rules WHERE id = ?', (rule_id,)).fetchone()
    conn.close()
    
    if rule:
        return jsonify(dict(rule))
    else:
        return jsonify({'error': 'Rule not found'}), 404

@app.route('/rules/add', methods=['POST'])
def add_rule():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
        
    data = request.get_json()
    rule_name = data.get('rule_name')
    url_pattern = data.get('url_pattern')
    title_xpath = data.get('title_xpath')
    content_xpath = data.get('content_xpath')
    request_headers = parse_headers_to_json(data.get('request_headers'))
    
    if not rule_name or not url_pattern:
        return jsonify({'error': 'Missing required fields'}), 400
        
    domain = extract_domain(url_pattern)
    
    conn = get_db_connection()
    try:
        conn.execute('''
            INSERT INTO crawling_rules (rule_name, domain, url_pattern, title_xpath, content_xpath, request_headers)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (rule_name, domain, url_pattern, title_xpath, content_xpath, request_headers))
        conn.commit()
        return jsonify({'message': 'Rule added successfully'})
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/rules/update/<int:rule_id>', methods=['POST'])
def update_rule(rule_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
        
    data = request.get_json()
    rule_name = data.get('rule_name')
    url_pattern = data.get('url_pattern')
    title_xpath = data.get('title_xpath')
    content_xpath = data.get('content_xpath')
    request_headers = parse_headers_to_json(data.get('request_headers'))
    
    if not rule_name or not url_pattern:
        return jsonify({'error': 'Missing required fields'}), 400
        
    domain = extract_domain(url_pattern)
    
    conn = get_db_connection()
    try:
        conn.execute('''
            UPDATE crawling_rules 
            SET rule_name = ?, domain = ?, url_pattern = ?, title_xpath = ?, content_xpath = ?, request_headers = ?
            WHERE id = ?
        ''', (rule_name, domain, url_pattern, title_xpath, content_xpath, request_headers, rule_id))
        conn.commit()
        return jsonify({'message': 'Rule updated successfully'})
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/rules/delete/<int:rule_id>', methods=['POST'])
def delete_rule(rule_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
        
    conn = get_db_connection()
    try:
        conn.execute('DELETE FROM crawling_rules WHERE id = ?', (rule_id,))
        conn.commit()
        return jsonify({'message': 'Rule deleted successfully'})
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/rules/copy/<int:rule_id>', methods=['POST'])
def copy_rule(rule_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
        
    conn = get_db_connection()
    try:
        rule = conn.execute('SELECT * FROM crawling_rules WHERE id = ?', (rule_id,)).fetchone()
        if not rule:
            return jsonify({'error': 'Rule not found'}), 404
            
        new_rule_name = f"{rule['rule_name']} (副本)"
        
        conn.execute('''
            INSERT INTO crawling_rules (rule_name, domain, url_pattern, title_xpath, content_xpath, request_headers)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (new_rule_name, rule['domain'], rule['url_pattern'], rule['title_xpath'], rule['content_xpath'], rule['request_headers']))
        conn.commit()
        return jsonify({'message': 'Rule copied successfully'})
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

def run_deep_crawl_task(task_id, items):
    """
    Background task to perform deep crawling.
    """
    task = crawl_tasks[task_id]
    conn = get_db_connection()
    
    try:
        total = len(items)
        for idx, item in enumerate(items):
            task['current'] = idx + 1
            task['status'] = 'running'
            
            url = item['url']
            domain = extract_domain(url)
            
            # Find rule
            rule = conn.execute('SELECT * FROM crawling_rules WHERE domain = ?', (domain,)).fetchone()
            
            if not rule:
                task['logs'].append(f"跳过: {url} (未找到匹配规则)")
                task['failed'] += 1
                continue
                
            # Check if already crawled (optional, but good for idempotency)
            # For now, we allow re-crawling
            
            # Crawl
            result = deep_crawler.fetch_content(url, dict(rule))
            
            if result['success']:
                try:
                    # Save to content_details
                    # Use INSERT OR REPLACE to update if exists
                    conn.execute('''
                        INSERT OR REPLACE INTO content_details (source_url, title, content, html_content, rule_id)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (url, result['title'], result['content'], result['html_content'], rule['id']))
                    conn.commit()
                    
                    task['logs'].append(f"成功: {url}")
                    task['success'] += 1
                except Exception as e:
                    task['logs'].append(f"保存失败: {url} ({str(e)})")
                    task['failed'] += 1
            else:
                task['logs'].append(f"采集失败: {url} ({result.get('error')})")
                task['failed'] += 1
            
            # Update progress percentage
            # task['progress'] = int((task['current'] / total) * 100)
            
    except Exception as e:
        task['logs'].append(f"任务异常中止: {str(e)}")
        task['status'] = 'error'
    finally:
        conn.close()
        task['status'] = 'completed'

@app.route('/crawl/start', methods=['POST'])
def start_crawl():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
        
    data = request.get_json()
    ids = data.get('ids', [])
    
    if not ids:
        return jsonify({'error': 'No items selected'}), 400
        
    conn = get_db_connection()
    # Fetch URLs for these IDs
    placeholders = ','.join('?' for _ in ids)
    items = conn.execute(f'SELECT id, url, title FROM crawled_data WHERE id IN ({placeholders})', ids).fetchall()
    conn.close()
    
    items = [dict(item) for item in items]
    
    task_id = str(uuid.uuid4())
    crawl_tasks[task_id] = {
        'id': task_id,
        'total': len(items),
        'current': 0,
        'success': 0,
        'failed': 0,
        'status': 'pending',
        'logs': [],
        'created_at': time.time()
    }
    
    # Start background thread
    thread = threading.Thread(target=run_deep_crawl_task, args=(task_id, items))
    thread.start()
    
    return jsonify({'task_id': task_id, 'message': 'Task started'})

@app.route('/crawl/status/<task_id>')
def get_crawl_status(task_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
        
    task = crawl_tasks.get(task_id)
    if not task:
        return jsonify({'error': 'Task not found'}), 404
        
    return jsonify(task)

@app.route('/content_details')
def content_details():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    
    page = request.args.get('page', 1, type=int)
    keyword = request.args.get('keyword', '', type=str)
    per_page = 20
    offset = (page - 1) * per_page
    
    conn = get_db_connection()
    
    where_clause = ""
    params = []
    if keyword:
        where_clause = "WHERE title LIKE ? OR source_url LIKE ?"
        params = [f'%{keyword}%', f'%{keyword}%']
        
    count_query = f"SELECT COUNT(*) FROM content_details {where_clause}"
    total = conn.execute(count_query, params).fetchone()[0]
    
    query = f"SELECT * FROM content_details {where_clause} ORDER BY crawled_at DESC LIMIT ? OFFSET ?"
    params.extend([per_page, offset])
    
    items = conn.execute(query, params).fetchall()
    conn.close()
    
    return render_template('content_details.html', items=items, total=total, page=page, per_page=per_page, total_pages=(total + per_page - 1) // per_page, username=session.get('username'))

@app.route('/content_details/get/<int:id>')
def get_content_detail(id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
        
    conn = get_db_connection()
    item = conn.execute('SELECT * FROM content_details WHERE id = ?', (id,)).fetchone()
    conn.close()
    
    if item:
        return jsonify(dict(item))
    else:
        return jsonify({'error': 'Item not found'}), 404

@app.route('/content_details/update/<int:id>', methods=['POST'])
def update_content_detail(id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
        
    data = request.get_json()
    title = data.get('title')
    content = data.get('content')
    
    conn = get_db_connection()
    try:
        conn.execute('UPDATE content_details SET title = ?, content = ? WHERE id = ?', (title, content, id))
        conn.commit()
        return jsonify({'message': 'Updated successfully'})
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/content_details/delete/<int:id>', methods=['POST'])
def delete_content_detail(id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
        
    conn = get_db_connection()
    try:
        conn.execute('DELETE FROM content_details WHERE id = ?', (id,))
        conn.commit()
        return jsonify({'message': 'Deleted successfully'})
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

# AI Model Management Routes

@app.route('/ai_models')
def ai_models_index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    models = conn.execute('SELECT * FROM ai_models ORDER BY created_at DESC').fetchall()
    conn.close()
    return render_template('ai_models.html', models=[dict(m) for m in models], username=session.get('username'))

@app.route('/ai_models/add', methods=['POST'])
def add_ai_model():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
        
    data = request.get_json()
    conn = get_db_connection()
    try:
        conn.execute('INSERT INTO ai_models (name, provider, api_base, api_key, model_name) VALUES (?, ?, ?, ?, ?)',
                     (data['name'], data['provider'], data['api_base'], data['api_key'], data['model_name']))
        conn.commit()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})
    finally:
        conn.close()

@app.route('/ai_models/get/<int:id>')
def get_ai_model(id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = get_db_connection()
    model = conn.execute('SELECT * FROM ai_models WHERE id = ?', (id,)).fetchone()
    conn.close()
    
    if model:
        return jsonify(dict(model))
    return jsonify({'error': 'Not found'}), 404

@app.route('/ai_models/update/<int:id>', methods=['POST'])
def update_ai_model(id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
        
    data = request.get_json()
    conn = get_db_connection()
    try:
        conn.execute('''
            UPDATE ai_models 
            SET name=?, provider=?, api_base=?, api_key=?, model_name=?
            WHERE id=?
        ''', (data['name'], data['provider'], data['api_base'], data['api_key'], data['model_name'], id))
        conn.commit()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})
    finally:
        conn.close()

@app.route('/ai_models/delete/<int:id>', methods=['POST'])
def delete_ai_model(id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = get_db_connection()
    conn.execute('DELETE FROM ai_models WHERE id = ?', (id,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/ai_models/stats')
def ai_model_stats():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = get_db_connection()
    # Calculate total tokens
    result = conn.execute('SELECT SUM(tokens_used) as total FROM token_consumption').fetchone()
    total = result['total'] if result and result['total'] else 0
    conn.close()
    return jsonify({'total_tokens': total})

@app.route('/ai_models/test_sse')
def test_ai_model_sse():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
        
    model_id = request.args.get('model_id')
    message = request.args.get('message')
    
    if not model_id or not message:
        return jsonify({'error': 'Missing parameters'}), 400
        
    conn = get_db_connection()
    model = conn.execute('SELECT * FROM ai_models WHERE id = ?', (model_id,)).fetchone()
    conn.close()
    
    if not model:
        return jsonify({'error': 'Model not found'}), 404
        
    def generate():
        try:
            api_base = model['api_base']
            # OpenAI client expects base_url without /chat/completions
            if api_base.endswith('/chat/completions'):
                api_base = api_base.replace('/chat/completions', '')
            if api_base.endswith('/'):
                api_base = api_base[:-1]
                
            client = OpenAI(
                api_key=model['api_key'],
                base_url=api_base,
                http_client=httpx.Client(verify=False)
            )
            
            stream = client.chat.completions.create(
                model=model['model_name'],
                messages=[
                    {"role": "user", "content": message}
                ],
                stream=True
            )

            collected_content = ""
            
            for chunk in stream:
                if chunk.choices:
                    delta = chunk.choices[0].delta
                    if delta.content:
                        content = delta.content
                        collected_content += content
                        yield f"data: {json.dumps({'content': content})}\n\n"
                            
            # Record Token Usage
            input_tokens = len(message) 
            output_tokens = len(collected_content)
            total_tokens = input_tokens + output_tokens 
            
            try:
                db = get_db_connection()
                db.execute('INSERT INTO token_consumption (model_id, tokens_used, request_type) VALUES (?, ?, ?)',
                          (model_id, total_tokens, 'chat_test'))
                db.commit()
                db.close()
            except Exception as e:
                print(f"Failed to save stats: {e}")
                
            yield f"data: {json.dumps({'done': True})}\n\n"
            
        except Exception as e:
            yield f"data: {json.dumps({'error': str(e)})}\n\n"

    return Response(stream_with_context(generate()), mimetype='text/event-stream')

@app.route('/ai_analysis')
def ai_analysis():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    models = conn.execute('SELECT * FROM ai_models WHERE is_active = 1').fetchall()
    conn.close()
    
    return render_template('ai_analysis.html', models=[dict(m) for m in models], username=session.get('username'))

@app.route('/ai_analysis/chat_stream')
def ai_analysis_chat_stream():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
        
    model_id = request.args.get('model_id')
    message = request.args.get('message')
    history = request.args.get('history')
    
    if not model_id or not message:
        return jsonify({'error': 'Missing parameters'}), 400
        
    conn = get_db_connection()
    model = conn.execute('SELECT * FROM ai_models WHERE id = ?', (model_id,)).fetchone()
    conn.close()
    
    if not model:
        return jsonify({'error': 'Model not found'}), 404
        
    model_config = {
        'api_base': model['api_base'],
        'api_key': model['api_key'],
        'model_name': model['model_name']
    }
    
    messages = []
    if history:
        try:
            messages = json.loads(history)
        except:
            pass
            
    messages.append({"role": "user", "content": message})
    
    return Response(stream_with_context(stream_chat_with_data(model_config, messages)), mimetype='text/event-stream')

# --- Data Screen Routes ---

@app.route('/data_screen')
def data_screen():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('data_screen.html')

@app.route('/api/screen/stats')
def screen_stats():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = get_db_connection()
    
    try:
        # Total count
        total = conn.execute('SELECT COUNT(*) FROM content_details').fetchone()[0]
        
        # Today count
        today = conn.execute("SELECT COUNT(*) FROM content_details WHERE date(crawled_at) = date('now')").fetchone()[0]
        
        # Risk count (using keyword match)
        risk_keywords = ['事故', '违规', '处罚', '危险', '警告', '风险', '通报', '整改', '灾害', '预警']
        risk_query = " OR ".join([f"title LIKE '%{k}%'" for k in risk_keywords])
        risk_count = conn.execute(f"SELECT COUNT(*) FROM content_details WHERE {risk_query}").fetchone()[0]
        
        # Classification (using search_keyword from crawled_data as category proxy)
        classification_rows = conn.execute('''
            SELECT search_keyword, COUNT(*) as count 
            FROM crawled_data 
            WHERE search_keyword IS NOT NULL AND search_keyword != ''
            GROUP BY search_keyword
            ORDER BY count DESC
            LIMIT 5
        ''').fetchall()
        
        classification = [{'name': row['search_keyword'], 'value': row['count']} for row in classification_rows]
        
        return jsonify({
            'total_count': total,
            'today_count': today,
            'risk_count': risk_count,
            'classification': classification
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/api/screen/risks')
def screen_risks():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
        
    conn = get_db_connection()
    try:
        risk_keywords = ['事故', '违规', '处罚', '危险', '警告', '风险', '通报', '整改']
        
        counts = []
        for k in risk_keywords:
            c = conn.execute(f"SELECT COUNT(*) FROM content_details WHERE title LIKE '%{k}%' OR content LIKE '%{k}%'").fetchone()[0]
            counts.append(c)
            
        return jsonify({'keywords': risk_keywords, 'counts': counts})
    finally:
        conn.close()

@app.route('/api/screen/latest')
def screen_latest():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
        
    conn = get_db_connection()
    try:
        rows = conn.execute('''
            SELECT title, source_url, crawled_at 
            FROM content_details 
            ORDER BY crawled_at DESC 
            LIMIT 20
        ''').fetchall()
        
        data = []
        for row in rows:
            # Extract source domain
            try:
                domain = urlparse(row['source_url']).netloc
            except:
                domain = 'Unknown'
                
            data.append({
                'title': row['title'],
                'source': domain,
                'date': row['crawled_at']
            })
            
        return jsonify({'data': data})
    finally:
        conn.close()

@app.route('/api/screen/keywords')
def screen_keywords():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
        
    conn = get_db_connection()
    try:
        # Get top 5 keywords first
        top_keywords_rows = conn.execute('''
            SELECT search_keyword 
            FROM crawled_data 
            WHERE search_keyword IS NOT NULL AND search_keyword != ''
            GROUP BY search_keyword 
            ORDER BY COUNT(*) DESC 
            LIMIT 5
        ''').fetchall()
        top_keywords = [r['search_keyword'] for r in top_keywords_rows]
        
        # Get dates
        dates_rows = conn.execute("SELECT DISTINCT date(created_at) as d FROM crawled_data ORDER BY d DESC LIMIT 7").fetchall()
        dates = [r['d'] for r in dates_rows][::-1] # reverse to be ascending
        
        series = []
        for kw in top_keywords:
            data_points = []
            for d in dates:
                count = conn.execute('''
                    SELECT COUNT(*) FROM crawled_data 
                    WHERE search_keyword = ? AND date(created_at) = ?
                ''', (kw, d)).fetchone()[0]
                data_points.append(count)
            series.append({'name': kw, 'data': data_points})
            
        return jsonify({'dates': dates, 'series': series})
    finally:
        conn.close()

@app.route('/api/screen/heatmap')
def screen_heatmap():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
        
    cities = ['北京', '上海', '广州', '深圳', '成都', '杭州', '武汉', '西安', '重庆', '南京', '天津', '郑州', '长沙', '沈阳', '青岛', '济南', '大连', '厦门', '宁波', '哈尔滨', '长春', '石家庄', '合肥', '福州', '南昌', '昆明', '贵阳', '兰州', '南宁', '海口', '太原', '呼和浩特', '乌鲁木齐', '拉萨', '西宁', '银川']
    
    conn = get_db_connection()
    try:
        # Efficient way: fetch all titles and do python counting to avoid 30+ SQL queries
        rows = conn.execute("SELECT title, content FROM content_details ORDER BY crawled_at DESC LIMIT 1000").fetchall()
        
        city_counts = {c: 0 for c in cities}
        
        for row in rows:
            text = (row['title'] or '') + (row['content'] or '')
            for city in cities:
                if city in text:
                    city_counts[city] += 1
                    
        result = [{'name': c, 'value': v} for c, v in city_counts.items() if v > 0]
        return jsonify(result)
    finally:
        conn.close()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
