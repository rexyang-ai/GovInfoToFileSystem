from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, Response, stream_with_context
from openai import OpenAI
import httpx
from app.analysis_agent import stream_chat_with_data, calculate_tokens
from app.crawler_manager import CrawlerManager
from app.database.db import get_db_connection
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
import subprocess
import sys
import csv
import io

# 全局字典用于存储采集任务
crawl_tasks = {}
# 嗅探器信号，用于前端轮询状态更新
sniffer_signal = {'ts': 0}
executor = concurrent.futures.ThreadPoolExecutor(max_workers=5)

def search_task_runner(task_id, selected_sources, keyword, max_pages, max_items):
    """
    后台任务：运行采集器并更新进度。
    """
    try:
        crawl_tasks[task_id]['status'] = 'running'
        results = []
        
        # 辅助函数：更新进度
        def progress_callback(current_count, limit_items, current_page, limit_pages):
            # 此回调来自单个源的执行。
            # 由于我们可能并行运行多个源，这个简单的回调
            # 如果不小心可能会覆盖其他源的进度。
            # 目前，我们只是汇总结果或更新“最后活动”。
            # 更好的方法：在任务对象中累加计数。
            # 但 execute_source_with_config 在此线程（如果是顺序执行）
            # 或子线程（如果是并行执行）中运行。
            
            # 如果我们在后台任务中顺序运行源：
            crawl_tasks[task_id]['progress'] = f"正在采集... (当前页: {current_page}/{limit_pages}, 已采集: {len(results) + current_count})"
            crawl_tasks[task_id]['current_count'] = len(results) + current_count
            # 注意：此计数略有偏差，因为 'results' 来自之前的源，
            # 而 'current_count' 来自当前源。
            pass

        # 我们需要一种方法来聚合进度（如果我们运行多个源）。
        # 为了简单起见，让我们在这个后台线程中顺序运行源，
        # 这样我们可以准确地报告进度。
        
        conn = get_db_connection()
        crawler_manager = CrawlerManager(None) # 如果我们传递配置，execute_source_with_config 不需要连接
        
        total_sources = len(selected_sources)
        
        for idx, source_id in enumerate(selected_sources):
            source_row = conn.execute("SELECT * FROM crawl_sources WHERE id = ?", (source_id,)).fetchone()
            if not source_row:
                continue
                
            source_config = dict(source_row)
            source_name = source_config.get('name', 'Unknown')
            
            crawl_tasks[task_id]['progress'] = f"正在采集 [{source_name}] ({idx+1}/{total_sources})..."
            
            # 为此源定义特定的回调以更新全局任务状态
            def specific_callback(curr_c, max_c, curr_p, max_p, current_results=None):
                total_so_far = len(results) + curr_c
                crawl_tasks[task_id]['current_count'] = total_so_far
                crawl_tasks[task_id]['progress'] = f"正在采集 [{source_name}] ({idx+1}/{total_sources}): 第 {curr_p}/{max_p} 页, 累计 {total_so_far} 条"
                if current_results:
                     crawl_tasks[task_id]['results'] = results + current_results
            
            # 运行采集器
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
    将请求头字符串（JSON 或原始文本）解析为 JSON 字符串。
    支持从浏览器开发者工具直接复制粘贴（Key: Value 或 Key:\\nValue）。
    """
    if not header_str:
        return "{}"
    
    header_str = header_str.strip()
    
    # 1. 首先尝试解析为 JSON
    try:
        # 如果已经是 JSON，确保它是字典
        parsed = json.loads(header_str)
        if isinstance(parsed, dict):
            return json.dumps(parsed) 
    except:
        pass
        
    # 2. 解析为原始文本
    headers = {}
    lines = header_str.split('\n')
    current_key = None
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
            
        if line.endswith(':'):
             # 情况："Key:" 在一行，值在下一行
             current_key = line[:-1].strip()
        elif ':' in line:
             # 情况："Key: Value" 在同一行
             # 如果我们有一个待处理的 current_key，这意味着上一个键没有值或是格式错误的。
             # 我们暂时覆盖/忽略上一个键，或者假设为空字符串？
             # 让我们假设如果我们看到新的 Key: Value，上一个待处理的键已完成。
             
             # 处理 "Key: Value"
             parts = line.split(':', 1)
             key = parts[0].strip()
             value = parts[1].strip()
             headers[key] = value
             current_key = None 
        else:
             # 没有冒号。必须是 current_key 的值
             if current_key:
                 headers[current_key] = line
                 current_key = None
             else:
                 # 没有当前键？跳过或处理特定情况
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
app.secret_key = 'super_secret_key_for_demo_only'  # 生产环境请修改

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
        
    # 创建任务
    task_id = str(uuid.uuid4())
    crawl_tasks[task_id] = {
        'status': 'initializing',
        'progress': '正在初始化...',
        'current_count': 0,
        'total_planned': max_items,
        'results': []
    }
    
    # 启动后台任务
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
    
    # 我们将遍历项目并尝试逐个保存。
    # 为了避免部分失败阻塞其他项目，我们在循环内部使用 try/except。
    # 注意：SQLite 事务行为。如果我们想要部分成功，我们可以在最后提交，
    # 但如果发生错误（如唯一约束），我们应该处理它。
    # 因为我们先检查是否存在，所以除非有竞争条件，否则 URL 上的唯一约束不应触发。
    
    try:
        for item in items:
            try:
                url = item.get('url')
                if not url:
                    continue
                    
                # 检查是否存在
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
                # 继续处理下一个项目
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
    
    # 基础查询
    where_clause = " WHERE 1=1"
    params = []
    
    if keyword:
        where_clause += " AND (title LIKE ? OR summary LIKE ? OR search_keyword LIKE ?)"
        params.extend([f'%{keyword}%', f'%{keyword}%', f'%{keyword}%'])
        
    if date_filter:
        where_clause += " AND date(datetime(created_at,'localtime')) = ?"
        params.append(date_filter)
        
    conn = get_db_connection()
    
    # 统计总数
    count_query = "SELECT COUNT(*) FROM crawled_data" + where_clause
    total = conn.execute(count_query, params).fetchone()[0]
    
    # 获取分页数据
    query = "SELECT id, title, url, summary, cover_url, search_keyword, datetime(created_at,'localtime') AS created_at FROM crawled_data" + where_clause + " ORDER BY created_at DESC LIMIT ? OFFSET ?"
    params.extend([per_page, offset])
    rows = conn.execute(query, params).fetchall()
    urls = [row['url'] for row in rows]
    deep_set = set()
    if urls:
        placeholders = ','.join('?' for _ in urls)
        deep_rows = conn.execute(f'SELECT source_url FROM content_details WHERE source_url IN ({placeholders})', urls).fetchall()
        deep_set = set(dr['source_url'] for dr in deep_rows)
    
    items = []
    for row in rows:
        item = dict(row)
        domain = extract_domain(item['url'])
        rule = conn.execute('SELECT rule_name FROM crawling_rules WHERE domain = ?', (domain,)).fetchone()
        item['rule_name'] = rule['rule_name'] if rule else None
        item['has_rules'] = True if rule else False
        item['is_deep_crawled'] = item['url'] in deep_set
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
        
    # 尝试查找匹配的请求头源
    conn = get_db_connection()
    sources = conn.execute("SELECT url, headers FROM crawl_sources").fetchall()
    conn.close()
    
    target_domain = extract_domain(url)
    custom_headers = None
    matched_source_url = None
    
    for s in sources:
        s_url = s['url']
        s_domain = extract_domain(s_url)
        # 检查域名是否匹配（完全匹配或子域名）
        if target_domain == s_domain or target_domain.endswith('.' + s_domain) or s_domain.endswith('.' + target_domain):
             if s['headers']:
                 custom_headers = s['headers']
                 matched_source_url = s_url
                 break
    
    # 1. 嗅探页面
    result, error = sniffer.sniff_page(url, custom_headers)
    
    if error:
        return jsonify({'error': error}), 500
        
    # 2. 返回数据以供确认（尚未保存）
    # 如果可用，使用嗅探结果中的 final_url（处理重定向）
    final_url = result.get('final_url', url)
    domain = extract_domain(final_url)
    
    result['domain'] = domain
    result['rule_name'] = f"规则_{domain}"
    if matched_source_url:
         result['matched_source'] = matched_source_url
    
    return jsonify({'message': '嗅探成功', 'data': result})

@app.route('/rule/save', methods=['POST'])
def save_rule():
    # 允许会话验证或内部 Token 验证
    is_auth = 'user_id' in session
    if not is_auth:
        token = request.headers.get('X-Internal-Token')
        if token == 'sniffer-secret-123':
            is_auth = True
            
    if not is_auth:
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
        # 检查此域名是否存在规则
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

    query = f"SELECT id, rule_name, domain, url_pattern, title_xpath, content_xpath, request_headers, datetime(created_at,'localtime') AS created_at FROM crawling_rules {where_clause} ORDER BY created_at DESC LIMIT ? OFFSET ?"
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
    publish_time_xpath = data.get('publish_time_xpath')
    source_xpath = data.get('source_xpath')
    request_headers = parse_headers_to_json(data.get('request_headers'))
    
    if not rule_name or not url_pattern:
        return jsonify({'error': 'Missing required fields'}), 400
        
    domain = extract_domain(url_pattern)
    
    conn = get_db_connection()
    try:
        conn.execute('''
            INSERT INTO crawling_rules (rule_name, domain, url_pattern, title_xpath, content_xpath, publish_time_xpath, source_xpath, request_headers)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (rule_name, domain, url_pattern, title_xpath, content_xpath, publish_time_xpath, source_xpath, request_headers))
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
    publish_time_xpath = data.get('publish_time_xpath')
    source_xpath = data.get('source_xpath')
    request_headers = parse_headers_to_json(data.get('request_headers'))
    
    if not rule_name or not url_pattern:
        return jsonify({'error': 'Missing required fields'}), 400
        
    domain = extract_domain(url_pattern)
    
    conn = get_db_connection()
    try:
        conn.execute('''
            UPDATE crawling_rules 
            SET rule_name = ?, domain = ?, url_pattern = ?, title_xpath = ?, content_xpath = ?, publish_time_xpath = ?, source_xpath = ?, request_headers = ?
            WHERE id = ?
        ''', (rule_name, domain, url_pattern, title_xpath, content_xpath, publish_time_xpath, source_xpath, request_headers, rule_id))
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
            INSERT INTO crawling_rules (rule_name, domain, url_pattern, title_xpath, content_xpath, publish_time_xpath, source_xpath, request_headers)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (new_rule_name, rule['domain'], rule['url_pattern'], rule['title_xpath'], rule['content_xpath'], rule.get('publish_time_xpath'), rule.get('source_xpath'), rule['request_headers']))
        conn.commit()
        return jsonify({'message': 'Rule copied successfully'})
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

def run_deep_crawl_task(task_id, items):
    """
    后台任务：执行深度采集。
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
            
            # 查找规则
            rule = conn.execute('SELECT * FROM crawling_rules WHERE domain = ?', (domain,)).fetchone()
            
            if not rule:
                task['logs'].append(f"跳过: {url} (未找到匹配规则)")
                task['failed'] += 1
                continue
                
            # 检查是否已采集（可选，但有利于幂等性）
            # 目前，我们允许重新采集
            
            # 采集
            result = deep_crawler.fetch_content(url, dict(rule))
            
            if result['success']:
                try:
                    # 保存到 content_details
                    # 使用 INSERT OR REPLACE 更新（如果存在）
                    conn.execute('''
                        INSERT OR REPLACE INTO content_details (source_url, title, content, html_content, publish_time, source, rule_id)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''', (url, result['title'], result['content'], result['html_content'], result.get('publish_time'), result.get('source'), rule['id']))
                    conn.commit()
                    
                    task['logs'].append(f"成功: {url}")
                    task['success'] += 1
                except Exception as e:
                    task['logs'].append(f"保存失败: {url} ({str(e)})")
                    task['failed'] += 1
            else:
                task['logs'].append(f"采集失败: {url} ({result.get('error')})")
                task['failed'] += 1
            
            # 更新进度百分比

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
    # 获取这些 ID 的 URL
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
    
    # 启动后台线程
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
    
    query = f"SELECT id, title, source_url, content, html_content, publish_time, source, datetime(crawled_at,'localtime') AS crawled_at FROM content_details {where_clause} ORDER BY crawled_at DESC LIMIT ? OFFSET ?"
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

@app.route('/content_details/export')
def export_content_details():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    keyword = request.args.get('keyword', '')
    
    def generate():
        conn = get_db_connection()
        try:
            where_clause = ""
            params = []
            
            if keyword:
                where_clause = "WHERE title LIKE ? OR source_url LIKE ?"
                params = [f'%{keyword}%', f'%{keyword}%']
                
            query = f"SELECT id, title, source_url, content, publish_time, source, datetime(crawled_at,'localtime') AS crawled_at FROM content_details {where_clause} ORDER BY crawled_at DESC"
            
            cursor = conn.execute(query, params)
            
            data = io.StringIO()
            w = csv.writer(data)
            
            # 写入表头（带 BOM 以兼容 Excel）
            data.write('\ufeff')
            w.writerow(('ID', '标题', '源链接', '发布时间', '来源', '采集时间', '内容'))
            yield data.getvalue()
            data.seek(0)
            data.truncate(0)
            
            for row in cursor:
                w.writerow((row['id'], row['title'], row['source_url'], row['publish_time'], row['source'], row['crawled_at'], row['content']))
                yield data.getvalue()
                data.seek(0)
                data.truncate(0)
        finally:
            conn.close()
            
    return Response(stream_with_context(generate()), mimetype='text/csv', 
                    headers={"Content-Disposition": f"attachment; filename=content_details_export_{int(time.time())}.csv"})

# AI 模型管理路由

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
    # 计算总 Token
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
            # OpenAI 客户端期望 base_url 不带 /chat/completions
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
                            
            # 记录 Token 使用情况
            input_tokens = calculate_tokens(message) 
            output_tokens = calculate_tokens(collected_content)
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

def stream_chat_wrapper(model_config, messages, conversation_id, user_message_content, model_id):
    conn = get_db_connection()
    
    # 保存用户消息
    conn.execute('INSERT INTO ai_messages (conversation_id, role, content) VALUES (?, ?, ?)',
                 (conversation_id, 'user', user_message_content))
    conn.commit()
    conn.close()
    
    # 辅助变量：用于稍后保存助手消息
    full_content = []
    chart_options = None
    
    try:
        # 我们需要从原始生成器 yield
        for chunk in stream_chat_with_data(model_config, messages):
            yield chunk
            # 解析分块以进行累积
            if chunk.startswith("data: "):
                try:
                    data = json.loads(chunk[6:])
                    if data['type'] == 'content':
                        full_content.append(data['content'])
                    elif data['type'] == 'chart':
                        chart_options = data['options']
                    elif data['type'] == 'usage':
                        # 保存 Token 使用情况
                        input_tokens = data.get('input_tokens', 0)
                        output_tokens = data.get('output_tokens', 0)
                        total_tokens = input_tokens + output_tokens
                        
                        try:
                            db = get_db_connection()
                            db.execute('INSERT INTO token_consumption (model_id, tokens_used, request_type) VALUES (?, ?, ?)',
                                      (model_id, total_tokens, 'analysis_chat'))
                            db.commit()
                            db.close()
                        except Exception as e:
                            print(f"Failed to save token stats: {e}")
                except:
                    pass
    except Exception as e:
        yield f"data: {json.dumps({'type': 'error', 'content': str(e)})}\n\n"
    finally:
        # 保存助手消息
        conn = get_db_connection()
        final_content = "".join(full_content)
        meta_info = json.dumps({'chart_options': chart_options}) if chart_options else None
        
        if final_content or meta_info:
            conn.execute('INSERT INTO ai_messages (conversation_id, role, content, meta_info) VALUES (?, ?, ?, ?)',
                        (conversation_id, 'assistant', final_content, meta_info))
            
            # 更新对话时间戳
            conn.execute('UPDATE ai_conversations SET updated_at = CURRENT_TIMESTAMP WHERE id = ?', (conversation_id,))
            conn.commit()
        conn.close()

@app.route('/ai_analysis/chat_stream')
def ai_analysis_chat_stream():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
        
    model_id = request.args.get('model_id')
    message = request.args.get('message')
    conversation_id = request.args.get('conversation_id')
    
    if not model_id or not message:
        return jsonify({'error': 'Missing parameters'}), 400
        
    conn = get_db_connection()
    model = conn.execute('SELECT * FROM ai_models WHERE id = ?', (model_id,)).fetchone()
    
    if not model:
        conn.close()
        return jsonify({'error': 'Model not found'}), 404
        
    model_config = {
        'api_base': model['api_base'],
        'api_key': model['api_key'],
        'model_name': model['model_name']
    }
    
    messages = []
    # 如果提供了 conversation_id，则加载历史记录
    if conversation_id and conversation_id != 'null':
        rows = conn.execute('SELECT role, content FROM ai_messages WHERE conversation_id = ? ORDER BY id ASC', (conversation_id,)).fetchall()
        for row in rows:
            # 我们跳过工具调用以节省 LLM 上下文 Token，或者如果需要可以包含它们。
            # 目前，采用简单的方法：
            messages.append({"role": row['role'], "content": row['content'] or ""})
    else:
        # 创建新对话
        cur = conn.execute('INSERT INTO ai_conversations (user_id, title, model_id) VALUES (?, ?, ?)',
                           (session['user_id'], message[:20], model_id))
        conversation_id = cur.lastrowid
        conn.commit()
    
    conn.close()
            
    messages.append({"role": "user", "content": message})
    
    return Response(stream_with_context(stream_chat_wrapper(model_config, messages, conversation_id, message, model_id)), mimetype='text/event-stream')

@app.route('/api/ai/conversations', methods=['GET', 'POST'])
def ai_conversations():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = get_db_connection()
    if request.method == 'GET':
        rows = conn.execute('''
            SELECT id, title, model_id, datetime(created_at, 'localtime') as created_at 
            FROM ai_conversations 
            WHERE user_id = ? 
            ORDER BY updated_at DESC
        ''', (session['user_id'],)).fetchall()
        conn.close()
        return jsonify([dict(row) for row in rows])
        
    elif request.method == 'POST':
        data = request.get_json() or {}
        title = data.get('title', 'New Chat')
        model_id = data.get('model_id')
        
        cur = conn.execute('INSERT INTO ai_conversations (user_id, title, model_id) VALUES (?, ?, ?)',
                           (session['user_id'], title, model_id))
        conn.commit()
        new_id = cur.lastrowid
        conn.close()
        return jsonify({'id': new_id})

@app.route('/api/ai/conversations/<int:id>', methods=['DELETE', 'PATCH'])
def ai_conversation_item(id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
        
    conn = get_db_connection()
    if request.method == 'DELETE':
        conn.execute('DELETE FROM ai_conversations WHERE id = ? AND user_id = ?', (id, session['user_id']))
        conn.commit()
        conn.close()
        return jsonify({'success': True})
        
    elif request.method == 'PATCH':
        data = request.get_json() or {}
        title = data.get('title')
        if title:
            conn.execute('UPDATE ai_conversations SET title = ? WHERE id = ? AND user_id = ?', 
                         (title, id, session['user_id']))
            conn.commit()
        conn.close()
        return jsonify({'success': True})

@app.route('/api/ai/conversations/<int:id>/messages')
def ai_conversation_messages(id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
        
    conn = get_db_connection()
    # 验证所有权
    conv = conn.execute('SELECT * FROM ai_conversations WHERE id = ? AND user_id = ?', (id, session['user_id'])).fetchone()
    if not conv:
        conn.close()
        return jsonify({'error': 'Not found'}), 404
        
    rows = conn.execute('''
        SELECT id, role, content, meta_info, datetime(created_at, 'localtime') as created_at 
        FROM ai_messages 
        WHERE conversation_id = ? 
        ORDER BY id ASC
    ''', (id,)).fetchall()
    conn.close()
    
    return jsonify([dict(row) for row in rows])

# --- 数据大屏路由 ---

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
        # 总数
        total = conn.execute('SELECT COUNT(*) FROM content_details').fetchone()[0]
        
        # 今日计数
        today = conn.execute("SELECT COUNT(*) FROM content_details WHERE date(crawled_at) = date('now')").fetchone()[0]
        
        # 风险计数（使用关键字匹配）
        risk_keywords = ['事故', '违规', '处罚', '危险', '警告', '风险', '通报', '整改', '灾害', '预警']
        risk_query = " OR ".join([f"title LIKE '%{k}%'" for k in risk_keywords])
        risk_count = conn.execute(f"SELECT COUNT(*) FROM content_details WHERE {risk_query}").fetchone()[0]
        
        # 分类（使用 crawled_data 中的 search_keyword 作为分类代理）
        # 优化：将组合关键词（空格分隔）拆分后再统计
        all_keywords_rows = conn.execute('''
            SELECT search_keyword 
            FROM crawled_data 
            WHERE search_keyword IS NOT NULL AND search_keyword != ''
        ''').fetchall()
        
        keyword_counts = {}
        for row in all_keywords_rows:
            # 拆分关键词，支持空格、逗号等常见分隔符
            raw_kw = row['search_keyword']
            # 统一替换分隔符为空格
            normalized_kw = raw_kw.replace(',', ' ').replace('，', ' ').replace('、', ' ')
            # 拆分并去除空白
            parts = [p.strip() for p in normalized_kw.split() if p.strip()]
            
            for part in parts:
                keyword_counts[part] = keyword_counts.get(part, 0) + 1
        
        # 排序并取前 5
        sorted_keywords = sorted(keyword_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        
        classification = [{'name': k, 'value': v} for k, v in sorted_keywords]
        
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
            # 提取源域名
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
        # 获取所有数据进行Python处理（因为需要拆分关键词）
        all_rows = conn.execute('''
            SELECT search_keyword, date(created_at) as d
            FROM crawled_data 
            WHERE search_keyword IS NOT NULL AND search_keyword != ''
        ''').fetchall()
        
        global_counts = {}
        daily_counts = {} # Key: (keyword, date), Value: count
        
        # 收集所有日期用于排序
        all_dates_set = set()
        
        for row in all_rows:
            raw_kw = row['search_keyword']
            date_str = row['d']
            
            if date_str:
                all_dates_set.add(date_str)
            
            # 拆分关键词
            normalized_kw = raw_kw.replace(',', ' ').replace('，', ' ').replace('、', ' ')
            parts = [p.strip() for p in normalized_kw.split() if p.strip()]
            
            for part in parts:
                # 全局计数
                global_counts[part] = global_counts.get(part, 0) + 1
                
                #每日计数
                if date_str:
                    key = (part, date_str)
                    daily_counts[key] = daily_counts.get(key, 0) + 1
        
        # 获取前 5 个热门关键字
        sorted_keywords = sorted(global_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        top_keywords = [k for k, v in sorted_keywords]
        
        # 获取最近 7 天的日期
        dates = sorted(list(all_dates_set))[-7:]
        
        series = []
        for kw in top_keywords:
            data_points = []
            for d in dates:
                count = daily_counts.get((kw, d), 0)
                data_points.append(count)
            series.append({'name': kw, 'data': data_points})
            
        return jsonify({'dates': dates, 'series': series})
    finally:
        conn.close()

@app.route('/api/screen/heatmap')
def screen_heatmap():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
        
    # 定义省份-城市映射关系
    province_city_map = {
        '北京': ['北京'], '天津': ['天津'], '上海': ['上海'], '重庆': ['重庆'],
        '河北': ['石家庄', '唐山', '秦皇岛', '邯郸', '邢台', '保定', '张家口', '承德', '沧州', '廊坊', '衡水'],
        '山西': ['太原', '大同', '阳泉', '长治', '晋城', '朔州', '晋中', '运城', '忻州', '临汾', '吕梁'],
        '内蒙古': ['呼和浩特', '包头', '乌海', '赤峰', '通辽', '鄂尔多斯', '呼伦贝尔', '巴彦淖尔', '乌兰察布'],
        '辽宁': ['沈阳', '大连', '鞍山', '抚顺', '本溪', '丹东', '锦州', '营口', '阜新', '辽阳', '盘锦', '铁岭', '朝阳', '葫芦岛'],
        '吉林': ['长春', '吉林', '四平', '辽源', '通化', '白山', '松原', '白城', '延边'],
        '黑龙江': ['哈尔滨', '齐齐哈尔', '鸡西', '鹤岗', '双鸭山', '大庆', '伊春', '佳木斯', '七台河', '牡丹江', '黑河', '绥化'],
        '江苏': ['南京', '无锡', '徐州', '常州', '苏州', '南通', '连云港', '淮安', '盐城', '扬州', '镇江', '泰州', '宿迁'],
        '浙江': ['杭州', '宁波', '温州', '嘉兴', '湖州', '绍兴', '金华', '衢州', '舟山', '台州', '丽水'],
        '安徽': ['合肥', '芜湖', '蚌埠', '淮南', '马鞍山', '淮北', '铜陵', '安庆', '黄山', '滁州', '阜阳', '宿州', '六安', '亳州', '池州', '宣城'],
        '福建': ['福州', '厦门', '莆田', '三明', '泉州', '漳州', '南平', '龙岩', '宁德'],
        '江西': ['南昌', '景德镇', '萍乡', '九江', '新余', '鹰潭', '赣州', '吉安', '宜春', '抚州', '上饶'],
        '山东': ['济南', '青岛', '淄博', '枣庄', '东营', '烟台', '潍坊', '济宁', '泰安', '威海', '日照', '临沂', '德州', '聊城', '滨州', '菏泽'],
        '河南': ['郑州', '开封', '洛阳', '平顶山', '安阳', '鹤壁', '新乡', '焦作', '濮阳', '许昌', '漯河', '三门峡', '南阳', '商丘', '信阳', '周口', '驻马店'],
        '湖北': ['武汉', '黄石', '十堰', '宜昌', '襄阳', '鄂州', '荆门', '孝感', '荆州', '黄冈', '咸宁', '随州', '恩施'],
        '湖南': ['长沙', '株洲', '湘潭', '衡阳', '邵阳', '岳阳', '常德', '张家界', '益阳', '郴州', '永州', '怀化', '娄底', '湘西'],
        '广东': ['广州', '韶关', '深圳', '珠海', '汕头', '佛山', '江门', '湛江', '茂名', '肇庆', '惠州', '梅州', '汕尾', '河源', '阳江', '清远', '东莞', '中山', '潮州', '揭阳', '云浮'],
        '广西': ['南宁', '柳州', '桂林', '梧州', '北海', '防城港', '钦州', '贵港', '玉林', '百色', '贺州', '河池', '来宾', '崇左'],
        '海南': ['海口', '三亚', '三沙', '儋州'],
        '四川': ['成都', '自贡', '攀枝花', '泸州', '德阳', '绵阳', '广元', '遂宁', '内江', '乐山', '南充', '眉山', '宜宾', '广安', '达州', '雅安', '巴中', '资阳', '阿坝', '甘孜', '凉山'],
        '贵州': ['贵阳', '六盘水', '遵义', '安顺', '毕节', '铜仁', '黔西南', '黔东南', '黔南'],
        '云南': ['昆明', '曲靖', '玉溪', '保山', '昭通', '丽江', '普洱', '临沧', '楚雄', '红河', '文山', '西双版纳', '大理', '德宏', '怒江', '迪庆'],
        '西藏': ['拉萨', '日喀则', '昌都', '林芝', '山南', '那曲', '阿里'],
        '陕西': ['西安', '铜川', '宝鸡', '咸阳', '渭南', '延安', '汉中', '榆林', '安康', '商洛'],
        '甘肃': ['兰州', '嘉峪关', '金昌', '白银', '天水', '武威', '张掖', '平凉', '酒泉', '庆阳', '定西', '陇南', '临夏', '甘南'],
        '青海': ['西宁', '海东', '海北', '黄南', '海南', '果洛', '玉树', '海西'],
        '宁夏': ['银川', '石嘴山', '吴忠', '固原', '中卫'],
        '新疆': ['乌鲁木齐', '克拉玛依', '吐鲁番', '哈密', '昌吉', '博尔塔拉', '巴音郭楞', '阿克苏', '克孜勒苏', '喀什', '和田', '伊犁', '塔城', '阿勒泰'],
        '台湾': ['台北', '高雄', '台南', '台中'],
        '香港': ['香港'],
        '澳门': ['澳门']
    }
    
    # 映射标准省份名称以匹配地图 GeoJSON
    standard_names = {
        '北京': '北京市', '天津': '天津市', '上海': '上海市', '重庆': '重庆市',
        '河北': '河北省', '山西': '山西省', '辽宁': '辽宁省', '吉林': '吉林省', '黑龙江': '黑龙江省',
        '江苏': '江苏省', '浙江': '浙江省', '安徽': '安徽省', '福建': '福建省', '江西': '江西省',
        '山东': '山东省', '河南': '河南省', '湖北': '湖北省', '湖南': '湖南省', '广东': '广东省',
        '海南': '海南省', '四川': '四川省', '贵州': '贵州省', '云南': '云南省', '陕西': '陕西省',
        '甘肃': '甘肃省', '青海': '青海省', '台湾': '台湾省',
        '内蒙古': '内蒙古自治区', '广西': '广西壮族自治区', '西藏': '西藏自治区',
        '宁夏': '宁夏回族自治区', '新疆': '新疆维吾尔自治区',
        '香港': '香港特别行政区', '澳门': '澳门特别行政区'
    }
    
    # 扁平化城市列表以供快速查找
    all_cities = []
    city_to_province = {}
    for prov, cities in province_city_map.items():
        for city in cities:
            all_cities.append(city)
            city_to_province[city] = prov

    conn = get_db_connection()
    try:
        # 获取最近 1000 条数据
        rows = conn.execute("SELECT title, content FROM content_details ORDER BY crawled_at DESC LIMIT 1000").fetchall()
        
        city_counts = {c: 0 for c in all_cities}
        province_counts = {p: 0 for p in province_city_map.keys()}
        
        for row in rows:
            title = row['title'] or ''
            content = row['content'] or ''
            
            # 统计省份直接提及
            for prov in province_city_map.keys():
                prov_score = 0
                if prov in title:
                    prov_score += 5
                elif prov in content:
                    prov_score += 1
                province_counts[prov] += prov_score
            
            # 统计城市提及
            for city in all_cities:
                city_score = 0
                if city in title:
                    city_score += 5
                elif city in content:
                    city_score += 1
                
                if city_score > 0:
                    city_counts[city] += city_score
                    # 城市热度累加到省份
                    province_counts[city_to_province[city]] += city_score
                    
        # 格式化城市数据 (Top 50 避免前端渲染压力过大)
        city_result = [{'name': c, 'value': v} for c, v in city_counts.items() if v > 0]
        city_result.sort(key=lambda x: x['value'], reverse=True)
        city_result = city_result[:60]
        
        # 格式化省份数据 (使用标准全称)
        province_result = [{'name': standard_names.get(p, p), 'value': v} for p, v in province_counts.items() if v > 0]

        
        return jsonify({
            'province_data': province_result,
            'city_data': city_result
        })
    finally:
        conn.close()

@app.route('/launch_visual_sniffer', methods=['POST'])
def launch_visual_sniffer():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
        
    try:
        data = request.get_json() or {}
        url = data.get('url', '')
        
        # 将可视化嗅探器作为单独的进程启动
        # 使用当前环境中的 Python
        cmd = [sys.executable, 'sniffer_tool/main.py']
        if url:
            cmd.append(url)
            
        subprocess.Popen(cmd, cwd=os.getcwd())
        return jsonify({'message': 'Visual Sniffer launched on server desktop'})
    except Exception as e:
        return jsonify({'error': f'Failed to launch: {str(e)}'}), 500

@app.route('/sniffer/closed', methods=['POST'])
def sniffer_closed():
    try:
        data = request.get_json() or {}
        url = data.get('url')
        headers = data.get('headers')
        updated = False
        if url and headers:
            domain = extract_domain(url)
            conn = get_db_connection()
            try:
                existing = conn.execute("SELECT id FROM crawling_rules WHERE domain = ?", (domain,)).fetchone()
                if existing:
                    conn.execute('''
                        UPDATE crawling_rules SET request_headers = ?, created_at = CURRENT_TIMESTAMP WHERE id = ?
                    ''', (parse_headers_to_json(headers), existing['id']))
                    conn.commit()
                    updated = True
            finally:
                conn.close()
        sniffer_signal['ts'] = time.time()
        return jsonify({'ok': True, 'updated': updated, 'ts': sniffer_signal['ts']})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/refresh_signal')
def api_refresh_signal():
    return jsonify({'ts': sniffer_signal['ts']})

@app.route('/rules/refresh_headers/<int:rule_id>', methods=['POST'])
def refresh_rule_headers(rule_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    conn = get_db_connection()
    try:
        rule = conn.execute('SELECT * FROM crawling_rules WHERE id = ?', (rule_id,)).fetchone()
        if not rule:
            return jsonify({'error': 'Rule not found'}), 404
        url_pattern = rule['url_pattern']
        current_headers = rule['request_headers']
        result, error = sniffer.sniff_page(url_pattern, current_headers)
        if error:
            return jsonify({'error': error}), 500
        new_headers = result.get('request_headers', '{}')
        conn.execute('UPDATE crawling_rules SET request_headers = ?, created_at = CURRENT_TIMESTAMP WHERE id = ?', (new_headers, rule_id))
        conn.commit()
        return jsonify({'message': 'Headers refreshed', 'request_headers': new_headers})
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
