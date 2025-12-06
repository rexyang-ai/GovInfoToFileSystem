from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from app.database.db import get_db_connection
import dify_baidu_crawler
import yaan_crawler
import sniffer
import os
import json
import datetime
import concurrent.futures
from urllib.parse import urlparse

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

@app.route('/search', methods=['POST'])
def search():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
        
    data = request.get_json()
    keyword = data.get('keyword', '')
    
    if not keyword:
        return jsonify({'error': 'Keyword is required'}), 400
        
    # Call the crawlers concurrently
    results = []
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            # Submit tasks
            future_baidu = executor.submit(dify_baidu_crawler.main, keyword)
            future_yaan = executor.submit(yaan_crawler.search_yaan, keyword)
            
            # Wait for results
            baidu_res = future_baidu.result()
            yaan_res = future_yaan.result()
            
            # Process Baidu Results
            if baidu_res and 'result' in baidu_res:
                for item in baidu_res['result']:
                    item['source'] = '百度搜索'
                    results.append(item)
                    
            # Process Yaan Results
            if yaan_res and 'result' in yaan_res:
                for item in yaan_res['result']:
                    item['source'] = '雅安市人民政府'
                    # Ensure keys match
                    if 'date' in item:
                        # Append date to summary if exists, or just ignore as UI doesn't show date column yet
                        if item['summary']:
                            item['summary'] = f"[{item['date']}] " + item['summary']
                        else:
                             item['summary'] = f"[{item['date']}]"
                    results.append(item)

        return jsonify({"result": results})
        
    except Exception as e:
        print(f"Crawler error: {e}")
        # Even if one fails, try to return what we have? 
        # For now, just return error or empty
        return jsonify({'error': str(e), 'result': []}), 500

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
    count = 0
    try:
        for item in items:
            # Check if URL already exists to avoid duplicates (optional, but good practice)
            # For now, let's just insert or ignore if we had unique constraint (we don't on URL yet)
            # But user might want to save same link for different keywords.
            conn.execute('''
                INSERT INTO crawled_data (title, url, summary, cover_url, search_keyword)
                VALUES (?, ?, ?, ?, ?)
            ''', (item.get('title'), item.get('url'), item.get('summary'), item.get('cover_url'), keyword))
            count += 1
        conn.commit()
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()
        
    return jsonify({'message': f'成功保存 {count} 条数据。'})

@app.route('/warehouse')
def warehouse():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    keyword = request.args.get('keyword', '')
    date_filter = request.args.get('date', '')
    
    # Join with crawling_rules to check if rules exist for the domain
    # This is a bit complex because we need to match domain. 
    # For simplicity, let's just fetch all rules and map in python or do a left join if we can extract domain in SQL.
    # SQLite doesn't have easy domain extraction.
    # So let's just fetch data and rules separately for now or just check simply.
    
    query = "SELECT * FROM crawled_data WHERE 1=1"
    params = []
    
    if keyword:
        query += " AND (title LIKE ? OR summary LIKE ? OR search_keyword LIKE ?)"
        params.extend([f'%{keyword}%', f'%{keyword}%', f'%{keyword}%'])
        
    if date_filter:
        query += " AND date(created_at) = ?"
        params.append(date_filter)
        
    query += " ORDER BY created_at DESC"
    
    conn = get_db_connection()
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
    
    return render_template('warehouse.html', items=items, username=session['username'])

@app.route('/sniff', methods=['POST'])
def sniff():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    url = data.get('url')
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
        
    # 1. Sniff the page
    result, error = sniffer.sniff_page(url)
    
    if error:
        return jsonify({'error': error}), 500
        
    # 2. Return data for confirmation (DO NOT SAVE YET)
    domain = extract_domain(url)
    result['domain'] = domain
    result['rule_name'] = f"规则_{domain}"
    
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
    
    conn = get_db_connection()
    rules = conn.execute('SELECT * FROM crawling_rules ORDER BY created_at DESC').fetchall()
    conn.close()
    
    return render_template('rules.html', rules=rules, username=session.get('username'))

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

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
