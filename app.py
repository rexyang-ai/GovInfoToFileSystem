from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from app.database.db import get_db_connection
import dify_baidu_crawler
import os
import datetime

app = Flask(__name__, template_folder='app/templates', static_folder='app/static')
app.secret_key = 'super_secret_key_for_demo_only'  # Change for prod

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
        
    # Call the crawler
    try:
        # Calling the main function from the crawler script
        # The main function returns {"result": [...]}
        result_dict = dify_baidu_crawler.main(keyword)
        return jsonify(result_dict)
    except Exception as e:
        print(f"Crawler error: {e}")
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
    
    query = "SELECT * FROM crawled_data WHERE 1=1"
    params = []
    
    if keyword:
        query += " AND (title LIKE ? OR summary LIKE ? OR search_keyword LIKE ?)"
        params.extend([f'%{keyword}%', f'%{keyword}%', f'%{keyword}%'])
        
    if date_filter:
        # Assuming SQLite date string format YYYY-MM-DD
        query += " AND date(created_at) = ?"
        params.append(date_filter)
        
    query += " ORDER BY created_at DESC"
    
    conn = get_db_connection()
    rows = conn.execute(query, params).fetchall()
    conn.close()
    
    return render_template('warehouse.html', items=rows, username=session['username'])

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
