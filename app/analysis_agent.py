import json
import sqlite3
import time
from openai import OpenAI
import httpx
from app.database.db import get_db_connection

# Tool definitions used by the model
TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "query_database",
            "description": "对 content_details 表执行 SQL 查询以检索信息。表结构为：content_details (id, source_url, title, content, html_content, rule_id, crawled_at)。请使用 SQLite 语法。content 列包含主要文本内容。",
            "parameters": {
                "type": "object",
                "properties": {
                    "sql_query": {
                        "type": "string",
                        "description": "要执行的 SQL 查询语句。"
                    }
                },
                "required": ["sql_query"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "generate_echart",
            "description": "使用 ECharts 生成图表。当用户请求可视化时使用此工具。支持多系列数据。",
            "parameters": {
                "type": "object",
                "properties": {
                    "title": {
                        "type": "string",
                        "description": "图表标题。"
                    },
                    "chart_type": {
                        "type": "string",
                        "enum": ["bar", "line", "pie", "scatter"],
                        "description": "默认图表类型（如果在系列中未指定）。"
                    },
                    "x_data": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "X 轴标签（类别名称）。"
                    },
                    "series": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "name": {"type": "string"},
                                "data": {"type": "array", "items": {"type": "number"}},
                                "type": {"type": "string", "enum": ["bar", "line", "pie", "scatter"]}
                            },
                            "required": ["name", "data"]
                        },
                        "description": "数据系列列表。每个系列包含名称、数据数组和可选的类型覆盖。"
                    }
                },
                "required": ["title", "x_data", "series"]
            }
        }
    }
]

def execute_sql(query):
    """Execute SQL query on the database and return results."""
    try:
        # Safety check: only allow SELECT statements
        if not query.strip().upper().startswith("SELECT"):
            return {"error": "分析功能仅允许使用 SELECT 查询。"}

        conn = get_db_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(query)
        rows = cursor.fetchall()
        
        # Convert to list of dicts for JSON serialization
        result = []
        for row in rows:
            # Handle binary data or other non-serializable types (if any)
            row_dict = {}
            for key in row.keys():
                val = row[key]
                # Truncate overly long text fields to save tokens
                if isinstance(val, str) and len(val) > 200:
                    val = val[:200] + "...(已截断)"
                row_dict[key] = val
            result.append(row_dict)
        
        conn.close()
        
        # Limit result size to prevent token overflow
        # If result is too large, we should summarize or truncate
        if len(result) > 20:
            return {"data": result[:20], "warning": f"结果已截断。显示 {len(result)} 行中的前 20 行。如有需要请优化查询。"}
            
        if not result:
            return {"data": [], "message": "查询成功执行，但未返回任何结果。请尝试不同的查询。"}

        return {"data": result}
    except Exception as e:
        return {"error": str(e)}

import math

def calculate_tokens(text):
    """
    Estimate the number of tokens for the given text.
    Heuristic rules:
    - ASCII characters (English, numbers, symbols): ~0.25 Token/char (4 chars = 1 Token)
    - Non-ASCII characters (Chinese, Emojis, etc.): ~1.5 Token/char
    """
    if not text:
        return 0
    
    token_count = 0
    for char in text:
        if ord(char) < 128:
            token_count += 0.25
        else:
            token_count += 1.5
            
    return math.ceil(token_count)

def stream_chat_with_data(model_config, messages):
    """
    Stream AI model chat response, handling tool calls for database queries.
    model_config: Dict containing 'api_base', 'api_key', 'model_name'
    messages: List of message dictionaries
    """
    
    api_base = model_config['api_base']
    # OpenAI client expects base_url not to contain /chat/completions
    if api_base.endswith('/chat/completions'):
        api_base = api_base.replace('/chat/completions', '')
    if api_base.endswith('/'):
        api_base = api_base[:-1]

    client = OpenAI(
        api_key=model_config['api_key'],
        base_url=api_base,
        http_client=httpx.Client(verify=False) # Disable SSL verification if needed or for compatibility
    )

    # Add system prompt if not present at the beginning
    system_prompt = {
        "role": "system",
        "content": "你是一个数据分析助手。你可以查询 'content_details' 表来回答用户的问题。"
                   "当需要数据时，请务必使用 'query_database' 工具。"
                   "当用户请求可视化（例如：饼图、柱状图、折线图）或数据可以通过图形更好地表示时，"
                   "在获取必要数据后，请务必使用 'generate_echart' 工具。"
                   "注意：当使用 'generate_echart' 工具时，禁止在文本回复中生成 base64 图片数据或 Markdown 图片链接。"
                   "前端会自动根据你的工具调用渲染交互式图表。"
                   "你可以连续多次使用工具（例如：查询 -> 查询 -> 图表）。"
                   "表 'content_details' 包含以下列：id, source_url, title, content, html_content, rule_id, crawled_at。"
                   "编写 SQL 时，请确保使用有效的 SQLite 语法。"
                   "如果需要聚合数据，请尝试先在 SQL 中完成。"
    }
    
    if not messages or messages[0]['role'] != 'system':
        messages.insert(0, system_prompt)

    # Force enhance system prompt
    if messages[0]['role'] == 'system':
        messages[0]['content'] = (
            "你是一个数据分析助手。你可以查询 'content_details' 表来回答用户的问题。"
            "当需要数据时，请务必使用 'query_database' 工具。"
            "当用户请求可视化（例如：饼图、柱状图、折线图）或数据可以通过图形更好地表示时，"
            "在获取必要数据后，请务必使用 'generate_echart' 工具。"
            "IMPORTANT: 当使用 'generate_echart' 工具生成图表时，**严禁**在回复中输出任何 base64 图片数据、Markdown 图片语法 (![...](...)) 或 HTML img 标签。"
            "只需调用 'generate_echart' 工具，前端会负责渲染。生成冗余的图片数据会导致错误。"
            "你可以连续多次使用工具（例如：查询 -> 查询 -> 图表）。"
            "表 'content_details' 包含以下列：id, source_url, title, content, html_content, rule_id, crawled_at。"
            "编写 SQL 时，请确保使用有效的 SQLite 语法。"
            "如果需要聚合数据，请尝试先在 SQL 中完成（GROUP BY, COUNT 等）。"
            "对于图表，请确保提供与 'x_data' 匹配的有效 'series' 数据点。"
            "如果查询没有返回结果，请尝试更广泛的查询或通知用户。"
        )

    print(f"Sending request to {api_base}, model is {model_config['model_name']}")
    
    # Estimate tokens for tool definitions (one-time)
    tools_tokens = calculate_tokens(json.dumps(TOOLS))
    
    total_input_tokens = 0
    total_output_tokens = 0
    
    try:
        max_turns = 10 # Increase max turns for complex workflows
        current_turn = 0
        
        while current_turn < max_turns:
            current_turn += 1
            
            # Calculate input tokens for current turn
            current_input_tokens = tools_tokens
            for msg in messages:
                current_input_tokens += calculate_tokens(str(msg.get('content', '')))
                # Add some overhead for message structure/roles
                current_input_tokens += 4 
                if msg.get('tool_calls'):
                     current_input_tokens += calculate_tokens(json.dumps(msg['tool_calls']))
            
            total_input_tokens += current_input_tokens
            
            # Retry mechanism for rate limits
            max_retries = 3
            retry_count = 0
            stream = None
            
            while retry_count < max_retries:
                try:
                    stream = client.chat.completions.create(
                        model=model_config['model_name'],
                        messages=messages,
                        tools=TOOLS,
                        tool_choice="auto",
                        stream=True,
                        temperature=0.1
                    )
                    break # Success, exit retry loop
                except Exception as e:
                    error_msg = str(e)
                    if "429" in error_msg or "rate limit" in error_msg.lower():
                        retry_count += 1
                        wait_time = 2 ** retry_count # Exponential backoff: 2, 4, 8 seconds
                        print(f"Rate limit triggered. Retrying in {wait_time} seconds...")
                        time.sleep(wait_time)
                        if retry_count == max_retries:
                            raise e # Re-raise exception if max retries reached
                    else:
                        raise e # Immediately re-raise other errors
            
            collected_content = ""
            tool_calls_buffer = {} # Index -> {id, type, function: {name, arguments}}
            has_tool_calls = False
            
            for chunk in stream:
                if not chunk.choices:
                    continue
                    
                delta = chunk.choices[0].delta
                
                # Handle content
                if delta.content:
                    content = delta.content
                    collected_content += content
                    yield f"data: {json.dumps({'type': 'content', 'content': content})}\n\n"
                
                # Handle tool calls (accumulated)
                if delta.tool_calls:
                    has_tool_calls = True
                    for tool_call in delta.tool_calls:
                        idx = tool_call.index
                        
                        if idx not in tool_calls_buffer:
                            tool_calls_buffer[idx] = {
                                "id": tool_call.id,
                                "type": tool_call.type,
                                "function": {
                                    "name": tool_call.function.name,
                                    "arguments": ""
                                }
                            }
                        
                        if tool_call.function.arguments:
                            tool_calls_buffer[idx]["function"]["arguments"] += tool_call.function.arguments
            
            # Calculate output tokens for current turn
            turn_output_tokens = calculate_tokens(collected_content)
            if has_tool_calls:
                 # Add tool call tokens
                 for idx, tool_data in tool_calls_buffer.items():
                     turn_output_tokens += calculate_tokens(json.dumps(tool_data))
            
            total_output_tokens += turn_output_tokens
            
            # If no tool calls, we finish the current turn (and possibly the whole response)
            if not has_tool_calls:
                break
            
            # We have tool calls to execute
            yield f"data: {json.dumps({'type': 'status', 'status': 'analyzing', 'message': '正在执行工具调用...'})}\n\n"
            
            # Build assistant message containing tool calls
            assistant_msg = {
                "role": "assistant",
                "content": collected_content if collected_content else None,
                "tool_calls": []
            }
            
            messages.append(assistant_msg)
            
            for idx, tool_call_data in tool_calls_buffer.items():
                assistant_msg["tool_calls"].append({
                    "id": tool_call_data["id"],
                    "type": tool_call_data["type"],
                    "function": {
                        "name": tool_call_data["function"]["name"],
                        "arguments": tool_call_data["function"]["arguments"]
                    }
                })
                
                # Parse arguments
                try:
                    args = json.loads(tool_call_data["function"]["arguments"])
                    func_name = tool_call_data["function"]["name"]
                    
                    if func_name == "query_database":
                        sql = args.get("sql_query")
                        yield f"data: {json.dumps({'type': 'step', 'name': '执行SQL', 'status': 'running', 'details': sql})}\n\n"
                        
                        # Execute SQL
                        result = execute_sql(sql)
                        
                        yield f"data: {json.dumps({'type': 'step', 'name': '执行SQL', 'status': 'completed', 'details': '查询成功'})}\n\n"
                        
                        # Append tool result to message list
                        messages.append({
                            "role": "tool",
                            "tool_call_id": tool_call_data["id"],
                            "name": func_name,
                            "content": json.dumps(result, ensure_ascii=False)
                        })
                        
                    elif func_name == "generate_echart":
                        yield f"data: {json.dumps({'type': 'step', 'name': '生成图表', 'status': 'running', 'details': args.get('title')})}\n\n"
                        
                        # Send chart data to frontend
                        yield f"data: {json.dumps({'type': 'chart', 'options': args})}\n\n"
                        
                        result = {"status": "success", "message": "Chart generated successfully"}
                        
                        yield f"data: {json.dumps({'type': 'step', 'name': '生成图表', 'status': 'completed', 'details': '图表已渲染'})}\n\n"
                        
                        messages.append({
                            "role": "tool",
                            "tool_call_id": tool_call_data["id"],
                            "name": func_name,
                            "content": json.dumps(result, ensure_ascii=False)
                        })
                except Exception as e:
                    print(f"Tool execution error: {e}")
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tool_call_data["id"],
                        "name": tool_call_data["function"]["name"],
                        "content": json.dumps({"error": str(e)})
                    })
            
            # Loop continues to next turn, letting LLM see tool results and decide next steps
            
        # Yield usage statistics before ending
        yield f"data: {json.dumps({'type': 'usage', 'input_tokens': total_input_tokens, 'output_tokens': total_output_tokens})}\n\n"
        yield f"data: {json.dumps({'type': 'done'})}\n\n"

    except Exception as e:
        yield f"data: {json.dumps({'type': 'error', 'content': str(e)})}\n\n"
