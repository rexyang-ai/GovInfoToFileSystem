import json
import sqlite3
from openai import OpenAI
import httpx
from app.database.db import get_db_connection

# Tool definition for the model
TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "query_database",
            "description": "Execute a SQL query on the content_details table to retrieve information. The table schema is: content_details (id, source_url, title, content, html_content, rule_id, crawled_at). Use SQLite syntax. content column contains the main text.",
            "parameters": {
                "type": "object",
                "properties": {
                    "sql_query": {
                        "type": "string",
                        "description": "The SQL query to execute."
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
            "description": "Generate a chart using ECharts. Use this when the user asks for a visualization or when data can be better represented graphically.",
            "parameters": {
                "type": "object",
                "properties": {
                    "title": {
                        "type": "string",
                        "description": "The title of the chart."
                    },
                    "chart_type": {
                        "type": "string",
                        "enum": ["bar", "line", "pie"],
                        "description": "The type of chart to generate."
                    },
                    "x_data": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Labels for the X-axis (for bar/line) or category names (for pie)."
                    },
                    "series_data": {
                        "type": "array",
                        "items": {"type": "number"},
                        "description": "Data values for the series."
                    },
                    "series_name": {
                        "type": "string",
                        "description": "Name of the data series."
                    }
                },
                "required": ["title", "chart_type", "x_data", "series_data"]
            }
        }
    }
]

def execute_sql(query):
    """Execute a SQL query against the database and return results."""
    try:
        # Safety check: only allow SELECT statements
        if not query.strip().upper().startswith("SELECT"):
            return {"error": "Only SELECT queries are allowed for analysis."}

        conn = get_db_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(query)
        rows = cursor.fetchall()
        
        # Convert to list of dicts for JSON serialization
        result = []
        for row in rows:
            # Handle binary data or other non-serializable types if any
            row_dict = {}
            for key in row.keys():
                row_dict[key] = row[key]
            result.append(row_dict)
        
        conn.close()
        
        # Limit result size to prevent token overflow
        # If result is too large, we should probably summarize or truncate
        if len(result) > 20:
            return {"data": result[:20], "warning": f"Result truncated. Showing 20 of {len(result)} rows. Please refine query if needed."}
            
        return {"data": result}
    except Exception as e:
        return {"error": str(e)}

def stream_chat_with_data(model_config, messages):
    """
    Stream chat response from the AI model, handling tool calls for database querying.
    model_config: dict with 'api_base', 'api_key', 'model_name'
    messages: list of message dicts
    """
    
    api_base = model_config['api_base']
    # OpenAI client expects base_url without /chat/completions
    if api_base.endswith('/chat/completions'):
        api_base = api_base.replace('/chat/completions', '')
    if api_base.endswith('/'):
        api_base = api_base[:-1]

    client = OpenAI(
        api_key=model_config['api_key'],
        base_url=api_base,
        http_client=httpx.Client(verify=False) # Disable SSL verification if needed or for compatibility
    )

    # Add system prompt if not present at start
    system_prompt = {
        "role": "system",
        "content": "You are a data analysis assistant. You can query the 'content_details' table to answer user questions. "
                   "Always use the 'query_database' tool when you need data. "
                   "When the user requests a visualization (e.g., pie chart, bar chart, line chart) or when data can be better represented graphically, "
                   "always use the 'generate_echart' tool after obtaining the necessary data. "
                   "After getting data and generating visualizations (if needed), analyze it and provide a comprehensive report or answer. "
                   "The table 'content_details' has columns: id, source_url, title, content, html_content, rule_id, crawled_at. "
                   "When writing SQL, ensure it is valid SQLite syntax."
    }
    
    if not messages or messages[0]['role'] != 'system':
        messages.insert(0, system_prompt)

    print(f"Sending request to {api_base} with model {model_config['model_name']}")
    
    try:
        stream = client.chat.completions.create(
            model=model_config['model_name'],
            messages=messages,
            tools=TOOLS,
            tool_choice="auto",
            stream=True,
            temperature=0.1
        )
        
        collected_content = ""
        tool_calls_buffer = {} # index -> {id, type, function: {name, arguments}}
        
        for chunk in stream:
            if not chunk.choices:
                continue
                
            delta = chunk.choices[0].delta
            
            # Handle content
            if delta.content:
                content = delta.content
                collected_content += content
                yield f"data: {json.dumps({'type': 'content', 'content': content})}\n\n"
            
            # Handle tool calls (accumulation)
            if delta.tool_calls:
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
        
        # Check if we have tool calls to execute
        if tool_calls_buffer:
            # We need to inform the client that we are executing tools
            yield f"data: {json.dumps({'type': 'status', 'status': 'analyzing', 'message': '正在查询数据库...'})}\n\n"
            
            # Construct the assistant message with tool calls
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
                        
                        # Append tool result to messages
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
            
            # Second request: get final answer based on tool results
            # payload["messages"] = messages -> already appended
            
            yield f"data: {json.dumps({'type': 'status', 'status': 'thinking', 'message': '正在生成报告...'})}\n\n"
            
            stream2 = client.chat.completions.create(
                model=model_config['model_name'],
                messages=messages,
                stream=True,
                temperature=0.1
            )
            
            for chunk in stream2:
                if chunk.choices:
                    delta = chunk.choices[0].delta
                    if delta.content:
                        yield f"data: {json.dumps({'type': 'content', 'content': delta.content})}\n\n"

        yield f"data: {json.dumps({'type': 'done'})}\n\n"

    except Exception as e:
        yield f"data: {json.dumps({'type': 'error', 'content': str(e)})}\n\n"
