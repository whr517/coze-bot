from flask import Flask, jsonify, request
from flask_cors import CORS
import os
import time
import hashlib
import secrets

app = Flask(__name__)
CORS(app)

# ========== 配置区（在 Render 环境变量中设置）==========
COZE_API_KEY = os.environ.get("COZE_API_KEY", "")      # Coze 令牌（最重要！）
ACCESS_PASSWORD = os.environ.get("ACCESS_PASSWORD", "admin123")  # 访问密码
# ===================================================

# 存储已签发的临时 token（简单实现，生产环境建议用 Redis）
active_tokens = {}  # {token: expire_time}
TOKEN_EXPIRE_SECONDS = 3600  # 1小时

def generate_auth_token():
    """生成临时授权 token"""
    token = secrets.token_urlsafe(32)
    active_tokens[token] = time.time() + TOKEN_EXPIRE_SECONDS
    return token

def verify_auth_token(token):
    """验证临时 token 是否有效"""
    if not token:
        return False
    if token in active_tokens and active_tokens[token] > time.time():
        return True
    # 清理过期 token
    expired = [t for t, exp in active_tokens.items() if exp <= time.time()]
    for t in expired:
        del active_tokens[t]
    return False

# 简单的频率限制
RATE_LIMIT = {}
RATE_LIMIT_WINDOW = 60
RATE_LIMIT_MAX = 30

def rate_limit_check(ip):
    now = time.time()
    if ip not in RATE_LIMIT:
        RATE_LIMIT[ip] = []
    
    RATE_LIMIT[ip] = [t for t in RATE_LIMIT[ip] if now - t < RATE_LIMIT_WINDOW]
    
    if len(RATE_LIMIT[ip]) >= RATE_LIMIT_MAX:
        return False
    
    RATE_LIMIT[ip].append(now)
    return True

@app.route('/api/verify', methods=['POST'])
def verify_password():
    """验证密码，签发临时 token"""
    client_ip = request.remote_addr
    
    if not rate_limit_check(client_ip):
        return jsonify({"success": False, "error": "请求过于频繁"}), 429
    
    data = request.get_json()
    password = data.get('password', '')
    
    if password == ACCESS_PASSWORD:
        auth_token = generate_auth_token()
        return jsonify({
            "success": True,
            "auth_token": auth_token
        })
    else:
        return jsonify({"success": False, "error": "密码错误"}), 401

@app.route('/api/get_coze_token', methods=['GET'])
def get_coze_token():
    """返回 Coze API token（需要先验证临时 token）"""
    client_ip = request.remote_addr
    
    if not rate_limit_check(client_ip):
        return jsonify({"error": "请求过于频繁"}), 429
    
    # 从 Authorization header 获取临时 token
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return jsonify({"error": "invalid_token"}), 401
    
    temp_token = auth_header[7:]  # 去掉 'Bearer ' 前缀
    
    if not verify_auth_token(temp_token):
        return jsonify({"error": "invalid_token"}), 401
    
    # 验证通过，返回 Coze token
    return jsonify({
        "token": COZE_API_KEY,
        "expires_in": 3600
    })

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({"status": "ok", "timestamp": time.time()})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)