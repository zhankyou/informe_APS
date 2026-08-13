import jwt
import datetime
from functools import wraps
from flask import request, jsonify, g
from config import Config

def generar_token(user_id: int, correo: str, nombre: str, rol: str) -> str:
    payload = {
        "user_id": user_id, "correo": correo, "nombre": nombre, "rol": rol,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=Config.TOKEN_HOURS)
    }
    return jwt.encode(payload, Config.SECRET_KEY, algorithm="HS256")

def verificar_token(token: str) -> dict | None:
    try:
        return jwt.decode(token, Config.SECRET_KEY, algorithms=["HS256"])
    except:
        return None

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "): return jsonify({"error": "Token requerido"}), 401
        payload = verificar_token(auth.split(" ")[1])
        if not payload: return jsonify({"error": "Token inválido"}), 401
        g.user = payload
        return f(*args, **kwargs)
    return decorated
