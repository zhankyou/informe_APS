from flask import Blueprint, request, jsonify, g
from werkzeug.security import check_password_hash
from utils.security import generar_token, require_auth
from database.db_core import BaseService
from services.dashboard_service import DashboardService
from services.auditoria_service import AuditoriaService
from services.sihos_service import SihosService
from services.mapas_service import MapasService
import logging

api_bp = Blueprint('api', __name__, url_prefix='/api')
logger = logging.getLogger("API_ROUTES")
base_srv = BaseService()

@api_bp.route("/login", methods=["POST"])
def login():
    body = request.get_json(silent=True) or {}
    correo = str(body.get("correo", "")).strip().lower()
    password = str(body.get("password", "")).strip()
    fingerprint = str(body.get("device_fingerprint", "")).strip()

    if not correo or not password: return jsonify({"error": "Credenciales requeridas"}), 400

    rows = base_srv.ejecutar("SELECT id, username, password_hash, device_id FROM usuarios WHERE LOWER(TRIM(username)) = :u LIMIT 1", {"u": correo})
    if not rows: return jsonify({"error": "Credenciales incorrectas"}), 401

    usuario = rows[0]
    if not check_password_hash(usuario["password_hash"], password):
        return jsonify({"error": "Credenciales incorrectas"}), 401

    nombre_visual = usuario["username"].capitalize()
    token = generar_token(usuario["id"], usuario["username"], nombre_visual, "Auditor")

    logger.info(f"🟢 [LOGIN] Usuario '{nombre_visual}' conectado.")
    return jsonify({"token": token, "nombre": nombre_visual, "rol": "Auditor"})

@api_bp.route("/logout", methods=["POST"])
def logout():
    return jsonify({"status": "Cierre de sesión exitoso"}), 200

@api_bp.route("/encuestadores", methods=["GET"])
@require_auth
def get_encuestadores():
    rows = base_srv.ejecutar("""
        SELECT DISTINCT LOWER(TRIM(CAST(created_by AS text))) as correo
        FROM (SELECT created_by FROM caracterizacion_si_aps_individual_2026 UNION SELECT created_by FROM pcc_principal_2026 UNION SELECT created_by FROM pcf_planes_principal_2026 UNION SELECT created_by FROM desistimiento_aps_2026) AS tbl
        WHERE created_by IS NOT NULL AND created_by != ''
    """)
    return jsonify([r["correo"] for r in rows if r["correo"]])

@api_bp.route("/nombres_profesionales", methods=["GET"])
@require_auth
def get_nombres_profesionales():
    rows = base_srv.ejecutar("""
        SELECT DISTINCT "5_4_nombre_del_profe" as nombre
        FROM pcf_planes_principal_2026 WHERE "5_4_nombre_del_profe" IS NOT NULL AND TRIM("5_4_nombre_del_profe") != '' ORDER BY 1
    """)
    return jsonify([r["nombre"] for r in rows if r["nombre"]])

@api_bp.route("/dashboard", methods=["GET"])
@require_auth
def get_dashboard():
    srv = DashboardService()
    return jsonify(srv.obtener_datos(request.args.get("fecha_inicio", "").strip(), request.args.get("fecha_fin", "").strip()))

@api_bp.route("/auditoria", methods=["GET"])
@require_auth
def auditoria():
    srv = AuditoriaService()
    correo = request.args.get("usuario", "").strip()
    nombre = request.args.get("nombre", "").strip()
    if not correo and not nombre: return jsonify({"error": "Correo o nombre requerido."}), 400
    return jsonify(srv.obtener_datos(correo, nombre, request.args.get("fecha_inicio", "").strip(), request.args.get("fecha_fin", "").strip(), 'created_at'))

@api_bp.route("/auditoria_actualizacion", methods=["GET"])
@require_auth
def auditoria_actualizacion():
    srv = AuditoriaService()
    correo = request.args.get("usuario", "").strip()
    nombre = request.args.get("nombre", "").strip()
    if not correo and not nombre: return jsonify({"error": "Correo o nombre requerido."}), 400
    return jsonify(srv.obtener_datos(correo, nombre, request.args.get("fecha_inicio", "").strip(), request.args.get("fecha_fin", "").strip(), 'uploaded_at'))

@api_bp.route("/mapas", methods=["GET"])
@require_auth
def get_mapas():
    srv = MapasService()
    correo = request.args.get("usuario", "").strip()
    nombre = request.args.get("nombre", "").strip()
    if not correo and not nombre: return jsonify({"error": "Correo o nombre requerido."}), 400
    return jsonify(srv.obtener_coordenadas(correo, nombre, request.args.get("fecha_inicio", "").strip(), request.args.get("fecha_fin", "").strip()))

@api_bp.route("/profesionales_sihos", methods=["GET"])
@require_auth
def get_profesionales_sihos():
    srv = SihosService()
    return jsonify(srv.obtener_profesionales())

@api_bp.route("/sihos", methods=["GET"])
@require_auth
def get_sihos():
    srv = SihosService()
    profesional = request.args.get("profesional", "").strip()
    data = srv.obtener_datos(profesional, request.args.get("fecha_inicio", "").strip(), request.args.get("fecha_fin", "").strip())
    if "error" in data: return jsonify(data), 404
    return jsonify(data)

@api_bp.route("/health", methods=["GET"])
def health(): return jsonify({"status": "ok"}), 200