# -*- coding: utf-8 -*-
"""
Backend API – Módulo INFORMES (Dashboard + Auditoría)
Framework  : Flask + SQLAlchemy + PyJWT
"""

import os
import logging
import datetime
from functools import wraps
import jwt
from flask import Flask, jsonify, request, send_from_directory, g
from flask_cors import CORS
from sqlalchemy import create_engine, text
from werkzeug.security import check_password_hash
from dotenv import load_dotenv

load_dotenv()
logging.basicConfig(level=logging.INFO, format='%(asctime)s | [%(levelname)s] | %(message)s')
logger = logging.getLogger("INFORMES_API")

SECRET_KEY = os.getenv("SECRET_KEY", "informes-aps-ese-2026-secret-key-cambiar")
TOKEN_HOURS = 8

DIR_BASE = os.path.dirname(os.path.abspath(__file__))
DIR_HTML = DIR_BASE

app = Flask(__name__, static_folder=DIR_HTML)
CORS(app)

def get_engine():
    db_user = os.getenv("DB_USER_AIVEN")
    db_password = os.getenv("DB_PASSWORD_AIVEN")
    db_host = os.getenv("DB_HOST_AIVEN")
    db_port = os.getenv("DB_PORT_AIVEN", "13505")
    db_name = os.getenv("DB_NAME_AIVEN", "defaultdb")
    cadena = f"postgresql://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}?sslmode=require"
    return create_engine(cadena, pool_pre_ping=True, pool_size=5, max_overflow=10)

engine = get_engine()

def ejecutar(query_str: str, params: dict = None) -> list:
    try:
        with engine.connect() as conn:
            res = conn.execute(text(query_str), params or {})
            return [dict(row) for row in res.mappings()]
    except Exception as e:
        logger.error(f"❌ Error SQL detectado: {e}")
        return []

def safe_count(query_str: str, params: dict = None) -> int:
    rows = ejecutar(query_str, params)
    if rows:
        val = list(rows[0].values())[0]
        try: return int(val or 0)
        except: return 0
    return 0

def safe_group(query_str: str, params: dict = None) -> list:
    rows = ejecutar(query_str, params)
    result = []
    for row in rows:
        vals = list(row.values())
        if len(vals) >= 2: result.append({"label": str(vals[0] or "Sin dato"), "total": int(vals[1] or 0)})
    return result

def generar_token(user_id: int, correo: str, nombre: str, rol: str) -> str:
    payload = {"user_id" : user_id, "correo": correo, "nombre": nombre, "rol": rol, "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=TOKEN_HOURS)}
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def verificar_token(token: str) -> dict | None:
    try: return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except: return None

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

@app.route("/")
@app.route("/login")
def login_page(): return send_from_directory(DIR_HTML, "login.html")

@app.route("/dashboard")
def dashboard_page(): return send_from_directory(DIR_HTML, "dashboard.html")

@app.route("/auditoria")
def auditoria_page(): return send_from_directory(DIR_HTML, "auditoria.html")

@app.route("/api/login", methods=["POST"])
def login():
    body = request.get_json(silent=True) or {}
    correo      = str(body.get("correo", "")).strip().lower()
    password    = str(body.get("password", "")).strip()
    fingerprint = str(body.get("device_fingerprint", "")).strip()

    if not correo or not password: return jsonify({"error": "Credenciales requeridas"}), 400

    rows = ejecutar("SELECT id, username, password_hash, device_id FROM usuarios WHERE LOWER(TRIM(username)) = :u LIMIT 1", {"u": correo})
    if not rows: return jsonify({"error": "Credenciales incorrectas"}), 401

    usuario = rows[0]
    if not check_password_hash(usuario["password_hash"], password): return jsonify({"error": "Credenciales incorrectas"}), 401

    stored_fp = usuario.get("device_id")
    if not stored_fp:
        try:
            with engine.begin() as conn:
                conn.execute(text("UPDATE usuarios SET device_id = :fp WHERE id = :uid"), {"fp": fingerprint, "uid": usuario["id"]})
        except: pass
    elif stored_fp != fingerprint:
        return jsonify({"error": "Acceso denegado: Usuario vinculado a otro dispositivo."}), 403

    nombre_visual = usuario["username"].capitalize()
    token = generar_token(user_id = usuario["id"], correo = usuario["username"], nombre = nombre_visual, rol = "Auditor")

    return jsonify({"token": token, "nombre": nombre_visual, "rol": "Auditor"})

@app.route("/api/dashboard", methods=["GET"])
@require_auth
def get_dashboard():
    data = {}
    data["desistimientos"] = {
        "total": safe_count("SELECT COUNT(*) FROM desistimiento_aps_2026"),
        "con_error": safe_count("SELECT COUNT(*) FROM auditoria_errores_2026 WHERE modulo = 'DESISTIMIENTOS'"),
    }
    data["pcc"] = {
        "planes": safe_count("SELECT COUNT(*) FROM pcc_principal_2026"),
        "integrantes": safe_count("SELECT COUNT(*) FROM pcc_integrantes_2026"),
        "con_error": safe_count("SELECT COUNT(*) FROM auditoria_errores_2026 WHERE modulo LIKE 'PCC%'"),
    }

    query_edades = """
    WITH fechas_limpias AS (
        SELECT 
            to_date(SUBSTRING(CAST(created_at AS text), 1, 10), 'YYYY-MM-DD') as f_crea,
            TRIM(CAST("107_7_fecha_de_nacim" AS text)) as f_nac_raw
        FROM caracterizacion_si_aps_individual_2026
        WHERE "107_7_fecha_de_nacim" IS NOT NULL 
    ),
    edades AS (
        SELECT 
            f_crea,
            CASE 
                WHEN f_nac_raw ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}' THEN to_date(LEFT(f_nac_raw, 10), 'YYYY-MM-DD')
                WHEN f_nac_raw ~ '^[0-9]{2}/[0-9]{2}/[0-9]{4}' THEN to_date(LEFT(f_nac_raw, 10), 'DD/MM/YYYY')
                ELSE NULL 
            END as f_nac
        FROM fechas_limpias
    )
    SELECT 
        COUNT(*) FILTER (WHERE EXTRACT(YEAR FROM AGE(f_crea, f_nac)) < 5) as menores,
        COUNT(*) FILTER (WHERE EXTRACT(YEAR FROM AGE(f_crea, f_nac)) >= 60) as mayores
    FROM edades 
    WHERE f_nac IS NOT NULL
    """
    res_edades = ejecutar(query_edades)
    menores_5 = res_edades[0]["menores"] if res_edades else 0
    adultos_60 = res_edades[0]["mayores"] if res_edades else 0

    etnia_comp = ejecutar("""
        SELECT COUNT(*) FILTER (WHERE "116_16_pertenencia_t" = '7. Ninguna' OR "116_16_pertenencia_t" IS NULL) AS sin_etnia,
               COUNT(*) FILTER (WHERE "116_16_pertenencia_t" IS NOT NULL AND "116_16_pertenencia_t" != '7. Ninguna') AS con_etnia,
               COUNT(*) AS total FROM caracterizacion_si_aps_individual_2026
    """)
    etnia_data = etnia_comp[0] if etnia_comp else {"sin_etnia": 0, "con_etnia": 0, "total": 0}
    total_etnia = int(etnia_data.get("total") or 1)

    data["caracterizacion"] = {
        "familias": safe_count("SELECT COUNT(*) FROM caracterizacion_si_aps_familiar_2026 WHERE \"1_1_consentimiento_i\" = '1. SI'"),
        "individuos": safe_count("SELECT COUNT(*) FROM caracterizacion_si_aps_individual_2026"),
        "sin_aseguramiento": safe_count("SELECT COUNT(DISTINCT ec5_branch_owner_uuid) FROM caracterizacion_si_aps_individual_2026 WHERE \"113_13_rgimen_de_afi\" = '5. No afiliado'"),
        "gestantes": safe_count("SELECT COUNT(*) FROM caracterizacion_si_aps_individual_2026 WHERE \"109_9_se_encuentra_e\" = '1. SI'"),
        "menores_5": menores_5,
        "adultos_60": adultos_60,
        "victimas_conflicto": safe_count("SELECT COUNT(*) FROM caracterizacion_si_aps_familiar_2026 WHERE \"78_52_familia_vctima\" = '1. SI'"),
        "poblacion_etnica": safe_count("SELECT COUNT(*) FROM caracterizacion_si_aps_individual_2026 WHERE \"116_16_pertenencia_t\" IS NOT NULL AND \"116_16_pertenencia_t\" != '7. Ninguna'"),
        "tipo_familia": safe_group("SELECT \"64_41_tipo_de_famili\", COUNT(*) as total FROM caracterizacion_si_aps_familiar_2026 WHERE \"64_41_tipo_de_famili\" IS NOT NULL GROUP BY 1 ORDER BY 2 DESC"),
        "estrato": safe_group("SELECT \"23_12_estrato_socioe\", COUNT(*) as total FROM caracterizacion_si_aps_familiar_2026 WHERE \"23_12_estrato_socioe\" IS NOT NULL GROUP BY 1 ORDER BY 1"),
        "nivel_educativo": safe_group("SELECT \"112_12_nivel_educati\", COUNT(*) as total FROM caracterizacion_si_aps_individual_2026 WHERE \"112_12_nivel_educati\" IS NOT NULL GROUP BY 1 ORDER BY 2 DESC"),
        "etnia_sin_pct": round(int(etnia_data.get("sin_etnia") or 0) / total_etnia * 100, 1),
        "etnia_con_pct": round(int(etnia_data.get("con_etnia") or 0) / total_etnia * 100, 1),
        "etnia_con_total": int(etnia_data.get("con_etnia") or 0),
        "error_familiar": safe_count("SELECT COUNT(*) FROM auditoria_errores_2026 WHERE modulo = 'CARACT_FAMILIAR'"),
        "error_individual": safe_count("SELECT COUNT(*) FROM auditoria_errores_2026 WHERE modulo = 'CARACT_INDIVIDUAL'"),
    }
    data["pcf"] = {
        "familias_intervenidas": safe_count("SELECT COUNT(*) FROM pcf_planes_principal_2026 WHERE \"4_3_perfil_profesion\" IS NULL OR TRIM(\"4_3_perfil_profesion\") != 'Profesional Psicología'"),
        "integrantes_intervenidos": safe_count("SELECT COUNT(*) FROM pcf_planes_integrantes_2026"),
    }
    data["pcf_psicologia"] = {
        "intervenciones_familiares": safe_count("SELECT COUNT(*) FROM pcf_planes_principal_2026 WHERE TRIM(\"4_3_perfil_profesion\") = 'Profesional Psicología'"),
        "integrantes": safe_count("SELECT COUNT(*) FROM pcf_psicologia_principal_2026"),
        "seguimientos": safe_count("SELECT COUNT(*) FROM pcf_psicologia_seguimientos_2026"),
    }

    res_tramites = ejecutar("SELECT SUM(CAST(realizados AS numeric)) as tot, SUM(CAST(efectivos AS numeric)) as res, SUM(CAST(errores AS numeric)) as err FROM tramites_consolidados_2026")
    tr_tot = res_tramites[0]["tot"] or 0 if res_tramites else 0
    tr_res = res_tramites[0]["res"] or 0 if res_tramites else 0
    tr_err = res_tramites[0]["err"] or 0 if res_tramites else 0

    res_tramites_nombres = ejecutar("SELECT nombres_realizados FROM tramites_consolidados_2026 WHERE nombres_realizados IS NOT NULL")
    conteo_tramites = {}
    for row in res_tramites_nombres:
        texto = str(row["nombres_realizados"])
        if texto and "Ningún" not in texto and texto != 'None':
            items = texto.split("|")
            for item in items:
                val = item.strip()
                if val:
                    conteo_tramites[val] = conteo_tramites.get(val, 0) + 1

    por_tipo_lista = [{"label": k, "total": v} for k, v in sorted(conteo_tramites.items(), key=lambda x: x[1], reverse=True)]

    data["tramites"] = {
        "total": tr_tot,
        "resolutivos": tr_res,
        "con_error": tr_err,
        "por_tipo": por_tipo_lista,
    }
    return jsonify(data)


@app.route("/api/auditoria", methods=["GET"])
@require_auth
def get_auditoria():
    usuario     = request.args.get("usuario", "").strip()
    fecha_ini   = request.args.get("fecha_inicio", "").strip()
    fecha_fin   = request.args.get("fecha_fin", "").strip()

    if not usuario: return jsonify({"error": "El parámetro 'usuario' es requerido."}), 400
    params = {"usuario": usuario, "fecha_ini": fecha_ini or "2000-01-01", "fecha_fin": fecha_fin or "2099-12-31"}

    def q(table, extra_where=""):
        base = f"""
            SELECT COUNT(*) FROM {table} 
            WHERE LOWER(TRIM(CAST(created_by AS text))) = LOWER(:usuario) 
            AND to_date(SUBSTRING(CAST(created_at AS text), 1, 10), 'YYYY-MM-DD') BETWEEN CAST(:fecha_ini AS DATE) AND CAST(:fecha_fin AS DATE)
        """
        return base + (" AND " + extra_where if extra_where else "")

    def qerr(modulo):
        return f"""
            SELECT COUNT(*) FROM auditoria_errores_2026 
            WHERE LOWER(TRIM(CAST(usuario_creador AS text))) = LOWER(:usuario) 
            AND modulo = '{modulo}' 
            AND to_date(SUBSTRING(CAST(fecha_creacion AS text), 1, 10), 'YYYY-MM-DD') BETWEEN CAST(:fecha_ini AS DATE) AND CAST(:fecha_fin AS DATE)
        """

    data = {"usuario": usuario, "rango_fechas": f"{params['fecha_ini']} / {params['fecha_fin']}"}

    data["desistimientos"] = {"total": safe_count(q("desistimiento_aps_2026"), params), "con_error": safe_count(qerr("DESISTIMIENTOS"), params)}
    data["pcc"] = {"planes": safe_count(q("pcc_principal_2026"), params), "integrantes": safe_count(q("pcc_integrantes_2026"), params), "con_error": safe_count(qerr("PCC_PRINCIPAL"), params)}

    query_edades_aud = """
    WITH fechas_limpias AS (
        SELECT 
            to_date(SUBSTRING(CAST(created_at AS text), 1, 10), 'YYYY-MM-DD') as f_crea,
            TRIM(CAST("107_7_fecha_de_nacim" AS text)) as f_nac_raw
        FROM caracterizacion_si_aps_individual_2026
        WHERE LOWER(TRIM(CAST(created_by AS text))) = LOWER(:usuario)
        AND to_date(SUBSTRING(CAST(created_at AS text), 1, 10), 'YYYY-MM-DD') BETWEEN CAST(:fecha_ini AS DATE) AND CAST(:fecha_fin AS DATE)
        AND "107_7_fecha_de_nacim" IS NOT NULL 
    ),
    edades AS (
        SELECT 
            f_crea,
            CASE 
                WHEN f_nac_raw ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}' THEN to_date(LEFT(f_nac_raw, 10), 'YYYY-MM-DD')
                WHEN f_nac_raw ~ '^[0-9]{2}/[0-9]{2}/[0-9]{4}' THEN to_date(LEFT(f_nac_raw, 10), 'DD/MM/YYYY')
                ELSE NULL 
            END as f_nac
        FROM fechas_limpias
    )
    SELECT 
        COUNT(*) FILTER (WHERE EXTRACT(YEAR FROM AGE(f_crea, f_nac)) < 5) as menores,
        COUNT(*) FILTER (WHERE EXTRACT(YEAR FROM AGE(f_crea, f_nac)) >= 60) as mayores
    FROM edades 
    WHERE f_nac IS NOT NULL
    """
    res_edades_aud = ejecutar(query_edades_aud, params)
    men_5_aud = res_edades_aud[0]["menores"] if res_edades_aud else 0
    may_60_aud = res_edades_aud[0]["mayores"] if res_edades_aud else 0

    # === NUEVAS CONSULTAS: PERFIL SOCIAL Y ETNIA (AUDITORÍA) ===
    tipo_familia_aud = safe_group(f"""
        SELECT "64_41_tipo_de_famili", COUNT(*) as total 
        FROM caracterizacion_si_aps_familiar_2026 
        WHERE LOWER(TRIM(CAST(created_by AS text))) = LOWER(:usuario) 
        AND to_date(SUBSTRING(CAST(created_at AS text), 1, 10), 'YYYY-MM-DD') BETWEEN CAST(:fecha_ini AS DATE) AND CAST(:fecha_fin AS DATE)
        AND "64_41_tipo_de_famili" IS NOT NULL 
        GROUP BY 1 ORDER BY 2 DESC
    """, params)

    estrato_aud = safe_group(f"""
        SELECT "23_12_estrato_socioe", COUNT(*) as total 
        FROM caracterizacion_si_aps_familiar_2026 
        WHERE LOWER(TRIM(CAST(created_by AS text))) = LOWER(:usuario) 
        AND to_date(SUBSTRING(CAST(created_at AS text), 1, 10), 'YYYY-MM-DD') BETWEEN CAST(:fecha_ini AS DATE) AND CAST(:fecha_fin AS DATE)
        AND "23_12_estrato_socioe" IS NOT NULL 
        GROUP BY 1 ORDER BY 1
    """, params)

    nivel_educativo_aud = safe_group(f"""
        SELECT "112_12_nivel_educati", COUNT(*) as total 
        FROM caracterizacion_si_aps_individual_2026 
        WHERE LOWER(TRIM(CAST(created_by AS text))) = LOWER(:usuario) 
        AND to_date(SUBSTRING(CAST(created_at AS text), 1, 10), 'YYYY-MM-DD') BETWEEN CAST(:fecha_ini AS DATE) AND CAST(:fecha_fin AS DATE)
        AND "112_12_nivel_educati" IS NOT NULL 
        GROUP BY 1 ORDER BY 2 DESC
    """, params)

    etnia_comp_aud = ejecutar("""
        SELECT 
            COUNT(*) FILTER (WHERE "116_16_pertenencia_t" = '7. Ninguna' OR "116_16_pertenencia_t" IS NULL) AS sin_etnia,
            COUNT(*) FILTER (WHERE "116_16_pertenencia_t" IS NOT NULL AND "116_16_pertenencia_t" != '7. Ninguna') AS con_etnia,
            COUNT(*) AS total 
        FROM caracterizacion_si_aps_individual_2026
        WHERE LOWER(TRIM(CAST(created_by AS text))) = LOWER(:usuario) 
        AND to_date(SUBSTRING(CAST(created_at AS text), 1, 10), 'YYYY-MM-DD') BETWEEN CAST(:fecha_ini AS DATE) AND CAST(:fecha_fin AS DATE)
    """, params)

    etnia_data_aud = etnia_comp_aud[0] if etnia_comp_aud else {"sin_etnia": 0, "con_etnia": 0, "total": 0}
    total_etnia_aud = int(etnia_data_aud.get("total") or 1)
    if total_etnia_aud == 0: total_etnia_aud = 1

    data["caracterizacion"] = {
        "familias": safe_count(q("caracterizacion_si_aps_familiar_2026", "\"1_1_consentimiento_i\" = '1. SI'"), params),
        "individuos": safe_count(q("caracterizacion_si_aps_individual_2026"), params),
        "gestantes": safe_count(q("caracterizacion_si_aps_individual_2026", "\"109_9_se_encuentra_e\" = '1. SI'"), params),
        "menores_5": men_5_aud,
        "adultos_60": may_60_aud,
        "victimas_conflicto": safe_count(q("caracterizacion_si_aps_familiar_2026", "\"78_52_familia_vctima\" = '1. SI'"), params),
        "poblacion_etnica": safe_count(q("caracterizacion_si_aps_individual_2026", "\"116_16_pertenencia_t\" IS NOT NULL AND \"116_16_pertenencia_t\" != '7. Ninguna'"), params),
        "error_familiar": safe_count(qerr("CARACT_FAMILIAR"), params),
        "error_individual": safe_count(qerr("CARACT_INDIVIDUAL"), params),
        "tipo_familia": tipo_familia_aud,
        "estrato": estrato_aud,
        "nivel_educativo": nivel_educativo_aud,
        "etnia_sin_pct": round(int(etnia_data_aud.get("sin_etnia") or 0) / total_etnia_aud * 100, 1),
        "etnia_con_pct": round(int(etnia_data_aud.get("con_etnia") or 0) / total_etnia_aud * 100, 1),
        "etnia_con_total": int(etnia_data_aud.get("con_etnia") or 0)
    }

    # =========================================================================
    pcf_fam_count = safe_count(q("pcf_planes_principal_2026", "(\"4_3_perfil_profesion\" IS NULL OR TRIM(\"4_3_perfil_profesion\") != 'Profesional Psicología')"), params)
    texto_pcf_fam = ""
    texto_err_pcf = ""

    if pcf_fam_count > 0:
        try:
            res_pcf_fam = ejecutar("""
                SELECT ec5_uuid, created_at 
                FROM pcf_planes_principal_2026 
                WHERE LOWER(TRIM(CAST(created_by AS text))) = LOWER(:usuario) 
                AND to_date(SUBSTRING(CAST(created_at AS text), 1, 10), 'YYYY-MM-DD') BETWEEN CAST(:fecha_ini AS DATE) AND CAST(:fecha_fin AS DATE)
                AND ("4_3_perfil_profesion" IS NULL OR TRIM("4_3_perfil_profesion") != 'Profesional Psicología')
            """, params)
            for idx, r in enumerate(res_pcf_fam, 1):
                texto_pcf_fam += f"Intervención {idx}: Ficha [{r.get('ec5_uuid', 'N/A')}] - {str(r.get('created_at', ''))[:10]}\n"
        except: pass

    try:
        res_err_pcf = ejecutar("""
            SELECT id_ficha, detalle_inconsistencias, modulo 
            FROM auditoria_errores_2026
            WHERE LOWER(TRIM(CAST(usuario_creador AS text))) = LOWER(:usuario)
            AND modulo IN ('PCF_PRINCIPAL', 'PCF_INTEGRANTES')
            AND to_date(SUBSTRING(CAST(fecha_creacion AS text), 1, 10), 'YYYY-MM-DD') BETWEEN CAST(:fecha_ini AS DATE) AND CAST(:fecha_fin AS DATE)
        """, params)
        for idx, r in enumerate(res_err_pcf, 1):
            texto_err_pcf += f"{idx}. [{r['modulo']}] Ficha [{r['id_ficha']}]: {r['detalle_inconsistencias']}\n"
    except: pass

    data["pcf"] = {
        "familias_intervenidas": pcf_fam_count,
        "integrantes_intervenidos": safe_count(q("pcf_planes_integrantes_2026"), params),
        "reporte_familias": texto_pcf_fam if texto_pcf_fam else "No hay intervenciones familiares registradas en estas fechas.",
        "reporte_errores": texto_err_pcf if texto_err_pcf else "✅ Excelente. No hay errores de registro en Plan Cuidado Familiar."
    }

    fam_psico_count = safe_count(q("pcf_planes_principal_2026", "TRIM(\"4_3_perfil_profesion\") = 'Profesional Psicología'"), params)
    seg_psico_count = safe_count(q("pcf_psicologia_seguimientos_2026"), params)

    texto_psico_fam = ""
    texto_psico_seg = ""
    texto_err_psico = ""
    msg_no_psicologo = "El encuestador no registró atenciones bajo el perfil 'Profesional Psicología' o no aplica."
    es_psicologo = (fam_psico_count > 0 or seg_psico_count > 0)

    if es_psicologo:
        try:
            res_psico_fam = ejecutar("""
                SELECT ec5_uuid, created_at 
                FROM pcf_planes_principal_2026 
                WHERE LOWER(TRIM(CAST(created_by AS text))) = LOWER(:usuario) 
                AND to_date(SUBSTRING(CAST(created_at AS text), 1, 10), 'YYYY-MM-DD') BETWEEN CAST(:fecha_ini AS DATE) AND CAST(:fecha_fin AS DATE)
                AND TRIM("4_3_perfil_profesion") = 'Profesional Psicología'
            """, params)
            for idx, r in enumerate(res_psico_fam, 1):
                texto_psico_fam += f"Intervención {idx}: Ficha [{r.get('ec5_uuid', 'N/A')}] - {str(r.get('created_at', ''))[:10]}\n"
        except: pass

        try:
            res_psico_seg = ejecutar("""
                SELECT ec5_uuid, created_at
                FROM pcf_psicologia_seguimientos_2026 
                WHERE LOWER(TRIM(CAST(created_by AS text))) = LOWER(:usuario) 
                AND to_date(SUBSTRING(CAST(created_at AS text), 1, 10), 'YYYY-MM-DD') BETWEEN CAST(:fecha_ini AS DATE) AND CAST(:fecha_fin AS DATE)
            """, params)
            for idx, r in enumerate(res_psico_seg, 1):
                texto_psico_seg += f"Seguimiento {idx}: Ficha [{r.get('ec5_uuid', 'N/A')}] - {str(r.get('created_at', ''))[:10]}\n"
        except: pass

        try:
            res_err_psico = ejecutar("""
                SELECT id_ficha, detalle_inconsistencias, modulo
                FROM auditoria_errores_2026
                WHERE LOWER(TRIM(CAST(usuario_creador AS text))) = LOWER(:usuario)
                AND modulo IN ('PSICOLOGIA_PRINCIPAL', 'PSICOLOGIA_SEGUIMIENTOS')
                AND to_date(SUBSTRING(CAST(fecha_creacion AS text), 1, 10), 'YYYY-MM-DD') BETWEEN CAST(:fecha_ini AS DATE) AND CAST(:fecha_fin AS DATE)
            """, params)
            for idx, r in enumerate(res_err_psico, 1):
                texto_err_psico += f"{idx}. [{r['modulo']}] Ficha [{r['id_ficha']}]: {r['detalle_inconsistencias']}\n"
        except: pass

    data["pcf_psicologia"] = {
        "intervenciones_familiares": fam_psico_count,
        "integrantes": safe_count(q("pcf_psicologia_principal_2026"), params),
        "seguimientos": seg_psico_count,
        "reporte_familias": texto_psico_fam if texto_psico_fam else (msg_no_psicologo if not es_psicologo else "No hay nuevas intervenciones familiares en estas fechas."),
        "reporte_seguimientos": texto_psico_seg if texto_psico_seg else (msg_no_psicologo if not es_psicologo else "No hay seguimientos en estas fechas."),
        "reporte_errores": texto_err_psico if texto_err_psico else (msg_no_psicologo if not es_psicologo else "✅ Excelente. No hay errores de psicología.")
    }

    res_tram_aud = ejecutar("""
        SELECT SUM(CAST(realizados AS numeric)) as tot, SUM(CAST(efectivos AS numeric)) as res, SUM(CAST(errores AS numeric)) as err 
        FROM tramites_consolidados_2026 
        WHERE LOWER(TRIM(CAST(usuario AS text))) = LOWER(:usuario) 
        AND to_date(SUBSTRING(CAST(fecha AS text), 1, 10), 'YYYY-MM-DD') BETWEEN CAST(:fecha_ini AS DATE) AND CAST(:fecha_fin AS DATE)
    """, params)

    a_tr_tot = res_tram_aud[0]["tot"] or 0 if res_tram_aud else 0
    a_tr_res = res_tram_aud[0]["res"] or 0 if res_tram_aud else 0
    a_tr_err = res_tram_aud[0]["err"] or 0 if res_tram_aud else 0

    res_tramites_textos = ejecutar("""
        SELECT nombres_realizados, nombres_efectivos 
        FROM tramites_consolidados_2026 
        WHERE LOWER(TRIM(CAST(usuario AS text))) = LOWER(:usuario) 
        AND to_date(SUBSTRING(CAST(fecha AS text), 1, 10), 'YYYY-MM-DD') BETWEEN CAST(:fecha_ini AS DATE) AND CAST(:fecha_fin AS DATE)
    """, params)

    conteo_tramites_aud = {}
    texto_realizados = ""
    texto_resueltos = ""

    c_re = 1
    c_ef = 1

    for row in res_tramites_textos:
        nr = str(row["nombres_realizados"])
        ne = str(row["nombres_efectivos"])

        if nr and "Ningún" not in nr and nr != 'None':
            texto_realizados += f"Registro {c_re}: {nr.replace('|', ', ')}\n"
            c_re += 1
            items = nr.split("|")
            for item in items:
                val = item.strip()
                if val: conteo_tramites_aud[val] = conteo_tramites_aud.get(val, 0) + 1

        if ne and "Ningún" not in ne and ne != 'None':
            texto_resueltos += f"Registro {c_ef}: {ne.replace('|', ', ')}\n"
            c_ef += 1

    por_tipo_lista_aud = [{"label": k, "total": v} for k, v in sorted(conteo_tramites_aud.items(), key=lambda x: x[1], reverse=True)]

    res_err_tr = ejecutar("""
        SELECT id_ficha, detalle_inconsistencias 
        FROM auditoria_errores_2026
        WHERE LOWER(TRIM(CAST(usuario_creador AS text))) = LOWER(:usuario)
        AND modulo = 'TRAMITES'
        AND to_date(SUBSTRING(CAST(fecha_creacion AS text), 1, 10), 'YYYY-MM-DD') BETWEEN CAST(:fecha_ini AS DATE) AND CAST(:fecha_fin AS DATE)
    """, params)

    texto_errores_tr = ""
    c_err = 1
    for row in res_err_tr:
        texto_errores_tr += f"{c_err}. Ficha [{row['id_ficha']}]: {row['detalle_inconsistencias']}\n"
        c_err += 1

    data["tramites"] = {
        "total": a_tr_tot,
        "resolutivos": a_tr_res,
        "con_error": a_tr_err,
        "por_tipo": por_tipo_lista_aud,
        "reporte_realizados": texto_realizados if texto_realizados else "No hay trámites realizados en estas fechas.",
        "reporte_resueltos": texto_resueltos if texto_resueltos else "No hay trámites resueltos en estas fechas.",
        "reporte_errores": texto_errores_tr if texto_errores_tr else "✅ Excelente. No hay trámites con errores."
    }

    query_errores = text("""
        SELECT modulo, id_ficha, titulo_ficha, cantidad_errores, detalle_inconsistencias 
        FROM auditoria_errores_2026
        WHERE LOWER(TRIM(CAST(usuario_creador AS text))) = LOWER(:usuario)
        AND to_date(SUBSTRING(CAST(fecha_creacion AS text), 1, 10), 'YYYY-MM-DD') BETWEEN CAST(:fecha_ini AS DATE) AND CAST(:fecha_fin AS DATE)
        ORDER BY modulo, cantidad_errores DESC
    """)
    lista_errores_texto = []
    try:
        with engine.connect() as conn:
            res_errores = conn.execute(query_errores, params)
            for row in res_errores.mappings():
                texto = (
                    f"🛑 MÓDULO: {row['modulo']}\n"
                    f"Ficha ID: {row['id_ficha']} | Título: {row['titulo_ficha']}\n"
                    f"Errores ({row['cantidad_errores']}): {row['detalle_inconsistencias']}\n"
                    f"--------------------------------------------------"
                )
                lista_errores_texto.append(texto)
    except Exception as e: pass

    data["reporte_errores_texto"] = "\n".join(lista_errores_texto) if lista_errores_texto else "✅ ¡Felicitaciones! No se encontraron errores de auditoría para este encuestador en estas fechas."

    return jsonify(data)

@app.route("/api/health", methods=["GET"])
def health(): return jsonify({"status": "ok"}), 200

if __name__ == "__main__":
    port = int(os.getenv("PORT_INFORMES", 5001))
    app.run(host="0.0.0.0", port=port, debug=False)
