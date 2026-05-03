# -*- coding: utf-8 -*-
"""
Backend API – Módulo INFORMES (Dashboard + Auditoría + Mapas + Logs + SIHOS)
Framework  : Flask + SQLAlchemy + PyJWT
"""

import os
import logging
import datetime
from functools import wraps
from collections import Counter
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

app = Flask(__name__, static_folder=DIR_BASE)
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
        try:
            return int(val or 0)
        except:
            return 0
    return 0


def safe_group(query_str: str, params: dict = None) -> list:
    rows = ejecutar(query_str, params)
    result = []
    for row in rows:
        vals = list(row.values())
        if len(vals) >= 2: result.append({"label": str(vals[0] or "Sin dato"), "total": int(vals[1] or 0)})
    return result


def generar_token(user_id: int, correo: str, nombre: str, rol: str) -> str:
    payload = {"user_id": user_id, "correo": correo, "nombre": nombre, "rol": rol,
               "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=TOKEN_HOURS)}
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def verificar_token(token: str) -> dict | None:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
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


# ── RUTAS HTML ──
@app.route("/")
@app.route("/login")
def login_page(): return send_from_directory(DIR_BASE, "login.html")


@app.route("/dashboard")
def dashboard_page(): return send_from_directory(DIR_BASE, "dashboard.html")


@app.route("/auditoria")
def auditoria_page(): return send_from_directory(DIR_BASE, "auditoria.html")


@app.route("/sihos")
def sihos_page(): return send_from_directory(DIR_BASE, "sihos.html")


@app.route("/mapas")
def mapas_page(): return send_from_directory(DIR_BASE, "mapas.html")


@app.route("/informes")
def informes_page(): return send_from_directory(DIR_BASE, "informes.html")


@app.route("/firma.webp")
def firma_page(): return send_from_directory(DIR_BASE, "firma.webp")


@app.route("/logo-ese.png")
def logoese_page(): return send_from_directory(DIR_BASE, "logo-ese.png")


@app.route("/logo-aps.png")
def logoaps_page(): return send_from_directory(DIR_BASE, "logo-aps.png")


# ── API AUTENTICACIÓN ──
@app.route("/api/login", methods=["POST"])
def login():
    body = request.get_json(silent=True) or {}
    correo = str(body.get("correo", "")).strip().lower()
    password = str(body.get("password", "")).strip()
    fingerprint = str(body.get("device_fingerprint", "")).strip()

    if not correo or not password: return jsonify({"error": "Credenciales requeridas"}), 400

    rows = ejecutar(
        "SELECT id, username, password_hash, device_id FROM usuarios WHERE LOWER(TRIM(username)) = :u LIMIT 1",
        {"u": correo})
    if not rows: return jsonify({"error": "Credenciales incorrectas"}), 401

    usuario = rows[0]
    if not check_password_hash(usuario["password_hash"], password): return jsonify(
        {"error": "Credenciales incorrectas"}), 401

    stored_fp = usuario.get("device_id")
    if not stored_fp:
        try:
            with engine.begin() as conn:
                conn.execute(text("UPDATE usuarios SET device_id = :fp WHERE id = :uid"),
                             {"fp": fingerprint, "uid": usuario["id"]})
        except:
            pass
    elif stored_fp != fingerprint:
        return jsonify({"error": "Acceso denegado: Usuario vinculado a otro dispositivo."}), 403

    nombre_visual = usuario["username"].capitalize()
    token = generar_token(user_id=usuario["id"], correo=usuario["username"], nombre=nombre_visual, rol="Auditor")

    logger.info(f"🟢 [LOGIN_EXITOSO] El usuario '{nombre_visual}' ha iniciado sesión en el sistema.")
    return jsonify({"token": token, "nombre": nombre_visual, "rol": "Auditor"})


@app.route("/api/logout", methods=["POST"])
def logout():
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        payload = verificar_token(auth.split(" ")[1])
        if payload:
            logger.info(f"🔴 [LOGOUT] El usuario '{payload.get('nombre', 'Desconocido')}' cerró sesión.")
    return jsonify({"status": "Cierre de sesión exitoso"}), 200


@app.route("/api/encuestadores", methods=["GET"])
@require_auth
def get_encuestadores():
    rows = ejecutar("""
                    SELECT DISTINCT LOWER(TRIM(CAST(created_by AS text))) as correo
                    FROM (SELECT created_by
                          FROM caracterizacion_si_aps_individual_2026
                          UNION
                          SELECT created_by
                          FROM pcc_principal_2026
                          UNION
                          SELECT created_by
                          FROM pcf_planes_principal_2026
                          UNION
                          SELECT created_by
                          FROM desistimiento_aps_2026) AS tbl
                    WHERE created_by IS NOT NULL
                      AND created_by != ''
                    """)
    return jsonify([r["correo"] for r in rows if r["correo"]])


# ── FUNCION TRADUCTORA DE FECHAS ──
def get_date_filter(col_name):
    return f"""
    (CASE 
        WHEN CAST({col_name} AS text) ~ '^[0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}}' THEN to_date(LEFT(CAST({col_name} AS text), 10), 'YYYY-MM-DD') 
        WHEN CAST({col_name} AS text) ~ '^[0-9]{{2}}/[0-9]{{2}}/[0-9]{{4}}' THEN to_date(LEFT(CAST({col_name} AS text), 10), 'DD/MM/YYYY') 
        ELSE '1900-01-01'::date 
    END) >= to_date(:f_ini, 'YYYY-MM-DD') 
    AND 
    (CASE 
        WHEN CAST({col_name} AS text) ~ '^[0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}}' THEN to_date(LEFT(CAST({col_name} AS text), 10), 'YYYY-MM-DD') 
        WHEN CAST({col_name} AS text) ~ '^[0-9]{{2}}/[0-9]{{2}}/[0-9]{{4}}' THEN to_date(LEFT(CAST({col_name} AS text), 10), 'DD/MM/YYYY') 
        ELSE '2100-01-01'::date 
    END) <= to_date(:f_fin, 'YYYY-MM-DD')
    """


# ── API DASHBOARD GENERAL ──
@app.route("/api/dashboard", methods=["GET"])
@require_auth
def get_dashboard():
    usuario_req = g.user.get('nombre', 'Desconocido')

    fecha_ini = request.args.get("fecha_inicio", "").strip()
    fecha_fin = request.args.get("fecha_fin", "").strip()

    logger.info(f"📊 [DASHBOARD] El usuario '{usuario_req}' actualizando. Rango: {fecha_ini} a {fecha_fin}")

    f_ini = fecha_ini or "2000-01-01"
    f_fin = fecha_fin or "2099-12-31"
    f_fin_limite = f"{fecha_fin}T23:59:59" if fecha_fin else "2099-12-31T23:59:59"

    params = {"f_ini": f_ini, "f_fin": f_fin, "f_fin_limite": f_fin_limite}

    def q(table, extra_where=""):
        base = f"SELECT COUNT(*) FROM {table} WHERE {get_date_filter('created_at')}"
        if extra_where: base += f" AND {extra_where}"
        return safe_count(base, params)

    data = {}

    data["desistimientos"] = {
        "total": q("desistimiento_aps_2026"),
        "con_error": safe_count(
            f"SELECT COUNT(*) FROM auditoria_errores_2026 WHERE modulo = 'DESISTIMIENTOS' AND {get_date_filter('fecha_creacion')}",
            params),
    }

    query_pcc_int = f"""
        SELECT COUNT(*) FROM pcc_integrantes_2026 b
        JOIN pcc_principal_2026 p ON b.ec5_branch_owner_uuid = p.ec5_uuid
        WHERE {get_date_filter('p.created_at')}
    """
    data["pcc"] = {
        "planes": q("pcc_principal_2026"),
        "integrantes": safe_count(query_pcc_int, params),
        "con_error": safe_count(
            f"SELECT COUNT(*) FROM auditoria_errores_2026 WHERE modulo LIKE 'PCC%' AND {get_date_filter('fecha_creacion')}",
            params),
    }

    query_edades = f"""
                   WITH fechas_limpias AS (
                        SELECT CASE 
                                   WHEN CAST(created_at AS text) ~ '^[0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}}' THEN to_date(LEFT(CAST(created_at AS text), 10), 'YYYY-MM-DD') 
                                   WHEN CAST(created_at AS text) ~ '^[0-9]{{2}}/[0-9]{{2}}/[0-9]{{4}}' THEN to_date(LEFT(CAST(created_at AS text), 10), 'DD/MM/YYYY') 
                                   ELSE NULL END as f_crea,
                               TRIM(CAST("107_7_fecha_de_nacim" AS text)) as f_nac_raw 
                        FROM caracterizacion_si_aps_individual_2026 
                        WHERE "107_7_fecha_de_nacim" IS NOT NULL
                          AND {get_date_filter('created_at')}
                   ), 
                   edades AS (
                        SELECT f_crea, 
                               CASE 
                                   WHEN f_nac_raw ~ '^[0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}}' THEN to_date(LEFT(f_nac_raw, 10), 'YYYY-MM-DD') 
                                   WHEN f_nac_raw ~ '^[0-9]{{2}}/[0-9]{{2}}/[0-9]{{4}}' THEN to_date(LEFT(f_nac_raw, 10), 'DD/MM/YYYY') 
                                   ELSE NULL END as f_nac 
                        FROM fechas_limpias
                   )
                   SELECT COUNT(*) FILTER (WHERE EXTRACT(YEAR FROM AGE(f_crea, f_nac)) < 5) as menores, 
                          COUNT(*) FILTER (WHERE EXTRACT(YEAR FROM AGE(f_crea, f_nac)) >= 60) as mayores
                   FROM edades WHERE f_nac IS NOT NULL AND f_crea IS NOT NULL
                   """
    res_edades = ejecutar(query_edades, params)
    menores_5 = res_edades[0]["menores"] if res_edades else 0
    adultos_60 = res_edades[0]["mayores"] if res_edades else 0

    etnia_comp = ejecutar(f"""
                          SELECT COUNT(*) FILTER (WHERE "116_16_pertenencia_t" = '7. Ninguna' OR "116_16_pertenencia_t" IS NULL) AS sin_etnia, 
                                 COUNT(*) FILTER (WHERE "116_16_pertenencia_t" IS NOT NULL AND "116_16_pertenencia_t" != '7. Ninguna') AS con_etnia, 
                                 COUNT(*) AS total
                          FROM caracterizacion_si_aps_individual_2026
                          WHERE {get_date_filter('created_at')}
                          """, params)
    etnia_data = etnia_comp[0] if etnia_comp else {"sin_etnia": 0, "con_etnia": 0, "total": 0}
    total_etnia = int(etnia_data.get("total") or 1)

    query_disc = f"""
                 SELECT "119_19_reconoce_algu" as disc
                 FROM caracterizacion_si_aps_individual_2026
                 WHERE "119_19_reconoce_algu" IS NOT NULL
                   AND {get_date_filter('created_at')}
                 """
    res_disc = ejecutar(query_disc, params)
    total_discapacidad = 0
    conteo_disc = {}

    for r in res_disc:
        texto = str(r["disc"])
        if not texto or texto == 'None': continue
        items = [x.strip() for x in texto.split(",")]
        has_sin = any("Sin discapacidad" in x for x in items)
        if not has_sin:
            total_discapacidad += 1
            for item in items:
                if item: conteo_disc[item] = conteo_disc.get(item, 0) + 1
    disc_chart = [{"label": k, "total": v} for k, v in sorted(conteo_disc.items(), key=lambda x: x[1], reverse=True)]

    data["caracterizacion"] = {
        "familias": q("caracterizacion_si_aps_familiar_2026", "\"1_1_consentimiento_i\" = '1. SI'"),
        "individuos": q("caracterizacion_si_aps_individual_2026"),
        "sin_aseguramiento": safe_count(
            f"SELECT COUNT(DISTINCT ec5_branch_owner_uuid) FROM caracterizacion_si_aps_individual_2026 WHERE \"113_13_rgimen_de_afi\" = '5. No afiliado' AND {get_date_filter('created_at')}",
            params),
        "gestantes": q("caracterizacion_si_aps_individual_2026", "\"109_9_se_encuentra_e\" = '1. SI'"),
        "menores_5": menores_5, "adultos_60": adultos_60,
        "victimas_conflicto": q("caracterizacion_si_aps_familiar_2026", "\"78_52_familia_vctima\" = '1. SI'"),
        "poblacion_etnica": q("caracterizacion_si_aps_individual_2026",
                              "\"116_16_pertenencia_t\" IS NOT NULL AND \"116_16_pertenencia_t\" != '7. Ninguna'"),
        "discapacidad_total": total_discapacidad, "discapacidades_chart": disc_chart,
        "tipo_familia": safe_group(
            f"SELECT \"64_41_tipo_de_famili\", COUNT(*) as total FROM caracterizacion_si_aps_familiar_2026 WHERE \"64_41_tipo_de_famili\" IS NOT NULL AND {get_date_filter('created_at')} GROUP BY 1 ORDER BY 2 DESC",
            params),
        "estrato": safe_group(
            f"SELECT \"23_12_estrato_socioe\", COUNT(*) as total FROM caracterizacion_si_aps_familiar_2026 WHERE \"23_12_estrato_socioe\" IS NOT NULL AND {get_date_filter('created_at')} GROUP BY 1 ORDER BY 1",
            params),
        "nivel_educativo": safe_group(
            f"SELECT \"112_12_nivel_educati\", COUNT(*) as total FROM caracterizacion_si_aps_individual_2026 WHERE \"112_12_nivel_educati\" IS NOT NULL AND {get_date_filter('created_at')} GROUP BY 1 ORDER BY 2 DESC",
            params),
        "etnia_sin_pct": round(int(etnia_data.get("sin_etnia") or 0) / total_etnia * 100, 1) if total_etnia > 0 else 0,
        "etnia_con_pct": round(int(etnia_data.get("con_etnia") or 0) / total_etnia * 100, 1) if total_etnia > 0 else 0,
        "etnia_con_total": int(etnia_data.get("con_etnia") or 0),
        "error_familiar": safe_count(
            f"SELECT COUNT(*) FROM auditoria_errores_2026 WHERE modulo = 'CARACT_FAMILIAR' AND {get_date_filter('fecha_creacion')}",
            params),
        "error_individual": safe_count(
            f"SELECT COUNT(*) FROM auditoria_errores_2026 WHERE modulo = 'CARACT_INDIVIDUAL' AND {get_date_filter('fecha_creacion')}",
            params),
    }

    query_pcf_int = f"""
        SELECT COUNT(*) FROM pcf_planes_integrantes_2026 b
        JOIN pcf_planes_principal_2026 p ON b.ec5_branch_owner_uuid = p.ec5_uuid
        WHERE {get_date_filter('p.created_at')}
    """
    data["pcf"] = {
        "familias_intervenidas": q("pcf_planes_principal_2026",
                                   "(\"4_3_perfil_profesion\" IS NULL OR TRIM(\"4_3_perfil_profesion\") != 'Profesional Psicología')"),
        "integrantes_intervenidos": safe_count(query_pcf_int, params),
    }

    data["pcf_psicologia"] = {
        "intervenciones_familiares": q("pcf_planes_principal_2026",
                                       "TRIM(\"4_3_perfil_profesion\") = 'Profesional Psicología'"),
        "integrantes": q("pcf_psicologia_principal_2026"),
        "seguimientos": q("pcf_psicologia_seguimientos_2026"),
    }

    res_tramites = ejecutar(
        f"SELECT SUM(CAST(realizados AS numeric)) as tot, SUM(CAST(efectivos AS numeric)) as res, SUM(CAST(errores AS numeric)) as err FROM tramites_consolidados_2026 WHERE {get_date_filter('fecha')}",
        params)
    tr_tot = res_tramites[0]["tot"] or 0 if res_tramites else 0
    tr_res = res_tramites[0]["res"] or 0 if res_tramites else 0
    tr_err = res_tramites[0]["err"] or 0 if res_tramites else 0

    res_tramites_nombres = ejecutar(
        f"SELECT nombres_realizados FROM tramites_consolidados_2026 WHERE nombres_realizados IS NOT NULL AND {get_date_filter('fecha')}",
        params)
    conteo_tramites = {}
    for row in res_tramites_nombres:
        texto = str(row["nombres_realizados"])
        if texto and "Ningún" not in texto and texto != 'None':
            items = texto.split("|")
            for item in items:
                val = item.strip()
                if val: conteo_tramites[val] = conteo_tramites.get(val, 0) + 1
    por_tipo_lista = [{"label": k, "total": v} for k, v in
                      sorted(conteo_tramites.items(), key=lambda x: x[1], reverse=True)]

    tr_registros = q("tramites_aps_2026")
    tr_familias_query = f"""
                        SELECT COUNT(DISTINCT
                                     COALESCE("7_4_territorio", '') || COALESCE("8_5_microterritorio", '') ||
                                     CASE WHEN "3_2_cdigo_hogar" = 'No Aplica' OR "3_2_cdigo_hogar" IS NULL THEN COALESCE("4_21_cdigo_hogar", '') ELSE "3_2_cdigo_hogar" END ||
                                     CASE WHEN "5_3_cdigo_familia" = 'No Aplica' OR "5_3_cdigo_familia" IS NULL THEN COALESCE("6_31_cdigo_familia", '') ELSE "5_3_cdigo_familia" END
                               ) as total 
                        FROM tramites_aps_2026
                        WHERE {get_date_filter('created_at')}
                        """
    tr_fam_res = ejecutar(tr_familias_query, params)
    tr_familias = tr_fam_res[0]["total"] if tr_fam_res else 0

    data["tramites"] = {
        "total": tr_tot, "resolutivos": tr_res, "con_error": tr_err, "por_tipo": por_tipo_lista,
        "total_registros": tr_registros, "total_familias": tr_familias
    }
    return jsonify(data)


# ── LOGICA INTERNA DE AUDITORIA ──
def get_auditoria_data(usuario: str, fecha_ini: str, fecha_fin: str) -> dict:
    f_ini = fecha_ini or "2000-01-01"
    f_fin = fecha_fin or "2099-12-31"
    f_fin_limite = f"{fecha_fin}T23:59:59" if fecha_fin else "2099-12-31T23:59:59"

    params = {"usuario": usuario, "fecha_ini": f_ini, "fecha_fin_limite": f_fin_limite, "f_ini": f_ini, "f_fin": f_fin}

    def q(table, extra_where=""):
        base = f"""
            SELECT COUNT(*) FROM {table} 
            WHERE LOWER(TRIM(CAST(created_by AS text))) = LOWER(:usuario) 
            AND CAST(created_at AS text) >= :fecha_ini 
            AND CAST(created_at AS text) <= :fecha_fin_limite
        """
        return base + (" AND " + extra_where if extra_where else "")

    def qerr(modulo):
        return f"""
            SELECT COUNT(*) FROM auditoria_errores_2026 
            WHERE LOWER(TRIM(CAST(usuario_creador AS text))) = LOWER(:usuario) 
            AND modulo = '{modulo}' 
            AND CAST(fecha_creacion AS text) >= :fecha_ini 
            AND CAST(fecha_creacion AS text) <= :fecha_fin_limite
        """

    data = {"usuario": usuario, "rango_fechas": f"{params['fecha_ini']} / {fecha_fin}"}

    query_perfil = """
                   SELECT "5_4_nombre_del_profe" as nombre, "4_3_perfil_profesion" as perfil, COUNT(*) as qty
                   FROM pcf_planes_principal_2026
                   WHERE LOWER(TRIM(CAST(created_by AS text))) = LOWER(:usuario)
                     AND CAST(created_at AS text) >= :fecha_ini \
                     AND CAST(created_at AS text) <= :fecha_fin_limite
                     AND "5_4_nombre_del_profe" IS NOT NULL
                   GROUP BY 1, 2
                   ORDER BY qty DESC LIMIT 1 \
                   """
    res_perfil = ejecutar(query_perfil, params)
    if res_perfil:
        data["encuestador_nombre"] = res_perfil[0]["nombre"]
        data["encuestador_perfil"] = res_perfil[0]["perfil"]
    else:
        data["encuestador_nombre"] = "Sin registro de nombre"
        data["encuestador_perfil"] = "Sin registro de perfil"

    data["desistimientos"] = {"total": safe_count(q("desistimiento_aps_2026"), params),
                              "con_error": safe_count(qerr("DESISTIMIENTOS"), params)}

    query_pcc_int = """
                    SELECT COUNT(*) \
                    FROM pcc_integrantes_2026 b \
                             JOIN pcc_principal_2026 p ON b.ec5_branch_owner_uuid = p.ec5_uuid
                    WHERE LOWER(TRIM(CAST(p.created_by AS text))) = LOWER(:usuario)
                      AND CAST(p.created_at AS text) >= :fecha_ini
                      AND CAST(p.created_at AS text) <= :fecha_fin_limite \
                    """
    pcc_planes_count = safe_count(q("pcc_principal_2026"), params)

    texto_pcc_detalles = ""
    if pcc_planes_count > 0:
        try:
            res_pcc = ejecutar("""
                               SELECT ec5_uuid, created_at, "20_14_detalles_jorna"
                               FROM pcc_principal_2026
                               WHERE LOWER(TRIM(CAST(created_by AS text))) = LOWER(:usuario)
                                 AND CAST(created_at AS text) >= :fecha_ini
                                 AND CAST(created_at AS text) <= :fecha_fin_limite
                               """, params)
            for idx, r in enumerate(res_pcc, 1):
                uid_ficha = r.get('ec5_uuid', 'N/A')
                fecha = str(r.get('created_at', ''))[:10]
                detalle = str(r.get("20_14_detalles_jorna", "")).replace('\n', ' ')
                if not detalle or detalle == 'None': detalle = "Sin detalles registrados."
                texto_pcc_detalles += f"Plan {idx} [{uid_ficha}] - {fecha}: {detalle}\n\n"
        except:
            pass

    data["pcc"] = {
        "planes": pcc_planes_count,
        "integrantes": safe_count(query_pcc_int, params),
        "con_error": safe_count(qerr("PCC_PRINCIPAL"), params),
        "reporte_detalles": texto_pcc_detalles.strip() if texto_pcc_detalles else "No hay detalles de planes comunitarios registrados."
    }

    query_edades_aud = """
                       WITH fechas_limpias \
                                AS (SELECT to_date(SUBSTRING(CAST(created_at AS text), 1, 10), 'YYYY-MM-DD') as f_crea, \
                                           TRIM(CAST("107_7_fecha_de_nacim" AS text))                        as f_nac_raw \
                                    FROM caracterizacion_si_aps_individual_2026 \
                                    WHERE LOWER(TRIM(CAST(created_by AS text))) = LOWER(:usuario) \
                                      AND CAST(created_at AS text) >= :fecha_ini \
                                      AND CAST(created_at AS text) <= :fecha_fin_limite \
                                      AND "107_7_fecha_de_nacim" IS NOT NULL), \
                            edades AS (SELECT f_crea, \
                                              CASE \
                                                  WHEN f_nac_raw ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}' THEN to_date(LEFT(f_nac_raw, 10), 'YYYY-MM-DD') \
                                                  WHEN f_nac_raw ~ '^[0-9]{2}/[0-9]{2}/[0-9]{4}' THEN to_date(LEFT(f_nac_raw, 10), 'DD/MM/YYYY') \
                                                  ELSE NULL \
                                                  END as f_nac \
                                       FROM fechas_limpias)
                       SELECT COUNT(*) FILTER (WHERE EXTRACT(YEAR FROM AGE(f_crea, f_nac)) < 5) as menores, COUNT(*) FILTER (WHERE EXTRACT(YEAR FROM AGE(f_crea, f_nac)) >= 60) as mayores
                       FROM edades \
                       WHERE f_nac IS NOT NULL \
                       """
    res_edades_aud = ejecutar(query_edades_aud, params)
    men_5_aud = res_edades_aud[0]["menores"] if res_edades_aud else 0
    may_60_aud = res_edades_aud[0]["mayores"] if res_edades_aud else 0

    tipo_familia_aud = safe_group("""
                                  SELECT "64_41_tipo_de_famili", COUNT(*) as total
                                  FROM caracterizacion_si_aps_familiar_2026
                                  WHERE LOWER(TRIM(CAST(created_by AS text))) = LOWER(:usuario)
                                    AND CAST(created_at AS text) >= :fecha_ini
                                    AND CAST(created_at AS text) <= :fecha_fin_limite
                                    AND "64_41_tipo_de_famili" IS NOT NULL
                                  GROUP BY 1
                                  ORDER BY 2 DESC
                                  """, params)

    estrato_aud = safe_group("""
                             SELECT "23_12_estrato_socioe", COUNT(*) as total
                             FROM caracterizacion_si_aps_familiar_2026
                             WHERE LOWER(TRIM(CAST(created_by AS text))) = LOWER(:usuario)
                               AND CAST(created_at AS text) >= :fecha_ini
                               AND CAST(created_at AS text) <= :fecha_fin_limite
                               AND "23_12_estrato_socioe" IS NOT NULL
                             GROUP BY 1
                             ORDER BY 1
                             """, params)

    nivel_educativo_aud = safe_group("""
                                     SELECT "112_12_nivel_educati", COUNT(*) as total
                                     FROM caracterizacion_si_aps_individual_2026
                                     WHERE LOWER(TRIM(CAST(created_by AS text))) = LOWER(:usuario)
                                       AND CAST(created_at AS text) >= :fecha_ini
                                       AND CAST(created_at AS text) <= :fecha_fin_limite
                                       AND "112_12_nivel_educati" IS NOT NULL
                                     GROUP BY 1
                                     ORDER BY 2 DESC
                                     """, params)

    etnia_comp_aud = ejecutar("""
                              SELECT COUNT(*) FILTER (WHERE "116_16_pertenencia_t" = '7. Ninguna' OR "116_16_pertenencia_t" IS NULL) AS sin_etnia, COUNT(*) FILTER (WHERE "116_16_pertenencia_t" IS NOT NULL AND "116_16_pertenencia_t" != '7. Ninguna') AS con_etnia, COUNT(*) AS total
                              FROM caracterizacion_si_aps_individual_2026
                              WHERE LOWER(TRIM(CAST(created_by AS text))) = LOWER(:usuario)
                                AND CAST(created_at AS text) >= :fecha_ini
                                AND CAST(created_at AS text) <= :fecha_fin_limite
                              """, params)

    etnia_data_aud = etnia_comp_aud[0] if etnia_comp_aud else {"sin_etnia": 0, "con_etnia": 0, "total": 0}
    total_etnia_aud = int(etnia_data_aud.get("total") or 1)
    if total_etnia_aud == 0: total_etnia_aud = 1

    query_disc_aud = """
                     SELECT ec5_branch_owner_uuid as id_ficha, "119_19_reconoce_algu" as disc
                     FROM caracterizacion_si_aps_individual_2026
                     WHERE LOWER(TRIM(CAST(created_by AS text))) = LOWER(:usuario)
                       AND CAST(created_at AS text) >= :fecha_ini \
                       AND CAST(created_at AS text) <= :fecha_fin_limite
                       AND "119_19_reconoce_algu" IS NOT NULL \
                     """
    res_disc_aud = ejecutar(query_disc_aud, params)
    total_discapacidad_aud = 0
    conteo_disc_aud = {}
    errores_dinamicos = []

    for r in res_disc_aud:
        texto = str(r["disc"])
        if not texto or texto == 'None': continue
        items = [x.strip() for x in texto.split(",")]
        has_sin = any("Sin discapacidad" in x for x in items)

        if has_sin:
            if len(items) > 1:
                errores_dinamicos.append(
                    f"🛑 MÓDULO: CARACT_INDIVIDUAL\nFicha ID: {r.get('id_ficha', 'N/A')} | Errores: Contradicción en Discapacidad\n--------------------------------------------------"
                )
        else:
            total_discapacidad_aud += 1
            for item in items:
                if item: conteo_disc_aud[item] = conteo_disc_aud.get(item, 0) + 1

    disc_chart_aud = [{"label": k, "total": v} for k, v in
                      sorted(conteo_disc_aud.items(), key=lambda x: x[1], reverse=True)]

    data["caracterizacion"] = {
        "familias": safe_count(q("caracterizacion_si_aps_familiar_2026", "\"1_1_consentimiento_i\" = '1. SI'"), params),
        "individuos": safe_count(q("caracterizacion_si_aps_individual_2026"), params),
        "gestantes": safe_count(q("caracterizacion_si_aps_individual_2026", "\"109_9_se_encuentra_e\" = '1. SI'"),
                                params),
        "menores_5": men_5_aud, "adultos_60": may_60_aud,
        "victimas_conflicto": safe_count(
            q("caracterizacion_si_aps_familiar_2026", "\"78_52_familia_vctima\" = '1. SI'"), params),
        "poblacion_etnica": safe_count(q("caracterizacion_si_aps_individual_2026",
                                         "\"116_16_pertenencia_t\" IS NOT NULL AND \"116_16_pertenencia_t\" != '7. Ninguna'"),
                                       params),
        "sin_aseguramiento": safe_count(
            q("caracterizacion_si_aps_individual_2026", "\"113_13_rgimen_de_afi\" = '5. No afiliado'"), params),
        "discapacidad_total": total_discapacidad_aud, "discapacidades_chart": disc_chart_aud,
        "error_familiar": safe_count(qerr("CARACT_FAMILIAR"), params),
        "error_individual": safe_count(qerr("CARACT_INDIVIDUAL"), params),
        "tipo_familia": tipo_familia_aud, "estrato": estrato_aud, "nivel_educativo": nivel_educativo_aud,
        "etnia_sin_pct": round(int(etnia_data_aud.get("sin_etnia") or 0) / total_etnia_aud * 100, 1),
        "etnia_con_pct": round(int(etnia_data_aud.get("con_etnia") or 0) / total_etnia_aud * 100, 1),
        "etnia_con_total": int(etnia_data_aud.get("con_etnia") or 0)
    }

    pcf_fam_count = safe_count(q("pcf_planes_principal_2026",
                                 "(\"4_3_perfil_profesion\" IS NULL OR TRIM(\"4_3_perfil_profesion\") != 'Profesional Psicología')"),
                               params)
    texto_pcf_fam = ""
    texto_err_pcf = ""

    if pcf_fam_count > 0:
        try:
            res_pcf_fam = ejecutar("""
                                   SELECT ec5_uuid, created_at
                                   FROM pcf_planes_principal_2026
                                   WHERE LOWER(TRIM(CAST(created_by AS text))) = LOWER(:usuario)
                                     AND CAST(created_at AS text) >= :fecha_ini
                                     AND CAST(created_at AS text) <= :fecha_fin_limite
                                     AND ("4_3_perfil_profesion" IS NULL OR TRIM("4_3_perfil_profesion") != 'Profesional Psicología')
                                   """, params)
            for idx, r in enumerate(res_pcf_fam, 1):
                texto_pcf_fam += f"Intervención {idx}: Ficha [{r.get('ec5_uuid', 'N/A')}] - {str(r.get('created_at', ''))[:10]}\n"
        except:
            pass

    try:
        res_err_pcf = ejecutar("""
                               SELECT id_ficha, detalle_inconsistencias, modulo
                               FROM auditoria_errores_2026
                               WHERE LOWER(TRIM(CAST(usuario_creador AS text))) = LOWER(:usuario)
                                 AND modulo IN ('PCF_PRINCIPAL', 'PCF_INTEGRANTES')
                                 AND CAST(fecha_creacion AS text) >= :fecha_ini
                                 AND CAST(fecha_creacion AS text) <= :fecha_fin_limite
                               """, params)
        for idx, r in enumerate(res_err_pcf, 1):
            texto_err_pcf += f"{idx}. [{r['modulo']}] Ficha [{r['id_ficha']}]: {r['detalle_inconsistencias']}\n"
    except:
        pass

    query_pcf_int = """
                    SELECT COUNT(*) \
                    FROM pcf_planes_integrantes_2026 b \
                             JOIN pcf_planes_principal_2026 p ON b.ec5_branch_owner_uuid = p.ec5_uuid
                    WHERE LOWER(TRIM(CAST(p.created_by AS text))) = LOWER(:usuario)
                      AND CAST(p.created_at AS text) >= :fecha_ini
                      AND CAST(p.created_at AS text) <= :fecha_fin_limite \
                    """

    data["pcf"] = {
        "familias_intervenidas": pcf_fam_count,
        "integrantes_intervenidos": safe_count(query_pcf_int, params),
        "reporte_familias": texto_pcf_fam if texto_pcf_fam else "No hay intervenciones registradas en estas fechas.",
        "reporte_errores": texto_err_pcf if texto_err_pcf else "✅ Excelente. No hay errores de registro."
    }

    fam_psico_count = safe_count(
        q("pcf_planes_principal_2026", "TRIM(\"4_3_perfil_profesion\") = 'Profesional Psicología'"), params)

    try:
        res_psico_seg = ejecutar("""
                                 SELECT *
                                 FROM pcf_psicologia_seguimientos_2026
                                 WHERE LOWER(TRIM(CAST(created_by AS text))) = LOWER(:usuario)
                                   AND CAST(created_at AS text) >= :fecha_ini
                                   AND CAST(created_at AS text) <= :fecha_fin_limite
                                 """, params)
    except:
        res_psico_seg = []

    seg_psico_count = len(res_psico_seg)
    motivos_count, cont_seg_si, cont_seg_no = {}, 0, 0
    texto_psico_fam, texto_psico_seg, texto_err_psico, texto_psico_compromisos, texto_psico_evaluacion = "", "", "", "", ""

    es_psicologo = (fam_psico_count > 0 or seg_psico_count > 0)

    if es_psicologo:
        try:
            res_psico_fam = ejecutar("""
                                     SELECT ec5_uuid, created_at
                                     FROM pcf_planes_principal_2026
                                     WHERE LOWER(TRIM(CAST(created_by AS text))) = LOWER(:usuario)
                                       AND CAST(created_at AS text) >= :fecha_ini
                                       AND CAST(created_at AS text) <= :fecha_fin_limite
                                       AND TRIM("4_3_perfil_profesion") = 'Profesional Psicología'
                                     """, params)
            for idx, r in enumerate(res_psico_fam, 1):
                texto_psico_fam += f"Intervención {idx}: Ficha [{r.get('ec5_uuid', 'N/A')}] - {str(r.get('created_at', ''))[:10]}\n"
        except:
            pass

        for idx, r in enumerate(res_psico_seg, 1):
            uid_ficha = r.get('ec5_branch_uuid') or r.get('ec5_uuid') or 'N/A'
            texto_psico_seg += f"Seguimiento {idx}: Ficha [{uid_ficha}] - {str(r.get('created_at', ''))[:10]}\n"

            motivo = next((v for k, v in r.items() if k.startswith('128_23_')), None)
            req_cont = next((v for k, v in r.items() if k.startswith('130_25_')), None)
            comp = next((v for k, v in r.items() if k.startswith('131_26_')), None)
            evalu = next((v for k, v in r.items() if k.startswith('132_27_')), None)

            if motivo and str(motivo).strip() and str(motivo).strip() != 'None':
                m_str = str(motivo).strip()
                motivos_count[m_str] = motivos_count.get(m_str, 0) + 1

            if req_cont:
                v_req = str(req_cont).upper()
                if 'SI' in v_req or 'SÍ' in v_req:
                    cont_seg_si += 1
                elif 'NO' in v_req:
                    cont_seg_no += 1

            if comp and str(comp).strip() and str(comp).strip() != 'None':
                texto_psico_compromisos += f"Ficha [{uid_ficha}]: {str(comp).replace(chr(10), ' ')}\n\n"
            if evalu and str(evalu).strip() and str(evalu).strip() != 'None':
                texto_psico_evaluacion += f"Ficha [{uid_ficha}]: {str(evalu).replace(chr(10), ' ')}\n\n"

        try:
            res_err_psico = ejecutar("""
                                     SELECT id_ficha, detalle_inconsistencias, modulo
                                     FROM auditoria_errores_2026
                                     WHERE LOWER(TRIM(CAST(usuario_creador AS text))) = LOWER(:usuario)
                                       AND modulo IN ('PSICOLOGIA_PRINCIPAL', 'PSICOLOGIA_SEGUIMIENTOS')
                                       AND CAST(fecha_creacion AS text) >= :fecha_ini
                                       AND CAST(fecha_creacion AS text) <= :fecha_fin_limite
                                     """, params)
            for idx, r in enumerate(res_err_psico, 1):
                texto_err_psico += f"{idx}. [{r['modulo']}] Ficha [{r['id_ficha']}]: {r['detalle_inconsistencias']}\n"
        except:
            pass

    data["pcf_psicologia"] = {
        "intervenciones_familiares": fam_psico_count,
        "integrantes": safe_count(q("pcf_psicologia_principal_2026"), params),
        "seguimientos": seg_psico_count,
        "motivos_seguimiento": [{"label": k, "total": v} for k, v in
                                sorted(motivos_count.items(), key=lambda item: item[1], reverse=True)],
        "requiere_continuidad_si": cont_seg_si, "requiere_continuidad_no": cont_seg_no,
        "reporte_familias": texto_psico_fam if texto_psico_fam else "No hay intervenciones.",
        "reporte_seguimientos": texto_psico_seg if texto_psico_seg else "No hay seguimientos.",
        "reporte_compromisos": texto_psico_compromisos if texto_psico_compromisos else "No hay compromisos.",
        "reporte_evaluacion": texto_psico_evaluacion if texto_psico_evaluacion else "No hay evaluaciones.",
        "reporte_errores": texto_err_psico if texto_err_psico else "✅ Excelente. No hay errores."
    }

    res_tram_aud = ejecutar("""
                            SELECT SUM(CAST(realizados AS numeric)) as tot,
                                   SUM(CAST(efectivos AS numeric))  as res,
                                   SUM(CAST(errores AS numeric))    as err
                            FROM tramites_consolidados_2026
                            WHERE LOWER(TRIM(CAST(usuario AS text))) = LOWER(:usuario)
                              AND CAST(fecha AS text) >= :fecha_ini
                              AND CAST(fecha AS text) <= :fecha_fin_limite
                            """, params)

    a_tr_tot = res_tram_aud[0]["tot"] or 0 if res_tram_aud else 0
    a_tr_res = res_tram_aud[0]["res"] or 0 if res_tram_aud else 0
    a_tr_err = res_tram_aud[0]["err"] or 0 if res_tram_aud else 0

    res_tramites_textos = ejecutar("""
                                   SELECT nombres_realizados, nombres_efectivos
                                   FROM tramites_consolidados_2026
                                   WHERE LOWER(TRIM(CAST(usuario AS text))) = LOWER(:usuario)
                                     AND CAST(fecha AS text) >= :fecha_ini
                                     AND CAST(fecha AS text) <= :fecha_fin_limite
                                   """, params)

    conteo_tramites_aud, texto_realizados, texto_resueltos, c_re, c_ef = {}, "", "", 1, 1
    for row in res_tramites_textos:
        nr, ne = str(row["nombres_realizados"]), str(row["nombres_efectivos"])
        if nr and "Ningún" not in nr and nr != 'None':
            texto_realizados += f"Registro {c_re}: {nr.replace('|', ', ')}\n"
            c_re += 1
            for item in (x.strip() for x in nr.split("|") if x.strip()):
                conteo_tramites_aud[item] = conteo_tramites_aud.get(item, 0) + 1
        if ne and "Ningún" not in ne and ne != 'None':
            texto_resueltos += f"Registro {c_ef}: {ne.replace('|', ', ')}\n"
            c_ef += 1

    res_err_tr = ejecutar("""
                          SELECT id_ficha, detalle_inconsistencias
                          FROM auditoria_errores_2026
                          WHERE LOWER(TRIM(CAST(usuario_creador AS text))) = LOWER(:usuario)
                            AND modulo = 'TRAMITES'
                            AND CAST(fecha_creacion AS text) >= :fecha_ini
                            AND CAST(fecha_creacion AS text) <= :fecha_fin_limite
                          """, params)

    texto_errores_tr = "".join(
        [f"{idx + 1}. Ficha [{r['id_ficha']}]: {r['detalle_inconsistencias']}\n" for idx, r in enumerate(res_err_tr)])

    tr_familias_query_aud = """
                            SELECT COUNT(DISTINCT \
                                         COALESCE("7_4_territorio", '') || COALESCE("8_5_microterritorio", '') || \
                                         CASE \
                                             WHEN "3_2_cdigo_hogar" = 'No Aplica' OR "3_2_cdigo_hogar" IS NULL \
                                                 THEN COALESCE("4_21_cdigo_hogar", '') \
                                             ELSE "3_2_cdigo_hogar" END || \
                                         CASE \
                                             WHEN "5_3_cdigo_familia" = 'No Aplica' OR "5_3_cdigo_familia" IS NULL \
                                                 THEN COALESCE("6_31_cdigo_familia", '') \
                                             ELSE "5_3_cdigo_familia" END
                                   ) as total \
                            FROM tramites_aps_2026
                            WHERE LOWER(TRIM(CAST(created_by AS text))) = LOWER(:usuario)
                              AND CAST(created_at AS text) >= :fecha_ini \
                              AND CAST(created_at AS text) <= :fecha_fin_limite \
                            """
    tr_fam_res_aud = ejecutar(tr_familias_query_aud, params)

    res_obs_tramites = ejecutar("""
                                SELECT title, "150_describe_aqu_el_" as obs
                                FROM tramites_aps_2026
                                WHERE LOWER(TRIM(CAST(created_by AS text))) = LOWER(:usuario)
                                  AND CAST(created_at AS text) >= :fecha_ini
                                  AND CAST(created_at AS text) <= :fecha_fin_limite
                                """, params)

    texto_obs_tramites = ""
    for idx, r in enumerate(res_obs_tramites, 1):
        titulo = str(r.get("title", "Sin Título"))
        obs = str(r.get("obs", "")).replace('\n', ' ')
        if not obs or obs == 'None': obs = "Sin observaciones registradas."
        texto_obs_tramites += f"{idx}. Ficha {titulo}: {obs}\n\n"

    data["tramites"] = {
        "total": a_tr_tot, "resolutivos": a_tr_res, "con_error": a_tr_err,
        "por_tipo": [{"label": k, "total": v} for k, v in
                     sorted(conteo_tramites_aud.items(), key=lambda x: x[1], reverse=True)],
        "total_registros": safe_count(q("tramites_aps_2026"), params),
        "total_familias": tr_fam_res_aud[0]["total"] if tr_fam_res_aud else 0,
        "reporte_realizados": texto_realizados if texto_realizados else "No hay trámites realizados en estas fechas.",
        "reporte_resueltos": texto_resueltos if texto_resueltos else "No hay trámites resueltos en estas fechas.",
        "reporte_errores": texto_errores_tr if texto_errores_tr else "✅ Excelente. No hay trámites con errores.",
        "reporte_observaciones": texto_obs_tramites.strip() if texto_obs_tramites else "No hay observaciones de trámites en estas fechas."
    }

    query_errores = text("""
                         SELECT modulo, id_ficha, titulo_ficha, cantidad_errores, detalle_inconsistencias
                         FROM auditoria_errores_2026
                         WHERE LOWER(TRIM(CAST(usuario_creador AS text))) = LOWER(:usuario)
                           AND CAST(fecha_creacion AS text) >= :fecha_ini
                           AND CAST(fecha_creacion AS text) <= :fecha_fin_limite
                         ORDER BY modulo, cantidad_errores DESC
                         """)
    lista_errores_texto = []
    try:
        with engine.connect() as conn:
            for row in conn.execute(query_errores, params).mappings():
                lista_errores_texto.append(
                    f"🛑 MÓDULO: {row['modulo']}\nFicha ID: {row['id_ficha']} | Título: {row['titulo_ficha']}\nErrores ({row['cantidad_errores']}): {row['detalle_inconsistencias']}\n--------------------------------------------------")
    except:
        pass

    lista_errores_texto.extend(errores_dinamicos)
    data["reporte_errores_texto"] = "\n".join(
        lista_errores_texto) if lista_errores_texto else "✅ ¡Felicitaciones! No se encontraron errores de auditoría para este encuestador en estas fechas."
    return data


@app.route("/api/auditoria", methods=["GET"])
@require_auth
def auditoria_endpoint():
    usuario = request.args.get("usuario", "").strip()
    fecha_ini = request.args.get("fecha_inicio", "").strip()
    fecha_fin = request.args.get("fecha_fin", "").strip()
    if not usuario: return jsonify({"error": "El parámetro 'usuario' es requerido."}), 400

    usuario_req = g.user.get('nombre', 'Desconocido')
    logger.info(
        f"🔎 [AUDITORIA] El usuario '{usuario_req}' auditó al encuestador: '{usuario}'. Rango: {fecha_ini} a {fecha_fin}")

    data = get_auditoria_data(usuario, fecha_ini, fecha_fin)
    return jsonify(data)


@app.route("/api/mapas", methods=["GET"])
@require_auth
def get_mapas():
    usuario_req = g.user.get('nombre', 'Desconocido')
    usuario = request.args.get("usuario", "").strip()
    fecha_ini = request.args.get("fecha_inicio", "").strip()
    fecha_fin = request.args.get("fecha_fin", "").strip()

    if not usuario: return jsonify({"error": "El parámetro 'usuario' es requerido."}), 400

    logger.info(
        f"📍 [MAPAS GIS] El usuario '{usuario_req}' solicitó las coordenadas de: '{usuario}'. Rango: {fecha_ini} a {fecha_fin}")

    fecha_fin_limite = (fecha_fin or "2099-12-31") + "T23:59:59"
    params = {"usuario": usuario, "fecha_ini": fecha_ini or "2000-01-01", "fecha_fin_limite": fecha_fin_limite}

    LAT_MIN, LAT_MAX = 3.80, 4.40
    LNG_MIN, LNG_MAX = -74.00, -73.30

    mapas_config = [
        {"key": "desistimientos", "table": "desistimiento_aps_2026", "lat": "lat_2_2_geolocalizacin",
         "lng": "long_2_2_geolocalizacin"},
        {"key": "pcc", "table": "pcc_principal_2026", "lat": "lat_1_1_geolocalizacin",
         "lng": "long_1_1_geolocalizacin"},
        {"key": "caracterizacion", "table": "caracterizacion_si_aps_familiar_2026", "lat": "lat_15_8_geo_punto_georr",
         "lng": "long_15_8_geo_punto_georr"},
        {"key": "pcf", "table": "pcf_planes_principal_2026", "lat": "lat_1_1_geolocalizacin",
         "lng": "long_1_1_geolocalizacin"},
        {"key": "tramites", "table": "tramites_aps_2026", "lat": "lat_2_1_georreferenciaci",
         "lng": "long_2_1_georreferenciaci"}
    ]

    respuesta = {}

    for cfg in mapas_config:
        try:
            query = f"""
                SELECT * FROM {cfg['table']}
                WHERE LOWER(TRIM(CAST(created_by AS text))) = LOWER(:usuario)
                AND CAST(created_at AS text) >= :fecha_ini 
                AND CAST(created_at AS text) <= :fecha_fin_limite
            """
            rows = ejecutar(query, params)
            correctos, errores_vacios, errores_fuera = [], [], []

            for r in rows:
                uid = r.get('ec5_branch_uuid') or r.get('ec5_uuid') or 'N/A'
                fecha = str(r.get('created_at', ''))[:10]
                lat_str, lng_str = r.get(cfg['lat']), r.get(cfg['lng'])

                try:
                    lat, lng = float(lat_str), float(lng_str)
                    if lat == 0 and lng == 0: raise ValueError("Cero absoluto")
                except:
                    errores_vacios.append(f"Ficha [{uid}] - {fecha}")
                    continue

                if LAT_MIN <= lat <= LAT_MAX and LNG_MIN <= LNG_MAX:
                    correctos.append({"lat": lat, "lng": lng, "uid": uid, "fecha": fecha})
                else:
                    errores_fuera.append(f"Ficha [{uid}] - {fecha} (Lat: {lat}, Lng: {lng})")

            respuesta[cfg['key']] = {"correctos": correctos, "errores_vacios": errores_vacios,
                                     "errores_fuera": errores_fuera,
                                     "totales": {"ok": len(correctos), "vacios": len(errores_vacios),
                                                 "fuera": len(errores_fuera)}}
        except:
            respuesta[cfg['key']] = {"correctos": [], "errores_vacios": [], "errores_fuera": [],
                                     "totales": {"ok": 0, "vacios": 0, "fuera": 0}}

    total_coord = sum(r['totales']['ok'] for r in respuesta.values())
    if total_coord > 0:
        logger.info(
            f"✅ [MAPAS GIS] Georreferenciación de '{usuario}' exitosa. {total_coord} puntos válidos renderizados.")
    else:
        logger.warning(f"⚠️ [MAPAS GIS] Georreferenciación de '{usuario}' sin puntos válidos en el mapa.")

    query_perfil = """
                   SELECT "5_4_nombre_del_profe" as nombre, "4_3_perfil_profesion" as perfil, COUNT(*) as qty
                   FROM pcf_planes_principal_2026
                   WHERE LOWER(TRIM(CAST(created_by AS text))) = LOWER(:usuario)
                     AND CAST(created_at AS text) >= :fecha_ini \
                     AND CAST(created_at AS text) <= :fecha_fin_limite
                     AND "5_4_nombre_del_profe" IS NOT NULL
                   GROUP BY 1, 2
                   ORDER BY qty DESC LIMIT 1 \
                   """
    res_perfil = ejecutar(query_perfil, params)
    if res_perfil:
        respuesta["encuestador_nombre"] = res_perfil[0]["nombre"]
        respuesta["encuestador_perfil"] = res_perfil[0]["perfil"]
    else:
        respuesta["encuestador_nombre"] = "Sin registro de nombre"
        respuesta["encuestador_perfil"] = "Sin registro de perfil"

    return jsonify(respuesta)


# ── EXPORTACIÓN A EXCEL ──
@app.route("/api/exportar_excel", methods=["GET"])
@require_auth
def exportar_excel():
    pass  # Eliminado por solicitud de aligerar servidor


# ═══════════════════════════════════════════════════════════════
#   NUEVO MÓDULO SIHOS (CLÍNICA VS CAMPO)
# ═══════════════════════════════════════════════════════════════

@app.route("/api/profesionales_sihos", methods=["GET"])
@require_auth
def get_profesionales_sihos():
    rows = ejecutar(
        "SELECT DISTINCT profesional FROM sihos WHERE sede = 'APS' AND profesional IS NOT NULL ORDER BY profesional ASC")
    return jsonify([r["profesional"] for r in rows if r["profesional"]])


@app.route("/api/sihos", methods=["GET"])
@require_auth
def get_sihos_analytics():
    usuario_req = g.user.get('nombre', 'Desconocido')
    profesional = request.args.get("profesional", "").strip()
    fecha_ini = request.args.get("fecha_inicio", "").strip()
    fecha_fin = request.args.get("fecha_fin", "").strip()

    logger.info(f"🏥 [SIHOS] Auditando a: '{profesional or 'TODA LA SEDE APS'}'.")

    f_ini = fecha_ini or "2000-01-01"
    f_fin = fecha_fin or "2099-12-31"
    f_fin_limite = f"{fecha_fin}T23:59:59" if fecha_fin else "2099-12-31T23:59:59"

    params = {"f_ini": f_ini, "f_fin": f_fin, "f_fin_limite": f_fin_limite}

    prof_filter_sihos = ""
    prof_filter_aps = ""

    if profesional:
        prof_limpio = profesional.replace('ï¿½', '_').replace('Ñ', '_').replace('ñ', '_')
        prof_parts = [p for p in prof_limpio.split() if p]
        prof_like = '%' + '%'.join(prof_parts) + '%'
        prof_filter_sihos = "AND LOWER(TRIM(profesional)) LIKE LOWER(:prof_like)"
        prof_filter_aps = "AND LOWER(TRIM(\"5_4_nombre_del_profe\")) LIKE LOWER(:prof_like)"
        params["prof_like"] = prof_like

    # 1. Traer data de SIHOS aplicando el LIKE
    query_sihos = f"""
        WITH fechas_limpias AS (
            SELECT administradora, tipo_contrato, genero, actividad_suministro, 
                   finalidad, diagnostico, servicio_origen, tipo_servicio, especialidad,
            CASE 
                WHEN CAST(fecha AS text) ~ '^[0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}}' THEN to_date(LEFT(CAST(fecha AS text), 10), 'YYYY-MM-DD')
                WHEN CAST(fecha AS text) ~ '^[0-9]{{2}}/[0-9]{{2}}/[0-9]{{4}}' THEN to_date(LEFT(CAST(fecha AS text), 10), 'DD/MM/YYYY')
                ELSE NULL
            END as fecha_ok,
            CASE 
                WHEN CAST(fecha_nacimiento AS text) ~ '^[0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}}' THEN to_date(LEFT(CAST(fecha_nacimiento AS text), 10), 'YYYY-MM-DD')
                WHEN CAST(fecha_nacimiento AS text) ~ '^[0-9]{{2}}/[0-9]{{2}}/[0-9]{{4}}' THEN to_date(LEFT(CAST(fecha_nacimiento AS text), 10), 'DD/MM/YYYY')
                ELSE NULL
            END as f_nac_ok
            FROM sihos
            WHERE sede = 'APS' {prof_filter_sihos}
        )
        SELECT administradora, tipo_contrato, genero, actividad_suministro, 
               finalidad, diagnostico, servicio_origen, tipo_servicio, especialidad,
               CASE 
                   WHEN f_nac_ok IS NULL OR fecha_ok IS NULL THEN -1
                   ELSE EXTRACT(YEAR FROM age(fecha_ok, f_nac_ok)) 
               END as edad
        FROM fechas_limpias
        WHERE fecha_ok >= to_date(:f_ini, 'YYYY-MM-DD')
          AND fecha_ok <= to_date(SUBSTRING(:f_fin_limite, 1, 10), 'YYYY-MM-DD')
    """
    filas_sihos = ejecutar(query_sihos, params)
    total_atenciones = len(filas_sihos)

    especialidad_str = filas_sihos[0].get("especialidad", "Desconocida") if total_atenciones > 0 else "Desconocida"

    eps_count, contrato_count, genero_count, finalidad_count, servicio_count, c_vida_count = Counter(), Counter(), Counter(), Counter(), Counter(), Counter()
    diag_data = {}
    ind_salud_mental, ind_pyp_medicina, ind_pyp_enfermeria, ind_rias = 0, 0, 0, 0

    for f in filas_sihos:
        eps_count[str(f.get("administradora", "Sin Datos"))] += 1
        contrato_count[str(f.get("tipo_contrato", "Sin Datos"))] += 1
        genero_count[str(f.get("genero", "Sin Datos"))] += 1
        finalidad_count[str(f.get("finalidad", "Sin Datos"))] += 1
        servicio_count[str(f.get("tipo_servicio", "Sin Datos"))] += 1

        edad = f.get("edad", -1)
        c_vida_str = "Sin Datos"
        if edad < 0:
            c_vida_str = "Sin Datos"
        elif edad <= 5:
            c_vida_str = "1. Primera Infancia (0-5)"
        elif edad <= 11:
            c_vida_str = "2. Infancia (6-11)"
        elif edad <= 17:
            c_vida_str = "3. Adolescencia (12-17)"
        elif edad <= 28:
            c_vida_str = "4. Juventud (18-28)"
        elif edad <= 59:
            c_vida_str = "5. Adultez (29-59)"
        else:
            c_vida_str = "6. Vejez (60+)"

        c_vida_count[c_vida_str] += 1

        diag = str(f.get("diagnostico", "")).strip()
        if diag and diag != "None":
            if diag not in diag_data:
                diag_data[diag] = {"total": 0, "edades": Counter()}
            diag_data[diag]["total"] += 1
            diag_data[diag]["edades"][c_vida_str] += 1

        ts, ori, act = str(f.get("tipo_servicio", "")).lower(), str(f.get("servicio_origen", "")).lower(), str(
            f.get("actividad_suministro", "")).lower()
        if "psicolog" in ts or "psicolog" in act or "mental" in act: ind_salud_mental += 1
        if "pyp" in ts or "promocion" in ori:
            ind_rias += 1
            if "medicina" in ts or "medicina" in act: ind_pyp_medicina += 1
            if "enfermeria" in ts or "enfermeria" in act: ind_pyp_enfermeria += 1

    top_diags = sorted(diag_data.items(), key=lambda x: x[1]["total"], reverse=True)[:10]
    diagnosticos_list = []
    for d_name, d_info in top_diags:
        predominante = d_info["edades"].most_common(1)[0][0] if d_info["edades"] else "Sin Datos"
        diagnosticos_list.append({"label": d_name, "total": d_info["total"], "grupo_etario": predominante})

    query_cruce = f"""
        SELECT COUNT(*) as campo_total
        FROM pcf_planes_principal_2026
        WHERE {get_date_filter('created_at')}
          {prof_filter_aps}
    """
    res_cruce = ejecutar(query_cruce, params)
    atenciones_campo_aps = res_cruce[0]["campo_total"] if res_cruce else 0

    def format_counter(counter_obj):
        return [{"label": k, "total": v} for k, v in sorted(counter_obj.items(), key=lambda x: x[1], reverse=True)]

    data = {
        "profesional": profesional or "Global Sede APS",
        "especialidad": especialidad_str,
        "rango_fechas": f"{fecha_ini} / {fecha_fin}",
        "resumen": {"total_facturaciones": total_atenciones},
        "demografia": {"genero": format_counter(genero_count), "curso_vida": format_counter(c_vida_count)},
        "administrativo": {"eps": format_counter(eps_count), "contrato": format_counter(contrato_count)},
        "clinico": {"finalidad": format_counter(finalidad_count), "tipo_servicio": format_counter(servicio_count),
                    "diagnosticos": diagnosticos_list},
        "indicadores": {"salud_mental": ind_salud_mental, "pyp_medicina": ind_pyp_medicina,
                        "pyp_enfermeria": ind_pyp_enfermeria, "total_rias": ind_rias,
                        "campo_epi_collect": atenciones_campo_aps}
    }

    return jsonify(data)


@app.route("/api/health", methods=["GET"])
def health(): return jsonify({"status": "ok"}), 200


if __name__ == "__main__":
    port = int(os.getenv("PORT_INFORMES", 5001))
    app.run(host="0.0.0.0", port=port, debug=False)
