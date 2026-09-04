# -*- coding: utf-8 -*-
import re
import logging
from collections import Counter
from database.db_core import BaseService
from sqlalchemy import text

logger = logging.getLogger("AuditoriaEspecialistasService")


class AuditoriaEspecialistasService(BaseService):

    def obtener_datos(self, correo: str, nombre: str, fecha_ini: str, fecha_fin: str,
                      tipo_fecha: str = 'created_at') -> dict:
        f_ini = fecha_ini or "2000-01-01"
        f_fin = fecha_fin or "2099-12-31"

        email_res = correo if correo else self.resolver_correo(nombre)

        # 🟢 1. RESOLUCIÓN DE IDENTIDAD ESTRICTA (Sin comodines fraccionados)
        if correo and not nombre:
            for tbl, col in [('pcf_planes_principal_2026', '5_4_nombre_del_profe'),
                             ('caracterizacion_si_aps_familiar_2026', '32_20_responsable_de'),
                             ('pcc_principal_2026', '4_4_nombre_del_profe')]:
                res_n = self.ejecutar(
                    f'SELECT "{col}" as n FROM {tbl} WHERE LOWER(TRIM(CAST(created_by AS text))) = LOWER(:c) AND "{col}" IS NOT NULL LIMIT 1',
                    {'c': correo})
                if res_n and res_n[0]['n']:
                    nombre = res_n[0]['n']
                    break
        elif nombre and not correo:
            correo = self.resolver_correo(nombre)

        c_clean = (correo or "").strip().lower()
        n_clean = (nombre or "").strip().lower()
        e_res_clean = (email_res or "").strip().lower()

        # Colección de Alias Exactos (Evita falsos positivos)
        alias_set = set()
        for item in [c_clean, n_clean, e_res_clean]:
            if item:
                alias_set.add(item)
                if '@' in item:
                    alias_set.add(item.split('@')[0])  # Captura el prefijo del correo (ej: astridjo15)

        try:
            q_alias = """
                      SELECT DISTINCT created_by \
                      FROM pcf_planes_principal_2026 \
                      WHERE LOWER(TRIM(CAST("5_4_nombre_del_profe" AS text))) = LOWER(:n) \
                         OR LOWER(TRIM(CAST(created_by AS text))) = LOWER(:c)
                      UNION
                      SELECT DISTINCT "5_4_nombre_del_profe" \
                      FROM pcf_planes_principal_2026 \
                      WHERE LOWER(TRIM(CAST(created_by AS text))) = LOWER(:c)
                      UNION
                      SELECT DISTINCT created_by \
                      FROM caracterizacion_si_aps_familiar_2026 \
                      WHERE LOWER(TRIM(CAST("32_20_responsable_de" AS text))) = LOWER(:n) \
                         OR LOWER(TRIM(CAST(created_by AS text))) = LOWER(:c) \
                      """
            r_alias = self.ejecutar(q_alias, {"n": n_clean, "c": c_clean or e_res_clean})
            for ra in r_alias:
                val = str(list(ra.values())[0] or "").strip().lower()
                if val:
                    alias_set.add(val)
                    if '@' in val:
                        alias_set.add(val.split('@')[0])
        except Exception as e:
            logger.error(f"Error recopilando alias del especialista: {e}")

        # Evita consultas vacías
        if not alias_set:
            alias_set.add("___NOMATCH___")

        # Conversión del Set a cadena SQL para cláusulas IN (...)
        aliases_sql = ", ".join([f"'{a.replace(chr(39), '')}'" for a in alias_set])

        params = {
            "correo": c_clean, "nombre": n_clean, "email_res": e_res_clean,
            "f_ini": f_ini, "f_fin": f_fin
        }

        # 🟢 MACRO-FILTROS ESTRICTOS (Cruce exacto con usuario_creador, created_by o especialista_email)
        err_where_auditoria = f"LOWER(TRIM(CAST(usuario_creador AS text))) IN ({aliases_sql})"
        w_esp_email = f"LOWER(TRIM(CAST(especialista_email AS text))) IN ({aliases_sql})"

        if correo:
            w_desist = "LOWER(TRIM(CAST(created_by AS text))) = LOWER(:correo)"
            w_pcc_prin = "LOWER(TRIM(CAST(created_by AS text))) = LOWER(:correo)"
            w_pcc_int = "LOWER(TRIM(CAST(p.created_by AS text))) = LOWER(:correo)"
            w_pcf_prin = "LOWER(TRIM(CAST(created_by AS text))) = LOWER(:correo)"
            w_pcf_int = "LOWER(TRIM(CAST(p.created_by AS text))) = LOWER(:correo)"
        else:
            w_desist = "LOWER(TRIM(CAST(\"13_10_nombre_profesi\" AS text))) = LOWER(:nombre)"
            w_pcc_prin = "LOWER(TRIM(CAST(\"4_4_nombre_del_profe\" AS text))) = LOWER(:nombre)"
            w_pcc_int = "LOWER(TRIM(CAST(p.\"4_4_nombre_del_profe\" AS text))) = LOWER(:nombre)"
            w_pcf_prin = "LOWER(TRIM(CAST(\"5_4_nombre_del_profe\" AS text))) = LOWER(:nombre)"
            w_pcf_int = "LOWER(TRIM(CAST(p.\"5_4_nombre_del_profe\" AS text))) = LOWER(:nombre)"

        data = {"usuario": correo or nombre, "rango_fechas": f"{f_ini} / {f_fin}"}

        # =========================================================================
        # 🟢 2. MÓDULO NOVEDADES Y CONCILIACIÓN DE ESPECIALISTAS
        # =========================================================================
        detalle_novedades = []
        tot_evaluados, tot_correctos, tot_sin_pcf, tot_sin_pci, tot_sin_caract = 0, 0, 0, 0, 0

        try:
            query_esp = f"""
                SELECT 'Fisioterapia' as tabla_origen, fecha_visita, nombre_jefe_hogar as paciente, CAST(doc_identidad AS text) as documento, territorio, microterritorio, codigo_familia, especialista_email
                FROM formulario_fisioterapia WHERE {w_esp_email} AND fecha_visita BETWEEN :f_ini AND :f_fin
                UNION ALL
                SELECT 'Nutrición' as tabla_origen, fecha_visita, nombre_jefe_hogar as paciente, CAST(doc_identidad AS text) as documento, territorio, microterritorio, codigo_familia, especialista_email
                FROM formulario_nutricionista WHERE {w_esp_email} AND fecha_visita BETWEEN :f_ini AND :f_fin
                UNION ALL
                SELECT 'Respiratoria' as tabla_origen, fecha_visita, nombre_jefe_hogar as paciente, CAST(doc_identidad AS text) as documento, territorio, microterritorio, codigo_familia, especialista_email
                FROM formulario_respiratoria WHERE {w_esp_email} AND fecha_visita BETWEEN :f_ini AND :f_fin
            """
            registros_esp = self.ejecutar(query_esp, params)

            if registros_esp:
                # Extraemos las llaves de familia del PCF
                q_pcf_fam = f"""
                    SELECT created_by, "9_7_territorio", "10_8_microterritorio", "13_10_identificacin_", "14_101_identificacin" 
                    FROM pcf_planes_principal_2026 
                    WHERE {w_pcf_prin}
                """
                res_pcf_fam = self.ejecutar(q_pcf_fam, params)
                set_pcf_fam = set()
                for rf in res_pcf_fam:
                    c = str(rf.get("created_by", "")).strip().lower()
                    t = str(rf.get("9_7_territorio", "")).strip().lower()
                    m = str(rf.get("10_8_microterritorio", "")).strip().lower()
                    i1 = str(rf.get("13_10_identificacin_", "")).strip()
                    i2 = str(rf.get("14_101_identificacin", "")).strip()
                    cod = i1 if i1 and "aplica" not in i1.lower() else i2
                    set_pcf_fam.add(f"{t}|{m}|{cod.lower()}|{c}")

                docs_list = list(
                    set([str(r.get('documento', '')).strip() for r in registros_esp if r.get('documento')]))
                dict_pci_counts = {}
                set_caract = set()

                if docs_list:
                    docs_array = "ARRAY[" + ",".join([f"'{d.replace(chr(39), '')}'" for d in docs_list]) + "]::text[]"

                    # Conteo de planes individuales
                    q_pci = f"""SELECT CAST("36_6_numero_de_docum" AS text) as doc, COUNT(*) as c FROM pcf_planes_integrantes_2026 WHERE CAST("36_6_numero_de_docum" AS text) = ANY({docs_array}) GROUP BY 1"""
                    res_pci = self.ejecutar(q_pci, {})
                    dict_pci_counts = {str(r['doc']).strip().lower(): int(r['c']) for r in res_pci}

                    # Caracterización cruzada
                    q_car = f"""SELECT CAST("105_6_numero_de_iden" AS text) as doc FROM caracterizacion_si_aps_individual_2026 WHERE CAST("105_6_numero_de_iden" AS text) = ANY({docs_array})"""
                    res_car = self.ejecutar(q_car, {})
                    set_caract = set([str(r['doc']).strip().lower() for r in res_car])

                for r in registros_esp:
                    tot_evaluados += 1
                    doc = str(r.get('documento', '')).strip().lower()
                    paciente = str(r.get('paciente', 'Paciente Anónimo')).title()
                    fecha = str(r.get('fecha_visita', 'N/A'))[:10]
                    origen = r.get('tabla_origen', 'Desconocido')

                    t = str(r.get("territorio", "")).strip().lower()
                    m = str(r.get("microterritorio", "")).strip().lower()
                    cod = str(r.get("codigo_familia", "")).strip().lower()
                    email = str(r.get("especialista_email", "")).strip().lower()
                    key_fam = f"{t}|{m}|{cod}|{email}"

                    if not doc or doc == 'none':
                        detalle_novedades.append(
                            {"fecha": fecha, "paciente": paciente, "tabla_origen": origen, "tipo": "Documento Vacío",
                             "detalle": "El documento de identidad está vacío en el formulario del especialista."})
                        continue

                    is_correct = True

                    if key_fam not in set_pcf_fam:
                        tot_sin_pcf += 1
                        is_correct = False
                        detalle_novedades.append(
                            {"fecha": fecha, "paciente": f"{paciente} ({doc})", "tabla_origen": origen,
                             "tipo": "Sin PCF Familiar",
                             "detalle": "La familia no cuenta con Plan de Cuidado Familiar registrado por el especialista."})

                    pci_count = dict_pci_counts.get(doc, 0)
                    if pci_count == 0:
                        tot_sin_pci += 1
                        is_correct = False
                        detalle_novedades.append(
                            {"fecha": fecha, "paciente": f"{paciente} ({doc})", "tabla_origen": origen,
                             "tipo": "Sin PCF Individual",
                             "detalle": "La persona no fue intervenida por el especialista (No tiene Plan de Cuidado Individual)."})

                        if doc not in set_caract:
                            tot_sin_caract += 1
                            detalle_novedades.append(
                                {"fecha": fecha, "paciente": f"{paciente} ({doc})", "tabla_origen": origen,
                                 "tipo": "Sin Caracterización",
                                 "detalle": "El usuario no fue caracterizado por el perfil técnico en el sistema."})
                    elif pci_count == 1:
                        is_correct = False
                        detalle_novedades.append(
                            {"fecha": fecha, "paciente": f"{paciente} ({doc})", "tabla_origen": origen,
                             "tipo": "Validación PCI Leve",
                             "detalle": "Intervenida únicamente por el especialista y no por el perfil profesional o técnico. Se requiere validación."})

                    if is_correct:
                        tot_correctos += 1

            data["novedades"] = {"total_evaluados": tot_evaluados, "correctos": tot_correctos, "sin_pcf": tot_sin_pcf,
                                 "sin_pci": tot_sin_pci, "sin_caracterizacion": tot_sin_caract,
                                 "detalle": detalle_novedades}
        except Exception as e:
            logger.error(f"Error procesando novedades: {e}")
            data["novedades"] = {"total_evaluados": 0, "correctos": 0, "sin_pcf": 0, "sin_pci": 0,
                                 "sin_caracterizacion": 0, "detalle": []}

        # =========================================================================
        # 🟢 3. FORMULARIOS ESPECIALISTAS (EVALUADOR DE ERRORES Y DUPLICADOS)
        # =========================================================================
        tot_familias_esp, tot_duplicados_esp, tot_errores_esp = 0, 0, 0
        seen_keys_esp = set()
        tablas_esp = ['formulario_fisioterapia', 'formulario_nutricionista', 'formulario_respiratoria']
        tabla_fisio, tabla_nutri, tabla_resp = [], [], []

        for tabla in tablas_esp:
            try:
                q_form_esp = f"SELECT * FROM {tabla} WHERE {w_esp_email} AND ({self.get_date_filter('created_at')})"
                rows_esp = self.ejecutar(q_form_esp, params)

                for row in rows_esp:
                    tot_familias_esp += 1
                    row_clean = {k: (str(v).strip() if v is not None else "") for k, v in row.items()}

                    if tabla == 'formulario_fisioterapia':
                        tabla_fisio.append(row_clean)
                    elif tabla == 'formulario_nutricionista':
                        tabla_nutri.append(row_clean)
                    elif tabla == 'formulario_respiratoria':
                        tabla_resp.append(row_clean)

                    t_terr = str(row.get('territorio', '')).strip().lower()
                    t_micro = str(row.get('microterritorio', '')).strip().lower()
                    t_cod = str(row.get('codigo_familia', '')).strip().lower()
                    t_email = str(row.get('especialista_email', '')).strip().lower()

                    key_dup = f"{t_terr}|{t_micro}|{t_cod}|{t_email}"
                    if key_dup in seen_keys_esp:
                        tot_duplicados_esp += 1
                    else:
                        seen_keys_esp.add(key_dup)

                    row_has_error = False
                    for col, val in row.items():
                        if val is None:
                            row_has_error = True
                            break
                        s_val = str(val).strip()
                        if s_val == "" or s_val in ["[]", "{}"] or s_val.lower() == "sin asignar":
                            row_has_error = True
                            break
                        try:
                            num = float(s_val)
                            if num <= 0.0:
                                row_has_error = True
                                break
                        except ValueError:
                            pass
                    if row_has_error: tot_errores_esp += 1
            except Exception as e:
                logger.error(f"Error procesando formulario especialista {tabla}: {e}")

        data["formularios_especialistas"] = {"familias_intervenidas": tot_familias_esp,
                                             "duplicados": tot_duplicados_esp, "errores": tot_errores_esp,
                                             "tabla_fisioterapia": tabla_fisio, "tabla_nutricionista": tabla_nutri,
                                             "tabla_respiratoria": tabla_resp}

        # =========================================================================
        # 🟢 4. DESISTIMIENTOS Y PCC
        # =========================================================================
        data["desistimientos"] = {
            "total": self.safe_count(
                f"SELECT COUNT(*) FROM desistimiento_aps_2026 WHERE {w_desist} AND {self.get_date_filter(tipo_fecha)}",
                params),
            "con_error": self.safe_count(
                f"SELECT COUNT(*) FROM auditoria_errores_2026 WHERE {err_where_auditoria} AND modulo = 'DESISTIMIENTOS' AND ({self.get_date_filter('fecha_creacion')} OR fecha_creacion IS NULL)",
                params)
        }

        query_pcc_int = f"SELECT COUNT(*) FROM pcc_integrantes_2026 b JOIN pcc_principal_2026 p ON b.ec5_branch_owner_uuid = p.ec5_uuid WHERE {w_pcc_int} AND {self.get_date_filter(f'p.{tipo_fecha}')}"
        pcc_planes_count = self.safe_count(
            f"SELECT COUNT(*) FROM pcc_principal_2026 WHERE {w_pcc_prin} AND {self.get_date_filter(tipo_fecha)}",
            params)

        texto_pcc_detalles = ""
        if pcc_planes_count > 0:
            try:
                res_pcc = self.ejecutar(
                    f"SELECT ec5_uuid, {tipo_fecha} as fecha_base, \"20_14_detalles_jorna\" FROM pcc_principal_2026 WHERE {w_pcc_prin} AND {self.get_date_filter(tipo_fecha)}",
                    params)
                for idx, r in enumerate(res_pcc, 1):
                    texto_pcc_detalles += f"Plan {idx} [{r.get('ec5_uuid', 'N/A')}] - {str(r.get('fecha_base', ''))[:10]}: {str(r.get('20_14_detalles_jorna', '')).replace(chr(10), ' ') or 'Sin detalles.'}\n\n"
            except:
                pass

        data["pcc"] = {"planes": pcc_planes_count, "integrantes": self.safe_count(query_pcc_int, params),
                       "con_error": self.safe_count(
                           f"SELECT COUNT(*) FROM auditoria_errores_2026 WHERE {err_where_auditoria} AND modulo LIKE 'PCC%' AND ({self.get_date_filter('fecha_creacion')} OR fecha_creacion IS NULL)",
                           params), "reporte_detalles": texto_pcc_detalles.strip() or "No hay detalles."}

        # =========================================================================
        # 🟢 5. PLAN CUIDADO FAMILIAR (PCF EXCEL TABLAS)
        # =========================================================================
        query_pcf_prin = f"""
            SELECT ec5_uuid, CAST(created_at AS text) as created_at, CAST(uploaded_at AS text) as uploaded_at, 
                   created_by, lat_1_1_geolocalizacin, long_1_1_geolocalizacin, "4_3_perfil_profesion", 
                   "5_4_nombre_del_profe", "9_7_territorio", "10_8_microterritorio", "11_9_identificacin_d", 
                   "12_91_identificacin_", "13_10_identificacin_", "14_101_identificacin", 
                   "29_integrantes_inter", "73_17_realizara_la_e", "98_resumen_de_interv"
            FROM pcf_planes_principal_2026
            WHERE {w_pcf_prin} AND {self.get_date_filter(tipo_fecha)}
              AND "4_3_perfil_profesion" = 'Profesional Perfil Complementario'
        """
        raw_pcf_aud = self.ejecutar(query_pcf_prin, params)
        tabla_principal, seen_c_pcf_aud, dups_pcf_list = [], set(), []

        for r in raw_pcf_aud:
            row_clean = {k: (str(v).strip() if v is not None else "") for k, v in r.items()}
            tabla_principal.append(row_clean)
            c_key = f"{r.get('created_by', '')}|{r.get('9_7_territorio', '')}|{r.get('10_8_microterritorio', '')}|{r.get('11_9_identificacin_d', '')}|{r.get('12_91_identificacin_', '')}|{r.get('13_10_identificacin_', '')}|{r.get('14_101_identificacin', '')}".lower().strip()
            if c_key != "||||||" and c_key.replace("none", "").replace("|", "") != "" and c_key in seen_c_pcf_aud:
                dups_pcf_list.append(f"Ficha [{r.get('ec5_uuid')}] -> Motivo: Identificación/Territorio repetido")
            elif c_key != "||||||" and c_key.replace("none", "").replace("|", "") != "":
                seen_c_pcf_aud.add(c_key)

        query_pcf_int = f"""
            SELECT b.ec5_branch_owner_uuid, b.ec5_branch_uuid, CAST(b.created_at AS text) as created_at, 
                   CAST(b.uploaded_at AS text) as uploaded_at, b.created_by, b.title, "31_1_primer_nombre", 
                   "33_3_primer_apellido", "35_5_tipo_de_documen", "36_6_numero_de_docum", 
                   CAST("38_8_fecha_de_nacimi" AS text) as "38_8_fecha_de_nacimi", "41_11_sexo", 
                   "46_16_numero_de_celu", "57_23_que_tipo_de_co", "67_237_tema_central_", 
                   "69_239_metodologa_ed", "71_2311_ruta_sugerid", "72_24_resumen_de_val"
            FROM pcf_planes_integrantes_2026 b
            JOIN pcf_planes_principal_2026 p ON b.ec5_branch_owner_uuid = p.ec5_uuid
            WHERE {w_pcf_int} AND {self.get_date_filter(f'p.{tipo_fecha}')}
              AND p."4_3_perfil_profesion" = 'Profesional Perfil Complementario'
        """
        raw_pcf_ind_aud = self.ejecutar(query_pcf_int, params)
        tabla_integrantes, seen_ind_pcf_aud, dups_ind_pcf_aud_list = [], set(), []

        for r in raw_pcf_ind_aud:
            row_clean = {k: (str(v).strip() if v is not None else "") for k, v in r.items()}
            tabla_integrantes.append(row_clean)
            c, t = str(r.get("created_by", "")).strip().lower(), str(r.get("title", "")).strip().lower()
            if not t or t == "none": continue
            clave = f"{c}|{t}"
            if clave in seen_ind_pcf_aud:
                dups_ind_pcf_aud_list.append(f"Ficha [{r.get('ec5_branch_uuid')}] -> Motivo: Nombre repetido")
            else:
                seen_ind_pcf_aud.add(clave)

        try:
            res_err_pcf = self.ejecutar(f"""
                SELECT id_ficha, detalle_inconsistencias, modulo
                FROM auditoria_errores_2026
                WHERE {err_where_auditoria} AND modulo IN ('PCF_PRINCIPAL', 'PCF_INTEGRANTES')
                  AND ({self.get_date_filter('fecha_creacion')} OR fecha_creacion IS NULL)
            """, params)
            texto_err_pcf = "".join(
                [f"{idx + 1}. [{r['modulo']}] Ficha [{r['id_ficha']}]: {r['detalle_inconsistencias']}\n" for idx, r in
                 enumerate(res_err_pcf)])
        except:
            texto_err_pcf = ""

        data["pcf"] = {"familias_intervenidas": len(tabla_principal), "familias_duplicadas": len(dups_pcf_list),
                       "integrantes_intervenidos": len(tabla_integrantes),
                       "integrantes_duplicados": len(dups_ind_pcf_aud_list), "tabla_principal": tabla_principal,
                       "tabla_integrantes": tabla_integrantes,
                       "reporte_errores": texto_err_pcf if texto_err_pcf else "✅ Excelente. No hay errores de registro.",
                       "reporte_duplicados_fam": "\n".join(dups_pcf_list) or "✅ No se detectaron planes duplicados.",
                       "reporte_duplicados_ind": "\n".join(
                           dups_ind_pcf_aud_list) or "✅ No se detectaron integrantes duplicados."}

        # =========================================================================
        # 🟢 6. REPORTE DE INCONSISTENCIAS GLOBAL ABSOLUTO (Corrección Estricta)
        # =========================================================================
        query_errores_global = f"""
            SELECT modulo, id_ficha, usuario_creador, titulo_ficha, fecha_creacion, cantidad_errores, detalle_inconsistencias
            FROM auditoria_errores_2026
            WHERE {err_where_auditoria}
            ORDER BY modulo ASC, fecha_creacion DESC NULLS LAST
        """

        lista_errores_texto = []
        try:
            # Aquí la variable params se inyecta de forma segura a través de SQLAlchemy
            rows_errores = self.ejecutar(query_errores_global, params)
            errores_por_modulo = {}
            for row in rows_errores:
                mod = str(row.get('modulo', 'MÓDULO GENERAL / SIN CLASIFICAR')).strip().upper()
                if mod not in errores_por_modulo: errores_por_modulo[mod] = []
                errores_por_modulo[mod].append(row)

            for mod, errs in errores_por_modulo.items():
                lista_errores_texto.append(f"==================================================")
                lista_errores_texto.append(f"🛑 MÓDULO: {mod} ({len(errs)} registros con error)")
                lista_errores_texto.append(f"==================================================")
                for r in errs:
                    fecha_f = str(r.get('fecha_creacion', 'Sin fecha registrada'))[:19]
                    usr = str(r.get('usuario_creador', 'N/A'))
                    lista_errores_texto.append(
                        f"📅 Fecha Reporte : {fecha_f}\n👤 Usuario Creador: {usr}\n📄 Ficha ID       : {r.get('id_ficha', 'N/A')}\n🔖 Título Ficha   : {r.get('titulo_ficha', 'N/A')}\n⚠️ Inconsistencias ({r.get('cantidad_errores', 1)}): {r.get('detalle_inconsistencias', '')}\n{'-' * 50}")
                lista_errores_texto.append("")
        except Exception as e:
            logger.error(f"Error procesando reporte de errores global: {e}")

        data["reporte_errores_texto"] = "\n".join(
            lista_errores_texto).strip() if lista_errores_texto else "✅ ¡Excelente! No se encontraron errores de auditoría para este especialista en toda la base de datos."

        return data
