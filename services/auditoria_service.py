# -*- coding: utf-8 -*-
import re
from collections import Counter
import logging
from database.db_core import BaseService
from sqlalchemy import text

logger = logging.getLogger("AuditoriaService")


class AuditoriaService(BaseService):

    def obtener_datos(self, correo: str, nombre: str, fecha_ini: str, fecha_fin: str,
                      tipo_fecha: str = 'created_at') -> dict:
        f_ini = fecha_ini or "2000-01-01"
        f_fin = fecha_fin or "2099-12-31"

        email_res = correo if correo else self.resolver_correo(nombre)
        params = {"correo": correo, "nombre": nombre, "email_res": email_res, "f_ini": f_ini, "f_fin": f_fin}

        if correo:
            w_desist = "LOWER(TRIM(CAST(created_by AS text))) = LOWER(:correo)"
            w_pcc_prin = "LOWER(TRIM(CAST(created_by AS text))) = LOWER(:correo)"
            w_pcc_int = "LOWER(TRIM(CAST(p.created_by AS text))) = LOWER(:correo)"
            j_caract_ind = ""
            w_caract_fam = "LOWER(TRIM(CAST(created_by AS text))) = LOWER(:correo)"
            w_caract_ind = "LOWER(TRIM(CAST(tbl.created_by AS text))) = LOWER(:correo)"
            w_pcf_prin = "LOWER(TRIM(CAST(created_by AS text))) = LOWER(:correo)"
            w_pcf_int = "LOWER(TRIM(CAST(p.created_by AS text))) = LOWER(:correo)"
            j_psico_prin = ""
            w_psico_prin = "LOWER(TRIM(CAST(tbl.created_by AS text))) = LOWER(:correo)"
            j_psico_seg = "JOIN pcf_psicologia_principal_2026 i_seg ON tbl.ec5_branch_owner_uuid = i_seg.ec5_uuid JOIN pcf_planes_principal_2026 p ON i_seg.ec5_parent_uuid = p.ec5_uuid"
            w_psico_seg = "LOWER(TRIM(CAST(p.created_by AS text))) = LOWER(:correo)"
            w_tramites = "LOWER(TRIM(CAST(created_by AS text))) = LOWER(:correo)"
            w_psico_ant_fam = "LOWER(TRIM(CAST(f.created_by AS text))) = LOWER(:correo)"
            j_psico_ant_ind = ""
            w_psico_ant_ind = "LOWER(TRIM(CAST(i.created_by AS text))) = LOWER(:correo)"
        else:
            w_desist = "LOWER(TRIM(CAST(\"13_10_nombre_profesi\" AS text))) = LOWER(:nombre)"
            w_pcc_prin = "LOWER(TRIM(CAST(\"4_4_nombre_del_profe\" AS text))) = LOWER(:nombre)"
            w_pcc_int = "LOWER(TRIM(CAST(p.\"4_4_nombre_del_profe\" AS text))) = LOWER(:nombre)"
            w_caract_fam = "LOWER(TRIM(CAST(\"32_20_responsable_de\" AS text))) = LOWER(:nombre)"
            j_caract_ind = "JOIN caracterizacion_si_aps_familiar_2026 f ON tbl.ec5_branch_owner_uuid = f.ec5_uuid"
            w_caract_ind = "LOWER(TRIM(CAST(f.\"32_20_responsable_de\" AS text))) = LOWER(:nombre)"
            w_pcf_prin = "LOWER(TRIM(CAST(\"5_4_nombre_del_profe\" AS text))) = LOWER(:nombre)"
            w_pcf_int = "LOWER(TRIM(CAST(p.\"5_4_nombre_del_profe\" AS text))) = LOWER(:nombre)"
            j_psico_prin = "JOIN pcf_planes_principal_2026 p ON tbl.ec5_parent_uuid = p.ec5_uuid"
            w_psico_prin = "LOWER(TRIM(CAST(p.\"5_4_nombre_del_profe\" AS text))) = LOWER(:nombre)"
            j_psico_seg = "JOIN pcf_psicologia_principal_2026 i_seg ON tbl.ec5_branch_owner_uuid = i_seg.ec5_uuid JOIN pcf_planes_principal_2026 p ON i_seg.ec5_parent_uuid = p.ec5_uuid"
            w_psico_seg = "LOWER(TRIM(CAST(p.\"5_4_nombre_del_profe\" AS text))) = LOWER(:nombre)"
            w_tramites = "LOWER(TRIM(CAST(\"10_7_nombre_profesio\" AS text))) = LOWER(:nombre)"
            w_psico_ant_fam = "LOWER(TRIM(CAST(f.\"5_4_nombre_del_profe\" AS text))) = LOWER(:nombre)"
            j_psico_ant_ind = "JOIN pcf_planes_principal_2026 f ON i.ec5_parent_uuid = f.ec5_uuid"
            w_psico_ant_ind = "LOWER(TRIM(CAST(f.\"5_4_nombre_del_profe\" AS text))) = LOWER(:nombre)"

        data = {"usuario": correo or nombre, "rango_fechas": f"{f_ini} / {f_fin}"}

        # 1. PERFIL
        query_perfil = f"""
                       SELECT "5_4_nombre_del_profe" as nombre, "4_3_perfil_profesion" as perfil, COUNT(*) as qty
                       FROM pcf_planes_principal_2026
                       WHERE {w_pcf_prin}
                         AND {self.get_date_filter(tipo_fecha)}
                         AND "5_4_nombre_del_profe" IS NOT NULL
                       GROUP BY 1, 2
                       ORDER BY qty DESC LIMIT 1
                       """
        res_perfil = self.ejecutar(query_perfil, params)
        if res_perfil:
            data["encuestador_nombre"] = res_perfil[0]["nombre"]
            data["encuestador_perfil"] = res_perfil[0]["perfil"]
        else:
            data["encuestador_nombre"] = "Sin registro de nombre"
            data["encuestador_perfil"] = "Sin registro de perfil"

        data["desistimientos"] = {
            "total": self.safe_count(
                f"SELECT COUNT(*) FROM desistimiento_aps_2026 WHERE {w_desist} AND {self.get_date_filter(tipo_fecha)}",
                params),
            "con_error": self.safe_count(
                f"SELECT COUNT(*) FROM auditoria_errores_2026 WHERE LOWER(TRIM(CAST(usuario_creador AS text))) = LOWER(:email_res) AND modulo = 'DESISTIMIENTOS' AND {self.get_date_filter('fecha_creacion')}",
                params)
        }

        query_pcc_int = f"""
                        SELECT COUNT(*)
                        FROM pcc_integrantes_2026 b
                        JOIN pcc_principal_2026 p ON b.ec5_branch_owner_uuid = p.ec5_uuid
                        WHERE {w_pcc_int}
                          AND {self.get_date_filter(f'p.{tipo_fecha}')}
                        """
        pcc_planes_count = self.safe_count(
            f"SELECT COUNT(*) FROM pcc_principal_2026 WHERE {w_pcc_prin} AND {self.get_date_filter(tipo_fecha)}",
            params)

        texto_pcc_detalles = ""
        if pcc_planes_count > 0:
            try:
                res_pcc = self.ejecutar(f"""
                                   SELECT ec5_uuid, {tipo_fecha} as fecha_base, "20_14_detalles_jorna"
                                   FROM pcc_principal_2026
                                   WHERE {w_pcc_prin} AND {self.get_date_filter(tipo_fecha)}
                                   """, params)
                for idx, r in enumerate(res_pcc, 1):
                    uid_ficha = r.get('ec5_uuid', 'N/A')
                    fecha = str(r.get('fecha_base', ''))[:10]
                    detalle = str(r.get("20_14_detalles_jorna", "")).replace('\n', ' ')
                    if not detalle or detalle == 'None': detalle = "Sin detalles registrados."
                    texto_pcc_detalles += f"Plan {idx} [{uid_ficha}] - {fecha}: {detalle}\n\n"
            except:
                pass

        data["pcc"] = {
            "planes": pcc_planes_count,
            "integrantes": self.safe_count(query_pcc_int, params),
            "con_error": self.safe_count(
                f"SELECT COUNT(*) FROM auditoria_errores_2026 WHERE LOWER(TRIM(CAST(usuario_creador AS text))) = LOWER(:email_res) AND modulo LIKE 'PCC%' AND {self.get_date_filter('fecha_creacion')}",
                params),
            "reporte_detalles": texto_pcc_detalles.strip() if texto_pcc_detalles else "No hay detalles de planes comunitarios registrados."
        }

        query_edades_aud = f"""
                           WITH fechas_limpias AS (
                               SELECT CASE 
                                           WHEN CAST(tbl.{tipo_fecha} AS text) ~ '^[0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}}' THEN to_date(LEFT(CAST(tbl.{tipo_fecha} AS text), 10), 'YYYY-MM-DD') 
                                           WHEN CAST(tbl.{tipo_fecha} AS text) ~ '^[0-9]{{2}}/[0-9]{{2}}/[0-9]{{4}}' THEN to_date(LEFT(CAST(tbl.{tipo_fecha} AS text), 10), 'DD/MM/YYYY') 
                                           ELSE NULL END as f_crea,
                                      TRIM(CAST(tbl."107_7_fecha_de_nacim" AS text)) as f_nac_raw
                               FROM caracterizacion_si_aps_individual_2026 tbl
                               {j_caract_ind}
                               WHERE {w_caract_ind}
                                 AND {self.get_date_filter(f'tbl.{tipo_fecha}')}
                                 AND tbl."107_7_fecha_de_nacim" IS NOT NULL
                           ),
                           edades AS (
                               SELECT f_crea,
                                      CASE
                                          WHEN f_nac_raw ~ '^[0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}}' THEN to_date(LEFT(f_nac_raw, 10), 'YYYY-MM-DD')
                                          WHEN f_nac_raw ~ '^[0-9]{{2}}/[0-9]{{2}}/[0-9]{{4}}' THEN to_date(LEFT(f_nac_raw, 10), 'DD/MM/YYYY')
                                          ELSE NULL
                                          END as f_nac
                               FROM fechas_limpias
                           )
                           SELECT COUNT(*) FILTER (WHERE EXTRACT(YEAR FROM AGE(f_crea, f_nac)) < 5) as menores, 
                                  COUNT(*) FILTER (WHERE EXTRACT(YEAR FROM AGE(f_crea, f_nac)) >= 60) as mayores
                           FROM edades WHERE f_nac IS NOT NULL
                           """
        res_edades_aud = self.ejecutar(query_edades_aud, params)
        men_5_aud = res_edades_aud[0]["menores"] if res_edades_aud else 0
        may_60_aud = res_edades_aud[0]["mayores"] if res_edades_aud else 0

        tipo_familia_aud = self.safe_group(f"""
                                      SELECT "64_41_tipo_de_famili", COUNT(*) as total
                                      FROM caracterizacion_si_aps_familiar_2026
                                      WHERE {w_caract_fam} AND {self.get_date_filter(tipo_fecha)} AND "64_41_tipo_de_famili" IS NOT NULL
                                      GROUP BY 1 ORDER BY 2 DESC
                                      """, params)

        estrato_aud = self.safe_group(f"""
                                 SELECT "23_12_estrato_socioe", COUNT(*) as total
                                 FROM caracterizacion_si_aps_familiar_2026
                                 WHERE {w_caract_fam} AND {self.get_date_filter(tipo_fecha)} AND "23_12_estrato_socioe" IS NOT NULL
                                 GROUP BY 1 ORDER BY 1
                                 """, params)

        nivel_educativo_aud = self.safe_group(f"""
                                         SELECT tbl."112_12_nivel_educati", COUNT(*) as total
                                         FROM caracterizacion_si_aps_individual_2026 tbl
                                         {j_caract_ind}
                                         WHERE {w_caract_ind} AND {self.get_date_filter(f'tbl.{tipo_fecha}')} AND tbl."112_12_nivel_educati" IS NOT NULL
                                         GROUP BY 1 ORDER BY 2 DESC
                                         """, params)

        etnia_comp_aud = self.ejecutar(f"""
                                  SELECT COUNT(*) FILTER (WHERE tbl."116_16_pertenencia_t" = '7. Ninguna' OR tbl."116_16_pertenencia_t" IS NULL) AS sin_etnia, 
                                         COUNT(*) FILTER (WHERE tbl."116_16_pertenencia_t" IS NOT NULL AND tbl."116_16_pertenencia_t" != '7. Ninguna') AS con_etnia, 
                                         COUNT(*) AS total
                                  FROM caracterizacion_si_aps_individual_2026 tbl
                                  {j_caract_ind}
                                  WHERE {w_caract_ind} AND {self.get_date_filter(f'tbl.{tipo_fecha}')}
                                  """, params)

        etnia_data_aud = etnia_comp_aud[0] if etnia_comp_aud else {"sin_etnia": 0, "con_etnia": 0, "total": 0}
        total_etnia_aud = int(etnia_data_aud.get("total") or 1)
        if total_etnia_aud == 0: total_etnia_aud = 1

        query_disc_aud = f"""
                         SELECT tbl.ec5_branch_owner_uuid as id_ficha, tbl."119_19_reconoce_algu" as disc
                         FROM caracterizacion_si_aps_individual_2026 tbl
                         {j_caract_ind}
                         WHERE {w_caract_ind} AND {self.get_date_filter(f'tbl.{tipo_fecha}')} AND tbl."119_19_reconoce_algu" IS NOT NULL
                         """
        res_disc_aud = self.ejecutar(query_disc_aud, params)
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

        # 🛑 DUPLICADOS EN FAMILIAS
        raw_fam_aud = self.ejecutar(f"""
            SELECT ec5_uuid, title, "1_1_consentimiento_i",
                   created_by, "12_4_territorio", "13_5_microterritorio", "18_10_cdigo_hogar", "19_101_cdigo_hogar", "21_11_cdigo_familia", "22_111_cdigo_familia"
            FROM caracterizacion_si_aps_familiar_2026
            WHERE {w_caract_fam} AND {self.get_date_filter(tipo_fecha)}
        """, params)

        seen_t_aud = set()
        seen_c_aud = set()
        uniq_fam_aud = 0
        dups_fam_list = []

        for r in raw_fam_aud:
            consent = str(r.get("1_1_consentimiento_i", "")).strip().upper()
            if consent != '1. SI': continue

            uid = str(r.get("ec5_uuid", ""))
            t = str(r.get("title", "")).strip().lower()
            t_key = t if t and t != "none" else None

            c1 = str(r.get("created_by", "")).strip().lower()
            c2 = str(r.get("12_4_territorio", "")).strip().lower()
            c3 = str(r.get("13_5_microterritorio", "")).strip().lower()
            c4 = str(r.get("18_10_cdigo_hogar", "")).strip().lower()
            c5 = str(r.get("19_101_cdigo_hogar", "")).strip().lower()
            c6 = str(r.get("21_11_cdigo_familia", "")).strip().lower()
            c7 = str(r.get("22_111_cdigo_familia", "")).strip().lower()
            c_key = f"{c1}|{c2}|{c3}|{c4}|{c5}|{c6}|{c7}"

            is_dup = False
            reasons = []

            if t_key and t_key in seen_t_aud:
                is_dup = True
                reasons.append("Título repetido")
            if c_key != "||||||" and c_key.replace("none", "").replace("|", "") != "":
                if c_key in seen_c_aud:
                    is_dup = True
                    reasons.append("Códigos/Territorio concatenados repetidos")

            if is_dup:
                dups_fam_list.append(
                    f"Ficha [{uid}] - {t.title() if t and t != 'none' else 'N/A'} -> Motivo: {' y '.join(reasons)}")
            else:
                if t_key: seen_t_aud.add(t_key)
                if c_key != "||||||" and c_key.replace("none", "").replace("|", "") != "": seen_c_aud.add(c_key)
                uniq_fam_aud += 1

        texto_dups_fam = "\n".join(dups_fam_list) if dups_fam_list else "✅ No se detectaron familias duplicadas."
        dups_fam_count = len(dups_fam_list)

        # 🛑 DUPLICADOS EN INDIVIDUOS
        raw_ind_aud = self.ejecutar(f"""
            SELECT tbl.ec5_branch_uuid, tbl.title, tbl.{tipo_fecha}
            FROM caracterizacion_si_aps_individual_2026 tbl
            {j_caract_ind}
            WHERE {w_caract_ind} AND {self.get_date_filter(f'tbl.{tipo_fecha}')}
        """, params)

        seen_t_ind_aud = set()
        uniq_ind_aud = 0
        dups_ind_list = []

        for r in raw_ind_aud:
            uid = str(r.get("ec5_branch_uuid", ""))
            t = str(r.get("title", "")).strip().lower()
            t_key = t if t and t != "none" else None

            if t_key and t_key in seen_t_ind_aud:
                dups_ind_list.append(
                    f"Ficha [{uid}] - Nombre: {t.title() if t and t != 'none' else 'N/A'} -> Motivo: Integrante repetido (Título idéntico)")
            else:
                if t_key: seen_t_ind_aud.add(t_key)
                uniq_ind_aud += 1

        texto_dups_ind = "\n".join(dups_ind_list) if dups_ind_list else "✅ No se detectaron integrantes duplicados."
        dups_ind_count = len(dups_ind_list)

        data["caracterizacion"] = {
            "familias": uniq_fam_aud,
            "familias_duplicadas": dups_fam_count,
            "reporte_duplicados_fam": texto_dups_fam,
            "individuos": uniq_ind_aud,
            "individuos_duplicadas": dups_ind_count,
            "reporte_duplicados_ind": texto_dups_ind,
            "gestantes": self.safe_count(
                f"SELECT COUNT(*) FROM caracterizacion_si_aps_individual_2026 tbl {j_caract_ind} WHERE {w_caract_ind} AND {self.get_date_filter(f'tbl.{tipo_fecha}')} AND tbl.\"109_9_se_encuentra_e\" = '1. SI'",
                params),
            "menores_5": men_5_aud, "adultos_60": may_60_aud,
            "victimas_conflicto": self.safe_count(
                f"SELECT COUNT(*) FROM caracterizacion_si_aps_familiar_2026 WHERE {w_caract_fam} AND {self.get_date_filter(tipo_fecha)} AND \"78_52_familia_vctima\" = '1. SI'",
                params),
            "poblacion_etnica": self.safe_count(
                f"SELECT COUNT(*) FROM caracterizacion_si_aps_individual_2026 tbl {j_caract_ind} WHERE {w_caract_ind} AND {self.get_date_filter(f'tbl.{tipo_fecha}')} AND tbl.\"116_16_pertenencia_t\" IS NOT NULL AND tbl.\"116_16_pertenencia_t\" != '7. Ninguna'",
                params),
            "sin_aseguramiento": self.safe_count(
                f"SELECT COUNT(*) FROM caracterizacion_si_aps_individual_2026 tbl {j_caract_ind} WHERE {w_caract_ind} AND {self.get_date_filter(f'tbl.{tipo_fecha}')} AND tbl.\"113_13_rgimen_de_afi\" = '5. No afiliado'",
                params),
            "discapacidad_total": total_discapacidad_aud, "discapacidades_chart": disc_chart_aud,
            "error_familiar": self.safe_count(
                f"SELECT COUNT(*) FROM auditoria_errores_2026 WHERE LOWER(TRIM(CAST(usuario_creador AS text))) = LOWER(:email_res) AND modulo = 'CARACT_FAMILIAR' AND {self.get_date_filter('fecha_creacion')}",
                params),
            "error_individual": self.safe_count(
                f"SELECT COUNT(*) FROM auditoria_errores_2026 WHERE LOWER(TRIM(CAST(usuario_creador AS text))) = LOWER(:email_res) AND modulo = 'CARACT_INDIVIDUAL' AND {self.get_date_filter('fecha_creacion')}",
                params),
            "tipo_familia": tipo_familia_aud, "estrato": estrato_aud, "nivel_educativo": nivel_educativo_aud,
            "etnia_sin_pct": round(int(etnia_data_aud.get("sin_etnia") or 0) / total_etnia_aud * 100, 1),
            "etnia_con_pct": round(int(etnia_data_aud.get("con_etnia") or 0) / total_etnia_aud * 100, 1),
            "etnia_con_total": int(etnia_data_aud.get("con_etnia") or 0)
        }

        # === BLOQUE CARACTERIZACIÓN (PERÍODO ANTERIOR ACUMULADO) ===
        raw_fam_ant = self.ejecutar(
            f"SELECT title, \"1_1_consentimiento_i\", created_by, \"12_4_territorio\", \"13_5_microterritorio\", \"18_10_cdigo_hogar\", \"19_101_cdigo_hogar\", \"21_11_cdigo_familia\", \"22_111_cdigo_familia\" FROM caracterizacion_si_aps_familiar_2026 WHERE {w_caract_fam} AND {self.get_date_filter_ant(tipo_fecha)}",
            params)
        seen_t_ant, seen_c_ant, uniq_fam_ant, dup_fam_ant = set(), set(), 0, 0
        for r in raw_fam_ant:
            if str(r.get("1_1_consentimiento_i", "")).strip().upper() != '1. SI': continue
            t = str(r.get("title", "")).strip().lower()
            t_key = t if t and t != "none" else None
            c_key = f"{r.get('created_by', '')}|{r.get('12_4_territorio', '')}|{r.get('13_5_microterritorio', '')}|{r.get('18_10_cdigo_hogar', '')}|{r.get('19_101_cdigo_hogar', '')}|{r.get('21_11_cdigo_familia', '')}|{r.get('22_111_cdigo_familia', '')}".lower().strip()
            is_dup = False
            if t_key and t_key in seen_t_ant: is_dup = True
            if c_key != "||||||" and c_key.replace("none", "").replace("|", "") != "":
                if c_key in seen_c_ant: is_dup = True
            if is_dup:
                dup_fam_ant += 1
            else:
                if t_key: seen_t_ant.add(t_key)
                if c_key != "||||||" and c_key.replace("none", "").replace("|", "") != "": seen_c_ant.add(c_key)
                uniq_fam_ant += 1

        raw_ind_ant = self.ejecutar(
            f"SELECT tbl.title FROM caracterizacion_si_aps_individual_2026 tbl {j_caract_ind} WHERE {w_caract_ind} AND {self.get_date_filter_ant(f'tbl.{tipo_fecha}')}",
            params)
        seen_t_ind_ant, uniq_ind_ant, dup_ind_ant = set(), 0, 0
        for r in raw_ind_ant:
            t = str(r.get("title", "")).strip().lower()
            t_key = t if t and t != "none" else None
            if t_key and t_key in seen_t_ind_ant:
                dup_ind_ant += 1
            else:
                if t_key: seen_t_ind_ant.add(t_key)
                uniq_ind_ant += 1

        sin_aseg_ant = self.safe_count(
            f"SELECT COUNT(*) FROM caracterizacion_si_aps_individual_2026 tbl {j_caract_ind} WHERE {w_caract_ind} AND {self.get_date_filter_ant(f'tbl.{tipo_fecha}')} AND tbl.\"113_13_rgimen_de_afi\" = '5. No afiliado'",
            params)
        gestantes_ant = self.safe_count(
            f"SELECT COUNT(*) FROM caracterizacion_si_aps_individual_2026 tbl {j_caract_ind} WHERE {w_caract_ind} AND {self.get_date_filter_ant(f'tbl.{tipo_fecha}')} AND tbl.\"109_9_se_encuentra_e\" = '1. SI'",
            params)
        victimas_ant = self.safe_count(
            f"SELECT COUNT(*) FROM caracterizacion_si_aps_familiar_2026 WHERE {w_caract_fam} AND {self.get_date_filter_ant(tipo_fecha)} AND \"78_52_familia_vctima\" = '1. SI'",
            params)

        query_edades_ant = f"""
            WITH fechas_limpias AS (SELECT CASE WHEN CAST(tbl.{tipo_fecha} AS text) ~ '^[0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}}' THEN to_date(LEFT(CAST(tbl.{tipo_fecha} AS text), 10), 'YYYY-MM-DD') WHEN CAST(tbl.{tipo_fecha} AS text) ~ '^[0-9]{{2}}/[0-9]{{2}}/[0-9]{{4}}' THEN to_date(LEFT(CAST(tbl.{tipo_fecha} AS text), 10), 'DD/MM/YYYY') ELSE NULL END as f_crea, TRIM(CAST(tbl."107_7_fecha_de_nacim" AS text)) as f_nac_raw FROM caracterizacion_si_aps_individual_2026 tbl {j_caract_ind} WHERE {w_caract_ind} AND {self.get_date_filter_ant(f'tbl.{tipo_fecha}')} AND tbl."107_7_fecha_de_nacim" IS NOT NULL),
            edades AS (SELECT f_crea, CASE WHEN f_nac_raw ~ '^[0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}}' THEN to_date(LEFT(f_nac_raw, 10), 'YYYY-MM-DD') WHEN f_nac_raw ~ '^[0-9]{{2}}/[0-9]{{2}}/[0-9]{{4}}' THEN to_date(LEFT(f_nac_raw, 10), 'DD/MM/YYYY') ELSE NULL END as f_nac FROM fechas_limpias)
            SELECT COUNT(*) FILTER (WHERE EXTRACT(YEAR FROM AGE(f_crea, f_nac)) < 5) as menores, COUNT(*) FILTER (WHERE EXTRACT(YEAR FROM AGE(f_crea, f_nac)) >= 60) as mayores FROM edades WHERE f_nac IS NOT NULL
        """
        res_edades_ant = self.ejecutar(query_edades_ant, params)

        res_disc_ant = self.ejecutar(
            f"SELECT tbl.\"119_19_reconoce_algu\" as disc FROM caracterizacion_si_aps_individual_2026 tbl {j_caract_ind} WHERE {w_caract_ind} AND {self.get_date_filter_ant(f'tbl.{tipo_fecha}')} AND tbl.\"119_19_reconoce_algu\" IS NOT NULL",
            params)
        disc_tot_ant = sum(1 for r in res_disc_ant if "Sin discapacidad" not in str(r["disc"]))

        data["caracterizacion_ant"] = {
            "familias": uniq_fam_ant, "familias_duplicadas": dup_fam_ant,
            "individuos": uniq_ind_ant, "individuos_duplicadas": dup_ind_ant,
            "sin_aseguramiento": sin_aseg_ant
        }
        data["poblacion_ant"] = {
            "gestantes": gestantes_ant, "menores_5": res_edades_ant[0]["menores"] if res_edades_ant else 0,
            "adultos_60": res_edades_ant[0]["mayores"] if res_edades_ant else 0,
            "victimas_conflicto": victimas_ant, "discapacidad_total": disc_tot_ant
        }

        # 🛑 DUPLICADOS EN PCF GENERAL 🛑
        raw_pcf_aud = self.ejecutar(f"""
            SELECT ec5_uuid, title, {tipo_fecha} as fecha_base, created_by, 
                   "9_7_territorio", "10_8_microterritorio", "11_9_identificacin_d", 
                   "12_91_identificacin_", "13_10_identificacin_", "14_101_identificacin"
            FROM pcf_planes_principal_2026
            WHERE {w_pcf_prin} AND {self.get_date_filter(tipo_fecha)}
              AND ("4_3_perfil_profesion" IS NULL OR TRIM("4_3_perfil_profesion") != 'Profesional Psicología')
        """, params)

        seen_c_pcf_aud = set()
        uniq_pcf_aud = 0
        dups_pcf_list = []
        texto_pcf_fam = ""
        c_pcf_ok = 1

        for r in raw_pcf_aud:
            uid = str(r.get("ec5_uuid", "N/A"))
            t = str(r.get("title", "")).strip().lower()
            f = str(r.get("fecha_base", ""))[:10]

            c1 = str(r.get("created_by", "")).strip().lower()
            c2 = str(r.get("9_7_territorio", "")).strip().lower()
            c3 = str(r.get("10_8_microterritorio", "")).strip().lower()
            c4 = str(r.get("11_9_identificacin_d", "")).strip().lower()
            c5 = str(r.get("12_91_identificacin_", "")).strip().lower()
            c6 = str(r.get("13_10_identificacin_", "")).strip().lower()
            c7 = str(r.get("14_101_identificacin", "")).strip().lower()
            c_key = f"{c1}|{c2}|{c3}|{c4}|{c5}|{c6}|{c7}"

            is_dup = False
            if c_key != "||||||" and c_key.replace("none", "").replace("|", "") != "":
                if c_key in seen_c_pcf_aud:
                    is_dup = True

            if is_dup:
                dups_pcf_list.append(
                    f"Ficha [{uid}] - {t.title() if t and t != 'none' else 'N/A'} -> Motivo: Identificación/Territorio repetido")
            else:
                if c_key != "||||||" and c_key.replace("none", "").replace("|", "") != "":
                    seen_c_pcf_aud.add(c_key)
                uniq_pcf_aud += 1
                texto_pcf_fam += f"Intervención {c_pcf_ok}: Ficha [{uid}] - {f}\n"
                c_pcf_ok += 1

        texto_dups_pcf = "\n".join(dups_pcf_list) if dups_pcf_list else "✅ No se detectaron planes duplicados."
        dups_pcf_count = len(dups_pcf_list)

        # 🛑 DUPLICADOS EN PCF INTEGRANTES 🛑
        raw_pcf_ind_aud = self.ejecutar(f"""
            SELECT b.ec5_branch_uuid, b.title, p.created_by
            FROM pcf_planes_integrantes_2026 b
            JOIN pcf_planes_principal_2026 p ON b.ec5_branch_owner_uuid = p.ec5_uuid
            WHERE {w_pcf_int} AND {self.get_date_filter(f'p.{tipo_fecha}')}
              AND (p."4_3_perfil_profesion" IS NULL OR TRIM(p."4_3_perfil_profesion") != 'Profesional Psicología')
        """, params)

        seen_ind_pcf_aud = set()
        uniq_ind_pcf_aud = 0
        dups_ind_pcf_aud_list = []

        for r in raw_pcf_ind_aud:
            uid = str(r.get("ec5_branch_uuid", "N/A"))
            t = str(r.get("title", "")).strip().lower()
            c = str(r.get("created_by", "")).strip().lower()

            if not t or t == "none":
                uniq_ind_pcf_aud += 1
                continue

            clave = f"{c}|{t}"
            if clave in seen_ind_pcf_aud:
                dups_ind_pcf_aud_list.append(
                    f"Ficha [{uid}] - Integrante: {t.title()} -> Motivo: Nombre repetido por este encuestador")
            else:
                seen_ind_pcf_aud.add(clave)
                uniq_ind_pcf_aud += 1

        texto_dups_ind_pcf = "\n".join(
            dups_ind_pcf_aud_list) if dups_ind_pcf_aud_list else "✅ No se detectaron integrantes duplicados."
        dups_ind_pcf_aud_count = len(dups_ind_pcf_aud_list)

        try:
            res_err_pcf = self.ejecutar(f"""
                                   SELECT id_ficha, detalle_inconsistencias, modulo
                                   FROM auditoria_errores_2026
                                   WHERE LOWER(TRIM(CAST(usuario_creador AS text))) = LOWER(:email_res)
                                     AND modulo IN ('PCF_PRINCIPAL', 'PCF_INTEGRANTES')
                                     AND {self.get_date_filter('fecha_creacion')}
                                   """, params)
            texto_err_pcf = "".join(
                [f"{idx + 1}. [{r['modulo']}] Ficha [{r['id_ficha']}]: {r['detalle_inconsistencias']}\n" for idx, r in
                 enumerate(res_err_pcf)])
        except:
            texto_err_pcf = ""

        # === BLOQUE PCF GENERAL (PERÍODO ANTERIOR ACUMULADO) ===
        raw_pcf_ant = self.ejecutar(
            f"SELECT created_by, \"9_7_territorio\", \"10_8_microterritorio\", \"11_9_identificacin_d\", \"12_91_identificacin_\", \"13_10_identificacin_\", \"14_101_identificacin\" FROM pcf_planes_principal_2026 WHERE {w_pcf_prin} AND {self.get_date_filter_ant(tipo_fecha)} AND (\"4_3_perfil_profesion\" IS NULL OR TRIM(\"4_3_perfil_profesion\") != 'Profesional Psicología')",
            params)
        seen_c_pcf_ant, uniq_pcf_ant, dup_pcf_ant = set(), 0, 0
        for r in raw_pcf_ant:
            c_key = f"{r.get('created_by', '')}|{r.get('9_7_territorio', '')}|{r.get('10_8_microterritorio', '')}|{r.get('11_9_identificacin_d', '')}|{r.get('12_91_identificacin_', '')}|{r.get('13_10_identificacin_', '')}|{r.get('14_101_identificacin', '')}".lower().strip()
            if c_key == "||||||" or c_key.replace("none", "").replace("|", "") == "": uniq_pcf_ant += 1; continue
            if c_key in seen_c_pcf_ant:
                dup_pcf_ant += 1
            else:
                seen_c_pcf_ant.add(c_key); uniq_pcf_ant += 1

        raw_pcf_ind_ant = self.ejecutar(
            f"SELECT b.title, p.created_by FROM pcf_planes_integrantes_2026 b JOIN pcf_planes_principal_2026 p ON b.ec5_branch_owner_uuid = p.ec5_uuid WHERE {w_pcf_int} AND {self.get_date_filter_ant(f'p.{tipo_fecha}')} AND (p.\"4_3_perfil_profesion\" IS NULL OR TRIM(p.\"4_3_perfil_profesion\") != 'Profesional Psicología')",
            params)
        seen_ind_pcf_ant, uniq_ind_pcf_ant, dup_ind_pcf_ant = set(), 0, 0
        for r in raw_pcf_ind_ant:
            t, c = str(r.get("title", "")).strip().lower(), str(r.get("created_by", "")).strip().lower()
            if not t or t == "none": uniq_ind_pcf_ant += 1; continue
            clave = f"{c}|{t}"
            if clave in seen_ind_pcf_ant:
                dup_ind_pcf_ant += 1
            else:
                seen_ind_pcf_ant.add(clave); uniq_ind_pcf_ant += 1

        data["pcf_ant"] = {
            "familias_intervenidas": uniq_pcf_ant, "familias_duplicadas": dup_pcf_ant,
            "integrantes_intervenidos": uniq_ind_pcf_ant, "integrantes_duplicados": dup_ind_pcf_ant
        }

        data["pcf"] = {
            "familias_intervenidas": uniq_pcf_aud,
            "familias_duplicadas": dups_pcf_count,
            "integrantes_intervenidos": uniq_ind_pcf_aud,
            "integrantes_duplicados": dups_ind_pcf_aud_count,
            "reporte_familias": texto_pcf_fam if texto_pcf_fam else "No hay intervenciones registradas en estas fechas.",
            "reporte_errores": texto_err_pcf if texto_err_pcf else "✅ Excelente. No hay errores de registro.",
            "reporte_duplicados_fam": texto_dups_pcf,
            "reporte_duplicados_ind": texto_dups_ind_pcf
        }

        # 🛑 DUPLICADOS EN PCF PSICOLOGIA FAMILIAS 🛑
        raw_psico_fam_aud = self.ejecutar(f"""
            SELECT ec5_uuid, title, {tipo_fecha} as fecha_base, created_by, 
                   "9_7_territorio", "10_8_microterritorio", "11_9_identificacin_d", 
                   "12_91_identificacin_", "13_10_identificacin_", "14_101_identificacin"
            FROM pcf_planes_principal_2026
            WHERE {w_pcf_prin} AND {self.get_date_filter(tipo_fecha)}
              AND TRIM("4_3_perfil_profesion") = 'Profesional Psicología'
        """, params)

        seen_c_psico_fam_aud = set()
        uniq_psico_fam_aud = 0
        dups_psico_fam_list = []
        texto_psico_fam = ""
        c_psico_fam_ok = 1

        for r in raw_psico_fam_aud:
            uid = str(r.get("ec5_uuid", "N/A"))
            t = str(r.get("title", "")).strip().lower()
            f = str(r.get("fecha_base", ""))[:10]

            c1 = str(r.get("created_by", "")).strip().lower()
            c2 = str(r.get("9_7_territorio", "")).strip().lower()
            c3 = str(r.get("10_8_microterritorio", "")).strip().lower()
            c4 = str(r.get("11_9_identificacin_d", "")).strip().lower()
            c5 = str(r.get("12_91_identificacin_", "")).strip().lower()
            c6 = str(r.get("13_10_identificacin_", "")).strip().lower()
            c7 = str(r.get("14_101_identificacin", "")).strip().lower()
            c_key = f"{c1}|{c2}|{c3}|{c4}|{c5}|{c6}|{c7}"

            is_dup = False
            if c_key != "||||||" and c_key.replace("none", "").replace("|", "") != "":
                if c_key in seen_c_psico_fam_aud:
                    is_dup = True

            if is_dup:
                dups_psico_fam_list.append(
                    f"Ficha [{uid}] - {t.title() if t and t != 'none' else 'N/A'} -> Motivo: Identificación/Territorio repetido")
            else:
                if c_key != "||||||" and c_key.replace("none", "").replace("|", "") != "":
                    seen_c_psico_fam_aud.add(c_key)
                uniq_psico_fam_aud += 1
                texto_psico_fam += f"Intervención {c_psico_fam_ok}: Ficha [{uid}] - {f}\n"
                c_psico_fam_ok += 1

        texto_dups_psico_fam = "\n".join(
            dups_psico_fam_list) if dups_psico_fam_list else "✅ No se detectaron familias duplicadas en Psicología."
        dups_psico_fam_count = len(dups_psico_fam_list)

        # 🛑 FAMILIAS E INTEGRANTES ANTERIORES EN PSICOLOGIA 🛑
        raw_fam_ant = self.ejecutar(f"""
            SELECT f.ec5_uuid
            FROM pcf_psicologia_seguimientos_2026 s
            JOIN pcf_psicologia_principal_2026 i ON s.ec5_branch_owner_uuid = i.ec5_uuid
            JOIN pcf_planes_principal_2026 f ON i.ec5_parent_uuid = f.ec5_uuid
            WHERE {w_psico_ant_fam}
              AND {self.get_date_filter(f's.{tipo_fecha}')}
              AND NOT ({self.get_date_filter(f'f.{tipo_fecha}')})
        """, params)
        familias_anteriores_aud = len(set([str(r.get("ec5_uuid")) for r in raw_fam_ant]))

        raw_ind_ant = self.ejecutar(f"""
            SELECT i.ec5_uuid
            FROM pcf_psicologia_seguimientos_2026 s
            JOIN pcf_psicologia_principal_2026 i ON s.ec5_branch_owner_uuid = i.ec5_uuid
            {j_psico_ant_ind}
            WHERE {w_psico_ant_ind}
              AND {self.get_date_filter(f's.{tipo_fecha}')}
              AND NOT ({self.get_date_filter(f'i.{tipo_fecha}')})
        """, params)
        integrantes_anteriores_aud = len(set([str(r.get("ec5_uuid")) for r in raw_ind_ant]))

        integrantes_psico_count = self.safe_count(f"""
            SELECT COUNT(*) FROM pcf_psicologia_principal_2026 tbl
            {j_psico_prin}
            WHERE {w_psico_prin} AND {self.get_date_filter(f'tbl.{tipo_fecha}')}
        """, params)

        try:
            res_psico_seg = self.ejecutar(f"""
                                     SELECT tbl.*
                                     FROM pcf_psicologia_seguimientos_2026 tbl
                                     {j_psico_seg}
                                     WHERE {w_psico_seg} AND {self.get_date_filter(f'tbl.{tipo_fecha}')}
                                     """, params)
        except Exception as e:
            logger.error(f"Error consultando seguimientos de psicología: {e}")
            res_psico_seg = []

        seg_psico_count = len(res_psico_seg)
        motivos_count, cont_seg_si, cont_seg_no = {}, 0, 0
        tipo_seg_count = Counter()
        texto_psico_seg = ""
        texto_err_psico = ""
        texto_psico_compromisos = ""
        texto_psico_evaluacion = ""

        es_psicologo = (uniq_psico_fam_aud > 0 or seg_psico_count > 0)

        if es_psicologo:
            for idx, r in enumerate(res_psico_seg, 1):
                uid_ficha = r.get('ec5_branch_owner_uuid') or r.get('ec5_uuid') or 'N/A'
                fecha_str = str(r.get(tipo_fecha, ''))[:10]
                texto_psico_seg += f"Seguimiento {idx}: Ficha [{uid_ficha}] - {fecha_str}\n"

                tipo_seg = next((v for k, v in r.items() if k.startswith('128_23_')), None)
                motivo = next((v for k, v in r.items() if k.startswith('129_24_')), None)
                req_cont = next((v for k, v in r.items() if k.startswith('130_25_')), None)
                comp = next((v for k, v in r.items() if k.startswith('131_26_')), None)
                evalu = next((v for k, v in r.items() if k.startswith('132_27_')), None)

                if tipo_seg and str(tipo_seg).strip() and str(tipo_seg).strip() != 'None':
                    lbl_ts = str(tipo_seg).strip()
                    lbl_ts = re.sub(r'^\d+[\.-]?\s*', '', lbl_ts)
                    tipo_seg_count[lbl_ts] += 1

                if motivo and str(motivo).strip() and str(motivo).strip() != 'None':
                    m_str = str(motivo).strip()
                    m_str = re.sub(r'^\d+[\.-]?\s*', '', m_str)
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
                res_err_psico = self.ejecutar(f"""
                                         SELECT id_ficha, detalle_inconsistencias, modulo
                                         FROM auditoria_errores_2026
                                         WHERE LOWER(TRIM(CAST(usuario_creador AS text))) = LOWER(:email_res)
                                           AND modulo IN ('PSICOLOGIA_PRINCIPAL', 'PSICOLOGIA_SEGUIMIENTOS')
                                           AND {self.get_date_filter('fecha_creacion')}
                                         """, params)
                for idx, r in enumerate(res_err_psico, 1):
                    texto_err_psico += f"{idx}. [{r['modulo']}] Ficha [{r['id_ficha']}]: {r['detalle_inconsistencias']}\n"
            except:
                pass

        data["pcf_psicologia"] = {
            "intervenciones_familiares": uniq_psico_fam_aud,
            "familias_duplicadas": dups_psico_fam_count,
            "familias_anteriores": familias_anteriores_aud,
            "reporte_duplicados_fam": texto_dups_psico_fam,
            "integrantes": integrantes_psico_count,
            "integrantes_anteriores": integrantes_anteriores_aud,
            "seguimientos": seg_psico_count,
            "tipos_seguimiento": [{"label": k, "total": v} for k, v in
                                  sorted(tipo_seg_count.items(), key=lambda item: item[1], reverse=True)],
            "motivos_seguimiento": [{"label": k, "total": v} for k, v in
                                    sorted(motivos_count.items(), key=lambda item: item[1], reverse=True)],
            "requiere_continuidad_si": cont_seg_si, "requiere_continuidad_no": cont_seg_no,
            "reporte_familias": texto_psico_fam if texto_psico_fam else "No hay intervenciones en estas fechas.",
            "reporte_seguimientos": texto_psico_seg if texto_psico_seg else "No hay seguimientos en estas fechas.",
            "reporte_compromisos": texto_psico_compromisos if texto_psico_compromisos else "No hay compromisos en estas fechas.",
            "reporte_evaluacion": texto_psico_evaluacion if texto_psico_evaluacion else "No hay evaluaciones en estas fechas.",
            "reporte_errores": texto_err_psico if texto_err_psico else "✅ Excelente. No hay errores en estas fechas."
        }

        res_tram_err = self.ejecutar(f"""
                                SELECT SUM(CAST(errores AS numeric)) as err
                                FROM tramites_consolidados_2026
                                WHERE LOWER(TRIM(CAST(usuario AS text))) = LOWER(:email_res)
                                  AND {self.get_date_filter('fecha')}
                                """, params)

        a_tr_err = int(res_tram_err[0]["err"] or 0) if res_tram_err else 0

        res_tramites_textos = self.ejecutar(f"""
                                       SELECT nombres_realizados, nombres_efectivos
                                       FROM tramites_consolidados_2026
                                       WHERE LOWER(TRIM(CAST(usuario AS text))) = LOWER(:email_res)
                                         AND {self.get_date_filter('fecha')}
                                       """, params)

        conteo_realizados_aud = Counter()
        conteo_efectivos_aud = Counter()
        texto_realizados, texto_resueltos, c_re, c_ef = "", "", 1, 1
        invalid_words = ['none', 'null', 'ningún', 'ningun', 'no aplica', 'na', 'n/a', '']

        for row in res_tramites_textos:
            nr = str(row.get("nombres_realizados", "")).replace("Ningún", "").strip()
            ne = str(row.get("nombres_efectivos", "")).replace("Ningún", "").strip()

            items_r = [x.strip() for x in re.split(r'[|,]', nr) if x.strip() and x.strip().lower() not in invalid_words]
            items_e = [x.strip() for x in re.split(r'[|,]', ne) if x.strip() and x.strip().lower() not in invalid_words]

            for item in items_r:
                if 'trámite resuelto' in item.lower() or 'tramite resuelto' in item.lower(): continue
                conteo_realizados_aud[item] += 1
                texto_realizados += f"Registro {c_re}: {item}\n"
                c_re += 1

                if 'adicional' in item.lower() or 'otro' in item.lower():
                    conteo_efectivos_aud[item] += 1
                    texto_resueltos += f"Registro {c_ef}: Trámite adicional Resuelto\n"
                    c_ef += 1
                    if item in items_e: items_e.remove(item)

            for item in items_e:
                if 'trámite resuelto' in item.lower() or 'tramite resuelto' in item.lower(): continue
                conteo_efectivos_aud[item] += 1
                texto_resueltos += f"Registro {c_ef}: {item}\n"
                c_ef += 1

        a_tr_tot = sum(conteo_realizados_aud.values())
        a_tr_res = sum(conteo_efectivos_aud.values())

        por_tipo_aud = []
        for k in sorted(set(conteo_realizados_aud.keys()).union(set(conteo_efectivos_aud.keys()))):
            v_realizados = conteo_realizados_aud.get(k, 0)
            v_efectivos = conteo_efectivos_aud.get(k, 0)
            if v_efectivos > v_realizados: v_realizados = v_efectivos
            por_tipo_aud.append({
                "label": k,
                "total": v_realizados,
                "resueltos": v_efectivos,
                "pendientes": v_realizados - v_efectivos,
                "porcentaje": round((v_efectivos / v_realizados * 100), 1) if v_realizados > 0 else 0
            })

        res_err_tr = self.ejecutar(f"""
                              SELECT id_ficha, detalle_inconsistencias
                              FROM auditoria_errores_2026
                              WHERE LOWER(TRIM(CAST(usuario_creador AS text))) = LOWER(:email_res)
                                AND modulo = 'TRAMITES'
                                AND {self.get_date_filter('fecha_creacion')}
                              """, params)

        texto_errores_tr = "".join(
            [f"{idx + 1}. Ficha [{r['id_ficha']}]: {r['detalle_inconsistencias']}\n" for idx, r in
             enumerate(res_err_tr)])

        tr_raw = self.ejecutar(f"""
            SELECT tbl.ec5_uuid, tbl.title, tbl.{tipo_fecha} as fecha_base, 
                   COALESCE(tbl."7_4_territorio", '') || COALESCE(tbl."8_5_microterritorio", '') || 
                   CASE WHEN tbl."3_2_cdigo_hogar" = 'No Aplica' OR tbl."3_2_cdigo_hogar" IS NULL THEN COALESCE(tbl."4_21_cdigo_hogar", '') ELSE tbl."3_2_cdigo_hogar" END || 
                   CASE WHEN tbl."5_3_cdigo_familia" = 'No Aplica' OR tbl."5_3_cdigo_familia" IS NULL THEN COALESCE(tbl."6_31_cdigo_familia", '') ELSE tbl."5_3_cdigo_familia" END as cod_familia
            FROM tramites_aps_2026 tbl
            WHERE {w_tramites} AND {self.get_date_filter(f'tbl.{tipo_fecha}')}
        """, params)

        titulos_fechas = {}
        duplicados_list = []
        familias_unicas = set()
        total_registros_brutos = 0

        for r in tr_raw:
            total_registros_brutos += 1
            t = str(r.get("title", "")).strip().lower()
            f = str(r.get("fecha_base", ""))[:10]
            uid = str(r.get("ec5_uuid", ""))
            fam = str(r.get("cod_familia", ""))

            if not t or t == "none": continue

            clave = f"{t}|{f}"
            if clave in titulos_fechas:
                duplicados_list.append(f"Ficha [{uid}] - Paciente: {t.title()} - Fecha: {f}")
            else:
                titulos_fechas[clave] = True
                if fam: familias_unicas.add(fam)

        duplicados_count = len(duplicados_list)
        tr_registros = max(0, total_registros_brutos - duplicados_count)

        tr_familias_query = f"""
                            SELECT COUNT(DISTINCT
                                         COALESCE(tbl."7_4_territorio", '') || COALESCE(tbl."8_5_microterritorio", '') ||
                                         CASE WHEN tbl."3_2_cdigo_hogar" = 'No Aplica' OR tbl."3_2_cdigo_hogar" IS NULL THEN COALESCE(tbl."4_21_cdigo_hogar", '') ELSE tbl."3_2_cdigo_hogar" END ||
                                         CASE WHEN tbl."5_3_cdigo_familia" = 'No Aplica' OR tbl."5_3_cdigo_familia" IS NULL THEN COALESCE(tbl."6_31_cdigo_familia", '') ELSE tbl."5_3_cdigo_familia" END
                                   ) as total 
                            FROM tramites_aps_2026 tbl
                            WHERE {w_tramites} AND {self.get_date_filter(f'tbl.{tipo_fecha}')}
                            """
        tr_fam_res = self.ejecutar(tr_familias_query, params)

        texto_duplicados = "\n".join(
            duplicados_list) if duplicados_list else "✅ No se detectaron trámites duplicados para este usuario."

        res_obs_tramites = self.ejecutar(f"""
                                    SELECT tbl.title, tbl."150_describe_aqu_el_" as obs
                                    FROM tramites_aps_2026 tbl
                                    WHERE {w_tramites} AND {self.get_date_filter(f'tbl.{tipo_fecha}')}
                                    """, params)

        texto_obs_tramites = ""
        for idx, r in enumerate(res_obs_tramites, 1):
            titulo = str(r.get("title", "Sin Título"))
            obs = str(r.get("obs", "")).replace('\n', ' ')
            if not obs or obs == 'None': obs = "Sin observaciones registradas."
            texto_obs_tramites += f"{idx}. Ficha {titulo}: {obs}\n\n"

        data["tramites"] = {
            "total": a_tr_tot, "resolutivos": a_tr_res, "con_error": a_tr_err, "por_tipo": por_tipo_aud,
            "total_registros": tr_registros, "total_familias": tr_fam_res[0]["total"] if tr_fam_res else 0,
            "duplicados": duplicados_count,
            "reporte_realizados": texto_realizados if texto_realizados else "No hay trámites realizados en estas fechas.",
            "reporte_resueltos": texto_resueltos if texto_resueltos else "No hay trámites resueltos en estas fechas.",
            "reporte_errores": texto_errores_tr if texto_errores_tr else "✅ Excelente. No hay trámites con errores.",
            "reporte_duplicados": texto_duplicados,
            "reporte_observaciones": texto_obs_tramites.strip() if texto_obs_tramites else "No hay observaciones de trámites en estas fechas."
        }

        # Integración de la vista global consolidada clasificada por módulo
        reporte_consolidado = self.obtener_reporte_inconsistencias_consolidadas()
        data.update(reporte_consolidado)

        # Mapeo garantizado del total de errores globales para el cuadro de texto principal
        data["reporte_errores_texto"] = reporte_consolidado.get("reporte_texto_global_consolidado") or "✅ No se encontraron inconsistencias de auditoría en la base de datos."

        return data

    def obtener_reporte_inconsistencias_consolidadas(self) -> dict:
        """
        Consulta la tabla 'auditoria_errores_2026', agrupa y clasifica TODOS los registros
        de la tabla por la columna 'modulo', proyectando 'auditoria_errores_2026' como tabla origen
        y asignando los íconos visuales (❌ Error vs ⚠️ Advertencia).
        """
        query = """
            SELECT 
                COALESCE(modulo, 'SIN_MODULO') AS modulo,
                id_ficha,
                COALESCE(usuario_creador, 'Desconocido') AS usuario_creador,
                COALESCE(titulo_ficha, 'Sin Título') AS titulo_ficha,
                fecha_creacion,
                COALESCE(cantidad_errores, 0) AS cantidad_errores,
                COALESCE(detalle_inconsistencias, '') AS detalle_inconsistencias,
                'auditoria_errores_2026' AS tabla_origen
            FROM auditoria_errores_2026
            ORDER BY modulo ASC, fecha_creacion DESC;
        """

        modulos_agrupados = {}
        reporte_texto_por_modulo = {}
        total_registros = 0
        total_errores = 0
        total_advertencias = 0

        try:
            rows = self.ejecutar(query, {})
            for row in rows:
                total_registros += 1

                mod = str(row['modulo']).strip().upper()
                id_ficha = row['id_ficha']
                usuario = row['usuario_creador']
                titulo = row['titulo_ficha']
                fecha = row['fecha_creacion'].strftime('%Y-%m-%d %H:%M:%S') if row.get('fecha_creacion') else 'N/A'
                cant_errores = row['cantidad_errores']
                detalle = row['detalle_inconsistencias']
                tabla = row['tabla_origen']

                # Clasificación de severidad basada en contenido y contador
                detalle_upper = str(detalle).upper()
                if any(k in detalle_upper for k in ['ADVERTENCIA', 'WARNING', 'ADV']) or cant_errores == 0:
                    icono = "⚠️"
                    tipo_normalizado = "ADVERTENCIA"
                    total_advertencias += 1
                else:
                    icono = "❌"
                    tipo_normalizado = "ERROR"
                    total_errores += 1

                registro_dict = {
                    "icono": icono,
                    "modulo": mod,
                    "id_ficha": id_ficha,
                    "usuario_creador": usuario,
                    "titulo_ficha": titulo,
                    "fecha_creacion": fecha,
                    "cantidad_errores": cant_errores,
                    "detalle_inconsistencias": detalle,
                    "tabla_origen": tabla,
                    "tipo_error": tipo_normalizado
                }

                if mod not in modulos_agrupados:
                    modulos_agrupados[mod] = []
                modulos_agrupados[mod].append(registro_dict)

            for mod, lista_errores in modulos_agrupados.items():
                lineas_texto = [f"=== MÓDULO: {mod} ({len(lista_errores)} registros) ==="]
                for idx, err in enumerate(lista_errores, 1):
                    lineas_texto.append(
                        f"[{idx}] {err['icono']} [{err['tipo_error']}] | Tabla: {err['tabla_origen']} | "
                        f"Ficha ID: {err['id_ficha']} | Título: {err['titulo_ficha']} | "
                        f"Usuario: {err['usuario_creador']} | Fecha: {err['fecha_creacion']} | "
                        f"Cant. Errores: {err['cantidad_errores']}\n"
                        f"    Detalle: {err['detalle_inconsistencias']}\n"
                    )
                reporte_texto_por_modulo[mod] = "\n".join(lineas_texto)

            reporte_global_str = "\n\n".join(reporte_texto_por_modulo.values())

            return {
                "modulos_consolidados": modulos_agrupados,
                "reporte_texto_por_modulo_consolidado": reporte_texto_por_modulo,
                "reporte_texto_global_consolidado": reporte_global_str if reporte_global_str else "✅ No se registraron inconsistencias en la tabla.",
                "resumen_consolidado": {
                    "total_registros": total_registros,
                    "total_errores": total_errores,
                    "total_advertencias": total_advertencias,
                    "total_modulos": len(modulos_agrupados)
                }
            }
        except Exception as e:
            logger.error(f"Error al obtener consolidado desde auditoria_errores_2026: {str(e)}", exc_info=True)
            return {
                "modulos_consolidados": {},
                "reporte_texto_por_modulo_consolidado": {},
                "reporte_texto_global_consolidado": "Ocurrió un error al cargar la información consolidada de auditoría.",
                "resumen_consolidado": {"total_registros": 0, "total_errores": 0, "total_advertencias": 0, "total_modulos": 0}
            }
