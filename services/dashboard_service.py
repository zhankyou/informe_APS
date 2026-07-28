# -*- coding: utf-8 -*-
import re
from collections import Counter
import logging
from database.db_core import BaseService

logger = logging.getLogger("DashboardService")


class DashboardService(BaseService):

    def obtener_datos(self, f_ini: str, f_fin: str) -> dict:
        f_ini = f_ini or "2000-01-01"
        f_fin = f_fin or "2099-12-31"
        params = {"f_ini": f_ini, "f_fin": f_fin}

        def q(table, extra_where=""):
            base = f"SELECT COUNT(*) FROM {table} WHERE {self.get_date_filter('created_at')}"
            if extra_where: base += f" AND {extra_where}"
            return self.safe_count(base, params)

        data = {}

        # DESISTIMIENTOS
        data["desistimientos"] = {
            "total": q("desistimiento_aps_2026"),
            "con_error": self.safe_count(
                f"SELECT COUNT(*) FROM auditoria_errores_2026 WHERE modulo = 'DESISTIMIENTOS' AND {self.get_date_filter('fecha_creacion')}",
                params),
        }

        # PCC
        query_pcc_int = f"""
            SELECT COUNT(*) FROM pcc_integrantes_2026 b
            JOIN pcc_principal_2026 p ON b.ec5_branch_owner_uuid = p.ec5_uuid
            WHERE {self.get_date_filter('p.created_at')}
        """
        data["pcc"] = {
            "planes": q("pcc_principal_2026"),
            "integrantes": self.safe_count(query_pcc_int, params),
            "con_error": self.safe_count(
                f"SELECT COUNT(*) FROM auditoria_errores_2026 WHERE modulo LIKE 'PCC%' AND {self.get_date_filter('fecha_creacion')}",
                params),
        }

        # CARACTERIZACIÓN EDADES
        query_edades = f"""
                       WITH fechas_limpias AS (
                            SELECT CASE 
                                       WHEN CAST(created_at AS text) ~ '^[0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}}' THEN to_date(LEFT(CAST(created_at AS text), 10), 'YYYY-MM-DD') 
                                       WHEN CAST(created_at AS text) ~ '^[0-9]{{2}}/[0-9]{{2}}/[0-9]{{4}}' THEN to_date(LEFT(CAST(created_at AS text), 10), 'DD/MM/YYYY') 
                                       ELSE NULL END as f_crea,
                                   TRIM(CAST("107_7_fecha_de_nacim" AS text)) as f_nac_raw 
                            FROM caracterizacion_si_aps_individual_2026 
                            WHERE "107_7_fecha_de_nacim" IS NOT NULL
                              AND {self.get_date_filter('created_at')}
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
        res_edades = self.ejecutar(query_edades, params)
        menores_5 = res_edades[0]["menores"] if res_edades else 0
        adultos_60 = res_edades[0]["mayores"] if res_edades else 0

        # ETNIA
        etnia_comp = self.ejecutar(f"""
                              SELECT COUNT(*) FILTER (WHERE "116_16_pertenencia_t" = '7. Ninguna' OR "116_16_pertenencia_t" IS NULL) AS sin_etnia, 
                                     COUNT(*) FILTER (WHERE "116_16_pertenencia_t" IS NOT NULL AND "116_16_pertenencia_t" != '7. Ninguna') AS con_etnia, 
                                     COUNT(*) AS total
                              FROM caracterizacion_si_aps_individual_2026
                              WHERE {self.get_date_filter('created_at')}
                              """, params)
        etnia_data = etnia_comp[0] if etnia_comp else {"sin_etnia": 0, "con_etnia": 0, "total": 0}
        total_etnia = int(etnia_data.get("total") or 1)

        # DISCAPACIDAD
        query_disc = f"""
                     SELECT "119_19_reconoce_algu" as disc
                     FROM caracterizacion_si_aps_individual_2026
                     WHERE "119_19_reconoce_algu" IS NOT NULL
                       AND {self.get_date_filter('created_at')}
                     """
        res_disc = self.ejecutar(query_disc, params)
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
        disc_chart = [{"label": k, "total": v} for k, v in
                      sorted(conteo_disc.items(), key=lambda x: x[1], reverse=True)]

        # FAMILIAS CARACT
        raw_fam_dash = self.ejecutar(f"""
            SELECT title, "1_1_consentimiento_i", created_by, "12_4_territorio", "13_5_microterritorio", "18_10_cdigo_hogar", "19_101_cdigo_hogar", "21_11_cdigo_familia", "22_111_cdigo_familia"
            FROM caracterizacion_si_aps_familiar_2026
            WHERE {self.get_date_filter('created_at')}
        """, params)

        seen_t_dash, seen_c_dash = set(), set()
        uniq_fam_dash, dups_fam_count_dash = 0, 0

        for r in raw_fam_dash:
            consent = str(r.get("1_1_consentimiento_i", "")).strip().upper()
            if consent != '1. SI': continue
            t = str(r.get("title", "")).strip().lower()
            t_key = t if t and t != "none" else None
            c_key = f"{r.get('created_by', '')}|{r.get('12_4_territorio', '')}|{r.get('13_5_microterritorio', '')}|{r.get('18_10_cdigo_hogar', '')}|{r.get('19_101_cdigo_hogar', '')}|{r.get('21_11_cdigo_familia', '')}|{r.get('22_111_cdigo_familia', '')}".lower().strip()
            is_dup = False
            if t_key and t_key in seen_t_dash: is_dup = True
            if c_key != "||||||" and c_key.replace("none", "").replace("|", "") != "":
                if c_key in seen_c_dash: is_dup = True
            if is_dup:
                dups_fam_count_dash += 1
            else:
                if t_key: seen_t_dash.add(t_key)
                if c_key != "||||||" and c_key.replace("none", "").replace("|", "") != "": seen_c_dash.add(c_key)
                uniq_fam_dash += 1

        # INDIVIDUOS CARACT
        raw_ind_dash = self.ejecutar(
            f"SELECT title FROM caracterizacion_si_aps_individual_2026 WHERE {self.get_date_filter('created_at')}",
            params)
        seen_t_ind_dash = set()
        uniq_ind_dash, dups_ind_count_dash = 0, 0
        for r in raw_ind_dash:
            t = str(r.get("title", "")).strip().lower()
            t_key = t if t and t != "none" else None
            if t_key and t_key in seen_t_ind_dash:
                dups_ind_count_dash += 1
            else:
                if t_key: seen_t_ind_dash.add(t_key)
                uniq_ind_dash += 1

        data["caracterizacion"] = {
            "familias": uniq_fam_dash,
            "familias_duplicadas": dups_fam_count_dash,
            "individuos": uniq_ind_dash,
            "individuos_duplicadas": dups_ind_count_dash,
            "sin_aseguramiento": self.safe_count(
                f"SELECT COUNT(DISTINCT ec5_branch_owner_uuid) FROM caracterizacion_si_aps_individual_2026 WHERE \"113_13_rgimen_de_afi\" = '5. No afiliado' AND {self.get_date_filter('created_at')}",
                params),
            "gestantes": q("caracterizacion_si_aps_individual_2026", "\"109_9_se_encuentra_e\" = '1. SI'"),
            "menores_5": menores_5, "adultos_60": adultos_60,
            "victimas_conflicto": q("caracterizacion_si_aps_familiar_2026", "\"78_52_familia_vctima\" = '1. SI'"),
            "poblacion_etnica": q("caracterizacion_si_aps_individual_2026",
                                  "\"116_16_pertenencia_t\" IS NOT NULL AND \"116_16_pertenencia_t\" != '7. Ninguna'"),
            "discapacidad_total": total_discapacidad, "discapacidades_chart": disc_chart,
            "tipo_familia": self.safe_group(
                f"SELECT \"64_41_tipo_de_famili\", COUNT(*) as total FROM caracterizacion_si_aps_familiar_2026 WHERE \"64_41_tipo_de_famili\" IS NOT NULL AND {self.get_date_filter('created_at')} GROUP BY 1 ORDER BY 2 DESC",
                params),
            "estrato": self.safe_group(
                f"SELECT \"23_12_estrato_socioe\", COUNT(*) as total FROM caracterizacion_si_aps_familiar_2026 WHERE \"23_12_estrato_socioe\" IS NOT NULL AND {self.get_date_filter('created_at')} GROUP BY 1 ORDER BY 1",
                params),
            "nivel_educativo": self.safe_group(
                f"SELECT \"112_12_nivel_educati\", COUNT(*) as total FROM caracterizacion_si_aps_individual_2026 WHERE \"112_12_nivel_educati\" IS NOT NULL AND {self.get_date_filter('created_at')} GROUP BY 1 ORDER BY 2 DESC",
                params),
            "etnia_sin_pct": round(int(etnia_data.get("sin_etnia") or 0) / total_etnia * 100,
                                   1) if total_etnia > 0 else 0,
            "etnia_con_pct": round(int(etnia_data.get("con_etnia") or 0) / total_etnia * 100,
                                   1) if total_etnia > 0 else 0,
            "etnia_con_total": int(etnia_data.get("con_etnia") or 0),
            "error_familiar": self.safe_count(
                f"SELECT COUNT(*) FROM auditoria_errores_2026 WHERE modulo = 'CARACT_FAMILIAR' AND {self.get_date_filter('fecha_creacion')}",
                params),
            "error_individual": self.safe_count(
                f"SELECT COUNT(*) FROM auditoria_errores_2026 WHERE modulo = 'CARACT_INDIVIDUAL' AND {self.get_date_filter('fecha_creacion')}",
                params),
        }

        # HOGARES TERRITORIO
        raw_caract_hogares = self.ejecutar(f"""
            SELECT "12_4_territorio", "13_5_microterritorio", "18_10_cdigo_hogar", "19_101_cdigo_hogar", "21_11_cdigo_familia", "22_111_cdigo_familia"
            FROM caracterizacion_si_aps_familiar_2026
            WHERE {self.get_date_filter('created_at')}
        """, params)

        hogares_caract_dict = {}
        for r in raw_caract_hogares:
            t = str(r.get("12_4_territorio", "")).strip().upper()
            m = str(r.get("13_5_microterritorio", "")).strip().upper()
            c1 = str(r.get("18_10_cdigo_hogar", "")).strip().lower()
            c2 = str(r.get("19_101_cdigo_hogar", "")).strip().lower()
            c3 = str(r.get("21_11_cdigo_familia", "")).strip().lower()
            c4 = str(r.get("22_111_cdigo_familia", "")).strip().lower()

            id_hogar = f"{t}|{m}|{c1}|{c2}|{c3}|{c4}".replace("none", "").strip()
            if id_hogar != "|||||" and len(id_hogar.replace("|", "")) > 0:
                if not t or t == "NONE": t = "SIN TERRITORIO"
                if not m or m == "NONE": m = "SIN MICROTERRITORIO"
                hogares_caract_dict[id_hogar] = {"terr": t, "micro": m}

        raw_pcf_hogares = self.ejecutar(f"""
            SELECT "9_7_territorio", "10_8_microterritorio", "11_9_identificacin_d", "12_91_identificacin_", "13_10_identificacin_", "14_101_identificacin"
            FROM pcf_planes_principal_2026
            WHERE {self.get_date_filter('created_at')}
        """, params)

        hogares_pcf_dict = {}
        for r in raw_pcf_hogares:
            t = str(r.get("9_7_territorio", "")).strip().upper()
            m = str(r.get("10_8_microterritorio", "")).strip().upper()
            c1 = str(r.get("11_9_identificacin_d", "")).strip().lower()
            c2 = str(r.get("12_91_identificacin_", "")).strip().lower()
            c3 = str(r.get("13_10_identificacin_", "")).strip().lower()
            c4 = str(r.get("14_101_identificacin", "")).strip().lower()

            id_hogar = f"{t}|{m}|{c1}|{c2}|{c3}|{c4}".replace("none", "").strip()
            if id_hogar != "|||||" and len(id_hogar.replace("|", "")) > 0:
                if not t or t == "NONE": t = "SIN TERRITORIO"
                if not m or m == "NONE": m = "SIN MICROTERRITORIO"
                hogares_pcf_dict[id_hogar] = {"terr": t, "micro": m}

        set_caract = set(hogares_caract_dict.keys())
        set_pcf = set(hogares_pcf_dict.keys())
        concertados = set_caract.intersection(set_pcf)

        agrupacion_terr = {}
        for id_h, info in hogares_caract_dict.items():
            llave = f"{info['terr']} / {info['micro']}"
            if llave not in agrupacion_terr: agrupacion_terr[llave] = {"caract": 0, "pcf": 0, "concertados": 0}
            agrupacion_terr[llave]["caract"] += 1
            if id_h in concertados:
                agrupacion_terr[llave]["concertados"] += 1

        for id_h, info in hogares_pcf_dict.items():
            llave = f"{info['terr']} / {info['micro']}"
            if llave not in agrupacion_terr: agrupacion_terr[llave] = {"caract": 0, "pcf": 0, "concertados": 0}
            agrupacion_terr[llave]["pcf"] += 1

        lista_territorios = []
        for k, v in agrupacion_terr.items():
            pct = round((v["concertados"] / v["caract"] * 100), 1) if v["caract"] > 0 else (
                100.0 if v["concertados"] > 0 else 0.0)
            lista_territorios.append({
                "label": k,
                "caract": v["caract"],
                "pcf": v["pcf"],
                "concertados": v["concertados"],
                "porcentaje": pct
            })

        lista_territorios.sort(key=lambda x: x["caract"] + x["pcf"], reverse=True)

        data["hogares_territorio"] = {
            "total_caract": len(set_caract),
            "total_pcf": len(set_pcf),
            "total_concertados": len(concertados),
            "desglose": lista_territorios
        }

        # PCF General
        raw_pcf_dash = self.ejecutar(
            f"SELECT created_by, \"9_7_territorio\", \"10_8_microterritorio\", \"11_9_identificacin_d\", \"12_91_identificacin_\", \"13_10_identificacin_\", \"14_101_identificacin\" FROM pcf_planes_principal_2026 WHERE {self.get_date_filter('created_at')} AND (\"4_3_perfil_profesion\" IS NULL OR TRIM(\"4_3_perfil_profesion\") != 'Profesional Psicología')",
            params)
        seen_c_pcf_dash = set()
        uniq_pcf_dash, dups_pcf_count_dash = 0, 0
        for r in raw_pcf_dash:
            c_key = f"{r.get('created_by', '')}|{r.get('9_7_territorio', '')}|{r.get('10_8_microterritorio', '')}|{r.get('11_9_identificacin_d', '')}|{r.get('12_91_identificacin_', '')}|{r.get('13_10_identificacin_', '')}|{r.get('14_101_identificacin', '')}".lower().strip()
            if c_key == "||||||" or c_key.replace("none", "").replace("|", "") == "": uniq_pcf_dash += 1; continue
            if c_key in seen_c_pcf_dash:
                dups_pcf_count_dash += 1
            else:
                seen_c_pcf_dash.add(c_key);
                uniq_pcf_dash += 1

        raw_pcf_ind_dash = self.ejecutar(
            f"SELECT b.title, p.created_by FROM pcf_planes_integrantes_2026 b JOIN pcf_planes_principal_2026 p ON b.ec5_branch_owner_uuid = p.ec5_uuid WHERE {self.get_date_filter('p.created_at')} AND (p.\"4_3_perfil_profesion\" IS NULL OR TRIM(p.\"4_3_perfil_profesion\") != 'Profesional Psicología')",
            params)
        seen_ind_pcf_dash = set()
        uniq_ind_pcf_dash, dups_ind_pcf_count_dash = 0, 0
        for r in raw_pcf_ind_dash:
            t = str(r.get("title", "")).strip().lower()
            c = str(r.get("created_by", "")).strip().lower()
            if not t or t == "none": uniq_ind_pcf_dash += 1; continue
            clave = f"{c}|{t}"
            if clave in seen_ind_pcf_dash:
                dups_ind_pcf_count_dash += 1
            else:
                seen_ind_pcf_dash.add(clave);
                uniq_ind_pcf_dash += 1

        data["pcf"] = {"familias_intervenidas": uniq_pcf_dash, "familias_duplicadas": dups_pcf_count_dash,
                       "integrantes_intervenidos": uniq_ind_pcf_dash, "integrantes_duplicados": dups_ind_pcf_count_dash}

        # Psicología
        raw_psico_fam_dash = self.ejecutar(
            f"SELECT created_by, \"9_7_territorio\", \"10_8_microterritorio\", \"11_9_identificacin_d\", \"12_91_identificacin_\", \"13_10_identificacin_\", \"14_101_identificacin\" FROM pcf_planes_principal_2026 WHERE {self.get_date_filter('created_at')} AND TRIM(\"4_3_perfil_profesion\") = 'Profesional Psicología'",
            params)
        seen_c_psico_dash = set()
        uniq_psico_fam_dash, dups_psico_fam_count_dash = 0, 0
        for r in raw_psico_fam_dash:
            c_key = f"{r.get('created_by', '')}|{r.get('9_7_territorio', '')}|{r.get('10_8_microterritorio', '')}|{r.get('11_9_identificacin_d', '')}|{r.get('12_91_identificacin_', '')}|{r.get('13_10_identificacin_', '')}|{r.get('14_101_identificacin', '')}".lower().strip()
            if c_key == "||||||" or c_key.replace("none", "").replace("|", "") == "": uniq_psico_fam_dash += 1; continue
            if c_key in seen_c_psico_dash:
                dups_psico_fam_count_dash += 1
            else:
                seen_c_psico_dash.add(c_key);
                uniq_psico_fam_dash += 1

        data["pcf_psicologia"] = {
            "intervenciones_familiares": uniq_psico_fam_dash, "familias_duplicadas": dups_psico_fam_count_dash,
            "integrantes": q("pcf_psicologia_principal_2026"), "seguimientos": q("pcf_psicologia_seguimientos_2026"),
        }

        # Trámites
        res_tramites_textos = self.ejecutar(
            f"SELECT nombres_realizados, nombres_efectivos FROM tramites_consolidados_2026 WHERE (nombres_realizados IS NOT NULL OR nombres_efectivos IS NOT NULL) AND {self.get_date_filter('fecha')}",
            params)

        conteo_realizados, conteo_efectivos = Counter(), Counter()
        invalid_words = ['none', 'null', 'ningún', 'ningun', 'no aplica', 'na', 'n/a', '']

        for row in res_tramites_textos:
            nr = str(row.get("nombres_realizados", "")).replace("Ningún", "").strip()
            ne = str(row.get("nombres_efectivos", "")).replace("Ningún", "").strip()
            items_r = [x.strip() for x in re.split(r'[|,]', nr) if x.strip() and x.strip().lower() not in invalid_words]
            items_e = [x.strip() for x in re.split(r'[|,]', ne) if x.strip() and x.strip().lower() not in invalid_words]
            for item in items_r:
                if 'trámite resuelto' in item.lower() or 'tramite resuelto' in item.lower(): continue
                conteo_realizados[item] += 1
                if 'adicional' in item.lower() or 'otro' in item.lower():
                    conteo_efectivos[item] += 1
                    if item in items_e: items_e.remove(item)
            for item in items_e:
                if 'trámite resuelto' in item.lower() or 'tramite resuelto' in item.lower(): continue
                conteo_efectivos[item] += 1

        tr_tot, tr_res = sum(conteo_realizados.values()), sum(conteo_efectivos.values())
        por_tipo_lista = []
        for k in sorted(set(conteo_realizados.keys()).union(set(conteo_efectivos.keys()))):
            v_realizados = conteo_realizados.get(k, 0)
            v_efectivos = conteo_efectivos.get(k, 0)
            if v_efectivos > v_realizados: v_realizados = v_efectivos
            por_tipo_lista.append(
                {"label": k, "total": v_realizados, "resueltos": v_efectivos, "pendientes": v_realizados - v_efectivos,
                 "porcentaje": round((v_efectivos / v_realizados * 100), 1) if v_realizados > 0 else 0})

        tr_raw = self.ejecutar(
            f"SELECT title, created_at FROM tramites_aps_2026 WHERE {self.get_date_filter('created_at')}", params)
        titulos_fechas = {}
        duplicados_count = 0
        for r in tr_raw:
            t = str(r.get("title", "")).strip().lower()
            if not t or t == "none": continue
            f = str(r.get("created_at", ""))[:10]
            clave = f"{t}|{f}"
            if clave in titulos_fechas:
                duplicados_count += 1
            else:
                titulos_fechas[clave] = True

        tr_registros = max(0, q("tramites_aps_2026") - duplicados_count)
        tr_familias_query = f"SELECT COUNT(DISTINCT COALESCE(\"7_4_territorio\", '') || COALESCE(\"8_5_microterritorio\", '') || CASE WHEN \"3_2_cdigo_hogar\" = 'No Aplica' OR \"3_2_cdigo_hogar\" IS NULL THEN COALESCE(\"4_21_cdigo_hogar\", '') ELSE \"3_2_cdigo_hogar\" END || CASE WHEN \"5_3_cdigo_familia\" = 'No Aplica' OR \"5_3_cdigo_familia\" IS NULL THEN COALESCE(\"6_31_cdigo_familia\", '') ELSE \"5_3_cdigo_familia\" END) as total FROM tramites_aps_2026 WHERE {self.get_date_filter('created_at')}"
        tr_fam_res = self.ejecutar(tr_familias_query, params)

        data["tramites"] = {
            "total": tr_tot, "resolutivos": tr_res,
            "con_error": self.safe_count(
                f"SELECT SUM(CAST(errores AS numeric)) as err FROM tramites_consolidados_2026 WHERE {self.get_date_filter('fecha')}",
                params),
            "por_tipo": por_tipo_lista,
            "total_registros": tr_registros, "total_familias": tr_fam_res[0]["total"] if tr_fam_res else 0
        }
        return data