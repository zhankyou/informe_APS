# services/sihos_service.py
import re
from collections import Counter
from database.db_core import BaseService
import logging

logger = logging.getLogger("SihosService")


class SihosService(BaseService):

    def obtener_datos(self, profesional: str, fecha_ini: str, fecha_fin: str) -> dict:
        f_ini = fecha_ini or "2000-01-01"
        f_fin = fecha_fin or "2099-12-31"
        params = {"f_ini": f_ini, "f_fin": f_fin}

        prof_filter_sihos = ""
        prof_filter_aps = ""

        if profesional:
            prof_limpio = profesional.replace('ï¿½', '_').replace('Ñ', '_').replace('ñ', '_')
            prof_parts = [p for p in prof_limpio.split() if p]
            prof_like = '%' + '%'.join(prof_parts) + '%'
            prof_filter_sihos = "AND LOWER(TRIM(profesional)) LIKE LOWER(:prof_like)"
            prof_filter_aps = "AND LOWER(TRIM(\"5_4_nombre_del_profe\")) LIKE LOWER(:prof_like)"
            params["prof_like"] = prof_like

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
            WHERE {self.get_date_filter('fecha_ok')}
        """
        filas_sihos = self.ejecutar(query_sihos, params)
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
                if diag not in diag_data: diag_data[diag] = {"total": 0, "edades": Counter()}
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
        diagnosticos_list = [{"label": d_name, "total": d_info["total"],
                              "grupo_etario": d_info["edades"].most_common(1)[0][0] if d_info[
                                  "edades"] else "Sin Datos"} for d_name, d_info in top_diags]

        query_cruce = f"""
            SELECT COUNT(*) as campo_total
            FROM pcf_planes_integrantes_2026 b
            JOIN pcf_planes_principal_2026 p ON b.ec5_branch_owner_uuid = p.ec5_uuid
            WHERE {self.get_date_filter('p.created_at')} {prof_filter_aps}
        """
        res_cruce = self.ejecutar(query_cruce, params)
        atenciones_campo_aps = res_cruce[0]["campo_total"] if res_cruce else 0

        if total_atenciones == 0 and atenciones_campo_aps == 0 and profesional:
            return {
                "error": f"No se encontraron facturaciones en SIHOS ni reportes en campo para {profesional} en estas fechas."}

        def format_counter(counter_obj):
            return [{"label": k, "total": v} for k, v in sorted(counter_obj.items(), key=lambda x: x[1], reverse=True)]

        return {
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

    def obtener_profesionales(self) -> list:
        rows = self.ejecutar(
            "SELECT DISTINCT profesional FROM sihos WHERE sede = 'APS' AND profesional IS NOT NULL ORDER BY profesional ASC")
        return [r["profesional"] for r in rows if r["profesional"]]
