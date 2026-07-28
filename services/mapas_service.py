# services/mapas_service.py
from database.db_core import BaseService
import logging

logger = logging.getLogger("MapasService")

class MapasService(BaseService):

    def obtener_coordenadas(self, correo: str, nombre: str, fecha_ini: str, fecha_fin: str) -> dict:
        f_ini = fecha_ini or "2000-01-01"
        f_fin = fecha_fin or "2099-12-31"

        email_res = correo if correo else self.resolver_correo(nombre)
        params = {"correo": correo, "nombre": nombre, "email_res": email_res, "f_ini": f_ini, "f_fin": f_fin}

        if correo:
            w_desist = "LOWER(TRIM(CAST(tbl.created_by AS text))) = LOWER(:correo)"
            w_pcc_prin = "LOWER(TRIM(CAST(tbl.created_by AS text))) = LOWER(:correo)"
            w_caract_fam = "LOWER(TRIM(CAST(tbl.created_by AS text))) = LOWER(:correo)"
            w_pcf_prin = "LOWER(TRIM(CAST(tbl.created_by AS text))) = LOWER(:correo)"
            w_tramites = "LOWER(TRIM(CAST(tbl.created_by AS text))) = LOWER(:correo)"
        else:
            w_desist = "LOWER(TRIM(CAST(tbl.\"13_10_nombre_profesi\" AS text))) = LOWER(:nombre)"
            w_pcc_prin = "LOWER(TRIM(CAST(tbl.\"4_4_nombre_del_profe\" AS text))) = LOWER(:nombre)"
            w_caract_fam = "LOWER(TRIM(CAST(tbl.\"32_20_responsable_de\" AS text))) = LOWER(:nombre)"
            w_pcf_prin = "LOWER(TRIM(CAST(tbl.\"5_4_nombre_del_profe\" AS text))) = LOWER(:nombre)"
            w_tramites = "LOWER(TRIM(CAST(tbl.\"10_7_nombre_profesio\" AS text))) = LOWER(:nombre)"

        LAT_MIN, LAT_MAX = 3.80, 4.40
        LNG_MIN, LNG_MAX = -74.00, -73.30

        mapas_config = [
            {"key": "desistimientos", "table": "desistimiento_aps_2026", "lat": "lat_2_2_geolocalizacin", "lng": "long_2_2_geolocalizacin", "where": w_desist},
            {"key": "pcc", "table": "pcc_principal_2026", "lat": "lat_1_1_geolocalizacin", "lng": "long_1_1_geolocalizacin", "where": w_pcc_prin},
            {"key": "caracterizacion", "table": "caracterizacion_si_aps_familiar_2026", "lat": "lat_15_8_geo_punto_georr", "lng": "long_15_8_geo_punto_georr", "where": w_caract_fam},
            {"key": "pcf", "table": "pcf_planes_principal_2026", "lat": "lat_1_1_geolocalizacin", "lng": "long_1_1_geolocalizacin", "where": w_pcf_prin},
            {"key": "tramites", "table": "tramites_aps_2026", "lat": "lat_2_1_georreferenciaci", "lng": "long_2_1_georreferenciaci", "where": w_tramites}
        ]

        respuesta = {}
        for cfg in mapas_config:
            try:
                where_clause = cfg['where']
                query = f"SELECT tbl.* FROM {cfg['table']} tbl WHERE {where_clause} AND {self.get_date_filter('tbl.created_at')}"
                rows = self.ejecutar(query, params)
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

                respuesta[cfg['key']] = {
                    "correctos": correctos, "errores_vacios": errores_vacios, "errores_fuera": errores_fuera,
                    "totales": {"ok": len(correctos), "vacios": len(errores_vacios), "fuera": len(errores_fuera)}
                }
            except:
                respuesta[cfg['key']] = {"correctos": [], "errores_vacios": [], "errores_fuera": [], "totales": {"ok": 0, "vacios": 0, "fuera": 0}}

        query_perfil = f"SELECT \"5_4_nombre_del_profe\" as nombre, \"4_3_perfil_profesion\" as perfil, COUNT(*) as qty FROM pcf_planes_principal_2026 tbl WHERE {w_pcf_prin} AND {self.get_date_filter('tbl.created_at')} AND tbl.\"5_4_nombre_del_profe\" IS NOT NULL GROUP BY 1, 2 ORDER BY qty DESC LIMIT 1"
        res_perfil = self.ejecutar(query_perfil, params)
        if res_perfil:
            respuesta["encuestador_nombre"] = res_perfil[0]["nombre"]
            respuesta["encuestador_perfil"] = res_perfil[0]["perfil"]
        else:
            respuesta["encuestador_nombre"] = "Sin registro de nombre"
            respuesta["encuestador_perfil"] = "Sin registro de perfil"

        return respuesta