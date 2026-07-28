import logging
from sqlalchemy import create_engine, text
from config import Config

logger = logging.getLogger("DB_CORE")

# 🚀 Engine optimizado para la nube (Aiven)
engine = create_engine(
    Config.SQLALCHEMY_DATABASE_URI,
    pool_pre_ping=True,       # Verifica si la conexión está viva antes de ejecutar SQL
    pool_size=5,              # Conexiones simultáneas permitidas
    max_overflow=10,          # Conexiones de desbordamiento en picos de usuarios
    pool_recycle=300,         # Fundamental para la Nube: Cierra conexiones huérfanas a los 5 mins
    connect_args={'connect_timeout': 10} # Evita bloqueos por resolución DNS lenta
)

class BaseService:
    def __init__(self):
        self.engine = engine

    def ejecutar(self, query_str: str, params: dict = None) -> list:
        try:
            with self.engine.connect() as conn:
                res = conn.execute(text(query_str), params or {})
                return [dict(row) for row in res.mappings()]
        except Exception as e:
            logger.error(f"❌ Error SQL: {e}")
            return []

    def safe_count(self, query_str: str, params: dict = None) -> int:
        rows = self.ejecutar(query_str, params)
        if rows:
            try:
                return int(list(rows[0].values())[0] or 0)
            except:
                return 0
        return 0

    def safe_group(self, query_str: str, params: dict = None) -> list:
        rows = self.ejecutar(query_str, params)
        result = []
        for row in rows:
            vals = list(row.values())
            if len(vals) >= 2:
                result.append({"label": str(vals[0] or "Sin dato"), "total": int(vals[1] or 0)})
        return result

    def resolver_correo(self, nombre: str) -> str:
        if not nombre: return ""
        tablas = [
            ('pcf_planes_principal_2026', '5_4_nombre_del_profe'),
            ('pcc_principal_2026', '4_4_nombre_del_profe'),
            ('tramites_aps_2026', '10_7_nombre_profesio'),
            ('desistimiento_aps_2026', '13_10_nombre_profesi'),
            ('caracterizacion_si_aps_familiar_2026', '32_20_responsable_de')
        ]
        for tbl, col in tablas:
            res = self.ejecutar(f'SELECT created_by FROM {tbl} WHERE LOWER(TRIM("{col}")) = LOWER(:nom) AND created_by IS NOT NULL AND TRIM(created_by) != \'\' LIMIT 1', {"nom": nombre})
            if res: return res[0]["created_by"]
        return ""

    def get_date_filter(self, col_name: str) -> str:
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

    def get_date_filter_ant(self, col_name: str) -> str:
        return f"""
        (CASE 
            WHEN CAST({col_name} AS text) ~ '^[0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}}' THEN to_date(LEFT(CAST({col_name} AS text), 10), 'YYYY-MM-DD') 
            WHEN CAST({col_name} AS text) ~ '^[0-9]{{2}}/[0-9]{{2}}/[0-9]{{4}}' THEN to_date(LEFT(CAST({col_name} AS text), 10), 'DD/MM/YYYY') 
            ELSE '2100-01-01'::date 
        END) < to_date(:f_ini, 'YYYY-MM-DD')
        """