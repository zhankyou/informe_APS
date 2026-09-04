from flask import Blueprint, render_template

web_bp = Blueprint('web', __name__)

@web_bp.route("/")
@web_bp.route("/login")
def login_page(): return render_template("login.html")

@web_bp.route("/dashboard")
def dashboard_page(): return render_template("dashboard.html")

@web_bp.route("/auditoria")
def auditoria_page(): return render_template("auditoria.html")

@web_bp.route("/auditoria_especialistas")
def auditoria_especialistas_page(): return render_template("auditoria_especialistas.html")

@web_bp.route("/auditoria_actualizacion")
def auditoria_actualizacion_page(): return render_template("auditoria_actualizacion.html")

@web_bp.route("/sihos")
def sihos_page(): return render_template("sihos.html")

@web_bp.route("/mapas")
def mapas_page(): return render_template("mapas.html")

@web_bp.route("/informes")
def informes_page(): return render_template("informes.html")
