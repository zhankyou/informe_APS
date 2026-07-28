// static/js/utils.js
const API_BASE = window.location.protocol === 'file:' ? 'http://127.0.0.1:5001' : window.location.origin;

function initAuth() {
    const token = localStorage.getItem('informes_token');
    if (!token && !window.location.pathname.includes('login')) {
        window.location.href = '/login';
    }

    const userInfo = JSON.parse(localStorage.getItem('informes_user') || '{}');
    const nameEl = document.getElementById('sidebarNombre');
    const roleEl = document.getElementById('sidebarRol');
    if(nameEl) nameEl.textContent = userInfo.nombre || '—';
    if(roleEl) roleEl.textContent = userInfo.rol || '—';
}

async function logout() {
    const token = localStorage.getItem('informes_token');
    try {
        await fetch(`${API_BASE}/api/logout`, { method:'POST', headers:{'Authorization':'Bearer '+token} });
    } catch(e){}
    localStorage.removeItem('informes_token');
    localStorage.removeItem('informes_user');
    window.location.href = '/login';
}

function fmt(n) { return Number(n||0).toLocaleString('es-CO'); }

function setVal(id, v) {
    const el = document.getElementById(id);
    if(el) { el.textContent = fmt(v); el.classList.remove('loading'); }
}

function copiarTexto(id) {
    navigator.clipboard.writeText(document.getElementById(id).value)
      .then(() => alert('¡Reporte copiado con éxito!'))
      .catch(err => alert('Error al copiar: ' + err));
}

// Ejecutar al cargar la página
document.addEventListener('DOMContentLoaded', initAuth);