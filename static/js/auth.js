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

// ── FUNCIONES UTILITARIAS GLOBALES (Formateo y Renderizado) ──

function fmt(n) {
    if (n === null || n === undefined || isNaN(n)) return '0';
    return Number(n).toLocaleString('es-CO');
}

function setVal(id, v) {
    const el = document.getElementById(id);
    if(el) {
        el.textContent = fmt(v);
        el.classList.remove('loading');
    }
}

function renderList(cid, arr) {
    const c = document.getElementById(cid);
    if (!c) return;
    c.innerHTML = '';
    if (!arr || !arr.length) {
        c.innerHTML = '<div style="font-size:.8rem;color:var(--muted);">Sin registros</div>';
        return;
    }
    arr.forEach(i => {
        c.innerHTML += `<div class="list-row"><span style="color:var(--muted);">${i.label}</span><span style="font-weight:bold;color:var(--navy);">${i.total}</span></div>`;
    });
}

function copiarTexto(id) {
    const el = document.getElementById(id);
    if(el) {
        navigator.clipboard.writeText(el.value)
          .then(() => alert('¡Texto copiado al portapapeles!'))
          .catch(err => alert('Error al copiar: ' + err));
    }
}

// Ejecutar inicialización de seguridad al cargar la página
document.addEventListener('DOMContentLoaded', initAuth);