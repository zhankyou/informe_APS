let todosLosCorreos = [];
let todosLosNombres = [];
const inputUser = document.getElementById('inputUser');
const dropdown  = document.getElementById('customDropdown');
const inputName = document.getElementById('inputName');
const dropdownName = document.getElementById('customDropdownName');

async function cargarFiltros() {
  const token = localStorage.getItem('informes_token');
  try {
    const resp1 = await fetch(`${API_BASE}/api/encuestadores`, { headers:{ 'Authorization':'Bearer '+token } });
    if (resp1.ok) { todosLosCorreos = await resp1.json(); }

    const resp2 = await fetch(`${API_BASE}/api/nombres_profesionales`, { headers:{ 'Authorization':'Bearer '+token } });
    if (resp2.ok) { todosLosNombres = await resp2.json(); }
  } catch(e) {}
}

function filtrar(query, list, dp, inpt) {
  dp.innerHTML = '';
  if (!list.length) return;
  const filtrados = list.filter(x => x.toLowerCase().includes(query.toLowerCase()));
  if (filtrados.length === 0) { dp.style.display = 'none'; return; }
  filtrados.forEach(item => {
    const div = document.createElement('div');
    div.className = 'custom-dropdown-item'; div.textContent = item;
    div.onmousedown = () => { inpt.value = item; dp.style.display = 'none'; };
    dp.appendChild(div);
  });
  dp.style.display = 'block';
}

if(inputUser) {
    inputUser.addEventListener('input', () => { inputName.value=''; filtrar(inputUser.value, todosLosCorreos, dropdown, inputUser); });
    inputUser.addEventListener('focus', () => filtrar(inputUser.value, todosLosCorreos, dropdown, inputUser));
}

if(inputName) {
    inputName.addEventListener('input', () => { inputUser.value=''; filtrar(inputName.value, todosLosNombres, dropdownName, inputName); });
    inputName.addEventListener('focus', () => filtrar(inputName.value, todosLosNombres, dropdownName, inputName));
}

document.addEventListener('click', (e) => {
  if (e.target !== inputUser && e.target !== dropdown && dropdown) dropdown.style.display = 'none';
  if (e.target !== inputName && e.target !== dropdownName && dropdownName) dropdownName.style.display = 'none';
});

cargarFiltros();