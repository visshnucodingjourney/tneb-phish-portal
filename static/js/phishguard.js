/* TNEB Phish Awareness Portal — Main JS */

// ── Theme (light / dark) ──────────────────────────────
const THEME_KEY = 'phishguard-theme';

function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  document.querySelectorAll('.theme-toggle i').forEach(icon => {
    icon.className = theme === 'light' ? 'bi bi-moon-stars' : 'bi bi-sun';
  });
}

function toggleTheme() {
  const current = document.documentElement.getAttribute('data-theme') || 'dark';
  const next = current === 'light' ? 'dark' : 'light';
  localStorage.setItem(THEME_KEY, next);
  applyTheme(next);
}

// Apply saved (or system-preferred) theme as soon as possible
(function initTheme() {
  const saved = localStorage.getItem(THEME_KEY);
  const preferred = saved || (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
  applyTheme(preferred);
})();

document.querySelectorAll('.theme-toggle').forEach(btn => {
  btn.addEventListener('click', toggleTheme);
});

// ── Live clock ────────────────────────────────────────
function updateClock() {
  const el = document.getElementById('live-clock');
  if (!el) return;
  const now = new Date();
  el.textContent = now.toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}
setInterval(updateClock, 1000);
updateClock();

// ── Auto-dismiss alerts ───────────────────────────────
document.querySelectorAll('.alert.auto-dismiss').forEach(alert => {
  setTimeout(() => {
    const bsAlert = bootstrap.Alert.getOrCreateInstance(alert);
    bsAlert.close();
  }, 5000);
});


const uploadZone = document.getElementById('upload-zone');
const fileInput  = document.getElementById('csv_file');

if (uploadZone && fileInput) {
  uploadZone.addEventListener('click', () => fileInput.click());
  uploadZone.addEventListener('dragover', e => { e.preventDefault(); uploadZone.classList.add('dragover'); });
  uploadZone.addEventListener('dragleave', () => uploadZone.classList.remove('dragover'));
  uploadZone.addEventListener('drop', e => {
    e.preventDefault();
    uploadZone.classList.remove('dragover');
    const file = e.dataTransfer.files[0];
    if (file && file.name.endsWith('.csv')) {
      const dt = new DataTransfer();
      dt.items.add(file);
      fileInput.files = dt.files;
      updateFileLabel(file.name);
    } else {
      showToast('Only CSV files are allowed.', 'danger');
    }
  });

  fileInput.addEventListener('change', () => {
    if (fileInput.files.length) updateFileLabel(fileInput.files[0].name);
  });

  function updateFileLabel(name) {
    const label = document.getElementById('upload-file-label');
    if (label) label.textContent = name;
    const icon = uploadZone.querySelector('i');
    if (icon) { icon.className = 'bi bi-file-earmark-check text-accent'; }
  }
}


document.querySelectorAll('[data-confirm]').forEach(btn => {
  btn.addEventListener('click', function(e) {
    if (!confirm(this.dataset.confirm || 'Are you sure?')) e.preventDefault();
  });
});

// ── Toast notifications ───────────────────────────────
function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container') || createToastContainer();
  const id = 'toast-' + Date.now();
  const icons = { success: 'bi-check-circle-fill', danger: 'bi-exclamation-circle-fill', info: 'bi-info-circle-fill', warning: 'bi-exclamation-triangle-fill' };
  const html = `
    <div id="${id}" class="toast align-items-center border-0 mb-2" role="alert" aria-live="assertive">
      <div class="d-flex" style="background:var(--bg-card);border:1px solid var(--border);border-radius:8px;padding:12px 16px;gap:10px;align-items:center;">
        <i class="bi ${icons[type] || icons.info}" style="color:var(--${type === 'danger' ? 'danger' : type === 'success' ? 'success' : 'accent'})"></i>
        <span style="font-size:13.5px">${message}</span>
        <button type="button" class="btn-close ms-auto" data-bs-dismiss="toast"></button>
      </div>
    </div>`;
  container.insertAdjacentHTML('beforeend', html);
  const toastEl = document.getElementById(id);
  const bsToast = new bootstrap.Toast(toastEl, { delay: 4000 });
  bsToast.show();
  toastEl.addEventListener('hidden.bs.toast', () => toastEl.remove());
}

function createToastContainer() {
  const div = document.createElement('div');
  div.id = 'toast-container';
  div.style.cssText = 'position:fixed;bottom:24px;right:24px;z-index:9999;';
  document.body.appendChild(div);
  return div;
}

// ── Live employee search (directory page) ─────────────
const liveSearch = document.getElementById('live-search-input');
if (liveSearch) {
  let timer;
  liveSearch.addEventListener('input', () => {
    clearTimeout(timer);
    timer = setTimeout(() => {
      document.getElementById('employee-search-form').submit();
    }, 600);
  });
}

// ── Sidebar toggle (mobile) ───────────────────────────
const sidebarToggle = document.getElementById('sidebar-toggle');
const sidebar = document.querySelector('.sidebar');
if (sidebarToggle && sidebar) {
  sidebarToggle.addEventListener('click', () => sidebar.classList.toggle('open'));
}

// ── Chart: Employee Growth (Chart.js) ────────────────
function initGrowthChart(canvasId, data) {
  const canvas = document.getElementById(canvasId);
  if (!canvas || !data) return;

  const parsed = typeof data === 'string' ? JSON.parse(data) : data;
  const labels = parsed.map(d => d.month);
  const values = parsed.map(d => d.count);

  new Chart(canvas, {
    type: 'line',
    data: {
      labels,
      datasets: [{
        label: 'New Employees',
        data: values,
        borderColor: '#00B4D8',
        backgroundColor: 'rgba(0,180,216,0.08)',
        borderWidth: 2,
        pointBackgroundColor: '#00B4D8',
        pointRadius: 4,
        tension: 0.4,
        fill: true,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: '#1A2840',
          titleColor: '#8899AA',
          bodyColor: '#E8F0FE',
          borderColor: 'rgba(0,180,216,0.2)',
          borderWidth: 1,
        }
      },
      scales: {
        x: { grid: { color: 'rgba(255,255,255,0.04)' }, ticks: { color: '#8899AA', font: { size: 11 } } },
        y: { grid: { color: 'rgba(255,255,255,0.04)' }, ticks: { color: '#8899AA', font: { size: 11 }, stepSize: 1 }, beginAtZero: true }
      }
    }
  });
}

// ── Chart: Department Distribution ───────────────────
function initDeptChart(canvasId, data) {
  const canvas = document.getElementById(canvasId);
  if (!canvas || !data) return;

  const parsed = typeof data === 'string' ? JSON.parse(data) : data;
  const labels = parsed.map(d => d.name);
  const values = parsed.map(d => d.count);
  const colors = ['#00B4D8','#2EC4B6','#4CC9F0','#F4A261','#E63946','#90E0EF','#48CAE4','#0096C7'];

  new Chart(canvas, {
    type: 'doughnut',
    data: {
      labels,
      datasets: [{
        data: values,
        backgroundColor: colors.slice(0, labels.length),
        borderWidth: 0,
        hoverOffset: 6,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '65%',
      plugins: {
        legend: {
          position: 'right',
          labels: { color: '#8899AA', font: { size: 11 }, padding: 12, boxWidth: 10 }
        },
        tooltip: {
          backgroundColor: '#1A2840',
          titleColor: '#8899AA',
          bodyColor: '#E8F0FE',
          borderColor: 'rgba(0,180,216,0.2)',
          borderWidth: 1,
        }
      }
    }
  });
}

// Expose to inline scripts (TNEB is the new namespace; PhishGuard kept as an alias
// in case other templates still reference window.PhishGuard.*)
window.TNEB = { initGrowthChart, initDeptChart, showToast };
window.PhishGuard = window.TNEB;