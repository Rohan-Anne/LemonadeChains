/* ============================================================
   LemonadeChains - Main JavaScript
   ============================================================ */

// Theme Toggle
(function() {
  const themeKey = 'lc-theme';
  const html = document.documentElement;

  function setTheme(theme) {
    html.setAttribute('data-theme', theme);
    localStorage.setItem(themeKey, theme);
    const icon = document.querySelector('#themeToggle i');
    if (icon) {
      icon.className = theme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
    }
  }

  // Apply saved theme immediately
  const saved = localStorage.getItem(themeKey) || 'light';
  setTheme(saved);

  document.addEventListener('DOMContentLoaded', function() {
    const toggle = document.getElementById('themeToggle');
    if (toggle) {
      toggle.addEventListener('click', function() {
        const current = html.getAttribute('data-theme');
        setTheme(current === 'dark' ? 'light' : 'dark');
      });
    }

    // Convert flash data to toasts
    document.querySelectorAll('.lc-flash-data').forEach(function(el) {
      const msg = el.textContent.trim();
      const type = el.getAttribute('data-type') || 'info';
      if (msg) {
        showToast(msg, type === 'danger' ? 'error' : type);
      }
    });
  });
})();

// Toast Notification System
function showToast(message, type) {
  type = type || 'info';
  const container = document.getElementById('toast-container');
  if (!container) return;

  const icons = {
    success: 'fas fa-check-circle',
    error: 'fas fa-times-circle',
    warning: 'fas fa-exclamation-triangle',
    info: 'fas fa-info-circle'
  };

  const toast = document.createElement('div');
  toast.className = 'lc-toast ' + type;
  toast.innerHTML = '<i class="lc-toast-icon ' + (icons[type] || icons.info) + '"></i><span>' + message + '</span>';
  container.appendChild(toast);

  setTimeout(function() {
    toast.classList.add('lc-toast-out');
    setTimeout(function() {
      if (toast.parentNode) toast.parentNode.removeChild(toast);
    }, 300);
  }, 4000);
}

// Plotly Theme Helper
function getPlotlyTheme() {
  var style = getComputedStyle(document.documentElement);
  return {
    paper_bgcolor: style.getPropertyValue('--bg-surface').trim() || '#FFFFFF',
    plot_bgcolor: style.getPropertyValue('--bg-surface').trim() || '#FFFFFF',
    font: {
      color: style.getPropertyValue('--text-primary').trim() || '#1A202C',
      family: 'Inter, sans-serif'
    },
    xaxis: {
      gridcolor: style.getPropertyValue('--border-color').trim() || '#E2E8F0',
      zerolinecolor: style.getPropertyValue('--border-color').trim() || '#E2E8F0'
    },
    yaxis: {
      gridcolor: style.getPropertyValue('--border-color').trim() || '#E2E8F0',
      zerolinecolor: style.getPropertyValue('--border-color').trim() || '#E2E8F0'
    }
  };
}

// TradingView Theme Helper
function getTradingViewTheme() {
  return document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
}
