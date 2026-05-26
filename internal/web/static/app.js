const kvApi = {
  async request(method, path, body) {
    const options = {
      method,
      credentials: 'include',
      headers: {}
    };
    if (body !== undefined) {
      options.headers['Content-Type'] = 'application/json';
      options.body = JSON.stringify(body);
    }

    const response = await fetch(path, options);
    const contentType = response.headers.get('content-type') || '';
    const hasJSON = contentType.includes('application/json');
    const payload = hasJSON ? await response.json() : null;

    if (!response.ok) {
      const message = payload && payload.error ? payload.error : `Request failed with status ${response.status}`;
      throw new Error(message);
    }

    return payload;
  },
  get(path) {
    return this.request('GET', path);
  },
  post(path, body) {
    return this.request('POST', path, body);
  },
  del(path) {
    return this.request('DELETE', path);
  }
};

function showToast(message, type = 'success') {
  let root = document.getElementById('snackbar-root');
  if (!root) {
    root = document.createElement('div');
    root.id = 'snackbar-root';
    root.className = 'snackbar-container';
    document.body.appendChild(root);
  }

  const toast = document.createElement('div');
  toast.className = `snackbar ${type === 'error' ? 'error' : ''}`.trim();
  toast.textContent = message;
  root.appendChild(toast);

  window.setTimeout(() => {
    toast.remove();
  }, 3200);
}

function formatDate(unix) {
  if (!unix) {
    return '—';
  }
  return new Date(unix * 1000).toLocaleString();
}

function truncate(value, length = 8) {
  if (!value) {
    return '—';
  }
  return value.length <= length ? value : `${value.slice(0, length)}…`;
}

window.kvApi = kvApi;
window.showToast = showToast;
window.formatDate = formatDate;
window.truncate = truncate;
