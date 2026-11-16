const $ = (id) => document.getElementById(id);
const tabs = new Map();
let activeId = null;
const pageSize = 100;
const chunkSize = 128 * 1024;

function openDatabase() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open('zw-zniffer-traces', 1);
    request.onupgradeneeded = () => request.result.createObjectStore('rows', { keyPath: ['doc', 'index'] });
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}
const dbPromise = openDatabase();

async function storeRows(doc, start, rows) {
  if (!rows.length) return;
  const db = await dbPromise;
  return new Promise((resolve, reject) => {
    const transaction = db.transaction('rows', 'readwrite');
    const store = transaction.objectStore('rows');
    rows.forEach((row, i) => store.put({ ...row, doc, index: start + i }));
    transaction.oncomplete = resolve;
    transaction.onerror = () => reject(transaction.error);
  });
}

async function getPage(doc, first, last) {
  const db = await dbPromise;
  return new Promise((resolve, reject) => {
    const request = db.transaction('rows').objectStore('rows').getAll(IDBKeyRange.bound([doc, first], [doc, last]));
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function findRow(doc, first, last, query) {
  if (first > last) return null;
  const db = await dbPromise;
  return new Promise((resolve, reject) => {
    const store = db.transaction('rows').objectStore('rows');
    const request = store.openCursor(IDBKeyRange.bound([doc, first], [doc, last]));
    request.onsuccess = () => {
      const cursor = request.result;
      if (!cursor) { resolve(null); return; }
      if (JSON.stringify(cursor.value).toLowerCase().includes(query)) resolve(cursor.value);
      else cursor.continue();
    };
    request.onerror = () => reject(request.error);
  });
}

async function deleteRows(doc) {
  const db = await dbPromise;
  return new Promise((resolve, reject) => {
    const transaction = db.transaction('rows', 'readwrite');
    const store = transaction.objectStore('rows');
    const request = store.openCursor(IDBKeyRange.bound([doc, 0], [doc, Number.MAX_SAFE_INTEGER]));
    request.onsuccess = () => {
      const cursor = request.result;
      if (cursor) { cursor.delete(); cursor.continue(); }
    };
    transaction.oncomplete = resolve;
    transaction.onerror = () => reject(transaction.error);
  });
}

async function requestJson(path, options = {}) {
  const response = await fetch(path, options);
  const body = await response.json();
  if (!response.ok) throw new Error(body.error || `HTTP ${response.status}`);
  return body;
}

function dateFromBinary(binary) {
  const ticks = BigInt(binary) & ((1n << 62n) - 1n);
  const ms = (ticks - 621355968000000000n) / 10000n;
  const date = new Date(Number(ms));
  return Number.isNaN(date.getTime()) ? binary : date.toLocaleString();
}

function bytesFromHex(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return bytes;
}

function showDetails(row) {
  const panel = $('decoded-fields');
  panel.replaceChildren();
  if (!row) {
    $('detail-prompt').hidden = false;
    $('raw-record').hidden = true;
    return;
  }
  $('detail-prompt').hidden = true;
  $('raw-record').hidden = false;
  const summary = document.createElement('p');
  summary.className = 'field-summary';
  summary.textContent = [
    row.frameType && `Frame: ${row.frameType}${row.headerDefinition === undefined ? '' : ` (#${row.headerDefinition})`}`,
    row.commandName && `Command: ${row.commandClass} / ${row.commandName} (v${row.commandVersion})`,
    row.decryptedName && `Decrypted: ${row.decryptedCommandClass ?? 'Z-Wave'} / ${row.decryptedName}`,
  ].filter(Boolean).join(' · ') || 'No Z-Wave frame definition for this record.';
  panel.append(summary);
  const sections = [
    ['Frame header · FrameDefinition.xml', row.headerFields],
    ['Command parameters · ZWave_cmd_classes.xml', row.commandFields],
    ['Decrypted parameters · ZWave_cmd_classes.xml', row.decryptedFields],
  ];
  for (const [heading, fields] of sections) {
    if (!fields?.length) continue;
    const title = document.createElement('h3');
    title.textContent = heading;
    panel.append(title);
    const table = document.createElement('table');
    const body = document.createElement('tbody');
    for (const field of fields) {
      const tr = document.createElement('tr');
      const name = document.createElement('th');
      name.textContent = field.name;
      name.style.paddingLeft = `${0.5 + Math.min(4, (field.name.match(/\./g) ?? []).length) * 0.75}rem`;
      const value = document.createElement('td');
      value.textContent = field.hex ? `${field.value} bytes: ${field.hex}` :
        field.label ? `${field.value} (${field.label})` : String(field.value);
      tr.append(name, value);
      body.append(tr);
    }
    table.append(body);
    panel.append(table);
  }
  if (row.commandName && !row.commandFields?.length && !row.keyMaterialRedacted) {
    const note = document.createElement('p');
    note.textContent = 'This XML command definition has no decoded parameters.';
    panel.append(note);
  }
  if (row.keyMaterialRedacted) {
    const note = document.createElement('p');
    note.textContent = 'Network key bytes are hidden.';
    panel.append(note);
  }
  $('trace-details').textContent = JSON.stringify(row, null, 2);
}

function renderTabs() {
  document.querySelectorAll('#tabs .tab, #tabs .close-tab').forEach((node) => node.remove());
  for (const tab of tabs.values()) {
    const button = document.createElement('button');
    button.className = `tab${tab.id === activeId ? ' active' : ''}`;
    button.type = 'button';
    button.setAttribute('role', 'tab');
    button.setAttribute('aria-selected', String(tab.id === activeId));
    button.append(document.createTextNode(tab.name));
    button.onclick = () => { activeId = tab.id; render(); };
    $('tabs').insertBefore(button, $('add-tab'));
    const close = document.createElement('button');
    close.className = 'close-tab';
    close.type = 'button';
    close.textContent = '×';
    close.setAttribute('aria-label', `Close ${tab.name}`);
    close.onclick = () => closeTab(tab.id);
    $('tabs').insertBefore(close, $('add-tab'));
  }
}

async function renderPage() {
  const tab = tabs.get(activeId);
  if (!tab) return;
  const first = tab.page * pageSize;
  const rows = await getPage(tab.id, first, first + pageSize - 1);
  if (activeId !== tab.id) return;
  const body = $('trace-rows');
  body.replaceChildren();
  for (const row of rows) {
    const tr = document.createElement('tr');
    tr.tabIndex = 0;
    if (tab.selectedRow?.index === row.index) tr.classList.add('selected');
    const values = [row.index + 1, dateFromBinary(row.timeBinary), row.frameType ?? row.apiName,
      row.decryptedName ?? (row.s2Encrypted ? 'S2 encrypted' : row.s0Encrypted ? 'S0 encrypted' : row.commandName ?? ''),
      row.homeId ?? '', row.sourceNode ?? '', row.destinationNode ?? '', row.sessionId,
      row.received === undefined ? (row.outgoing ? 'TX' : 'RX') : (row.received ? 'RX' : 'TX'),
      row.channel ?? '', row.rssiDbm ?? '', row.rawHex ?? ''];
    for (const value of values) {
      const td = document.createElement('td');
      td.textContent = String(value);
      tr.append(td);
    }
    const select = () => {
      tab.selectedRow = row;
      body.querySelectorAll('tr.selected').forEach((node) => node.classList.remove('selected'));
      tr.classList.add('selected');
      showDetails(row);
    };
    tr.onclick = select;
    tr.onkeydown = (event) => { if (event.key === 'Enter') select(); };
    body.append(tr);
  }
  $('page-label').textContent = `${tab.page + 1} / ${Math.max(1, Math.ceil(tab.count / pageSize))}`;
  $('prev-page').disabled = tab.page === 0;
  $('next-page').disabled = first + pageSize >= tab.count;
}

function render() {
  renderTabs();
  const tab = tabs.get(activeId);
  $('empty').hidden = Boolean(tab);
  $('trace').hidden = !tab;
  if (!tab) return;
  $('trace-status').textContent = tab.status;
  $('trace-count').textContent = `${tab.count} rows`;
  $('edit-comment').hidden = !tab.file;
  showDetails(tab.selectedRow ?? null);
  renderPage().catch((error) => { $('trace-status').textContent = error.message; });
}

async function closeTab(id) {
  const tab = tabs.get(id);
  if (!tab) return;
  tab.cancelled = true;
  tabs.delete(id);
  if (activeId === id) activeId = tabs.keys().next().value ?? null;
  render();
  await Promise.allSettled([
    requestJson(`/api/session?id=${encodeURIComponent(id)}`, { method: 'DELETE' }),
    deleteRows(id),
  ]);
}

async function findNext() {
  const tab = tabs.get(activeId);
  const query = $('search-text').value.trim().toLowerCase();
  if (!tab || !query || !tab.count) return;
  const first = Math.min(tab.count, (tab.selectedRow?.index ?? -1) + 1);
  try {
    const row = await findRow(tab.id, first, tab.count - 1, query) ??
      await findRow(tab.id, 0, first - 1, query);
    if (!row || tab.cancelled) {
      $('trace-status').textContent = `No match for “${query}”`;
      return;
    }
    tab.page = Math.floor(row.index / pageSize);
    tab.selectedRow = row;
    if (activeId === tab.id) render();
  } catch (error) {
    $('trace-status').textContent = `Search failed: ${error.message}`;
  }
}

async function openFile(file) {
  const { id } = await requestJson('/api/session', { method: 'POST' });
  const tab = { id, name: file.name, file, status: 'Opening…', count: 0, page: 0, comment: '', cancelled: false };
  tabs.set(id, tab);
  activeId = id;
  render();
  try {
    const readPass = async (label) => {
      for (let offset = 0; offset < file.size; offset += chunkSize) {
        if (tab.cancelled) return;
        const bytes = await file.slice(offset, offset + chunkSize).arrayBuffer();
        const result = await requestJson(`/api/chunk?id=${encodeURIComponent(id)}`, {
          method: 'POST', headers: { 'Content-Type': 'application/octet-stream' }, body: bytes,
        });
        if (tab.cancelled) return;
        await storeRows(id, tab.count, result.rows);
        if (tab.cancelled) { await deleteRows(id); return; }
        tab.count += result.rows.length;
        tab.status = `${label} ${Math.min(file.size, offset + chunkSize).toLocaleString()} / ${file.size.toLocaleString()} bytes`;
        if (activeId === id) render();
      }
    };
    await readPass('Reading');
    if (tab.cancelled) return;
    let result = await requestJson(`/api/finish?id=${encodeURIComponent(id)}`, { method: 'POST' });
    if (result.keyCount > 0) {
      await requestJson(`/api/replay?id=${encodeURIComponent(id)}`, { method: 'POST' });
      await deleteRows(id);
      if (tab.cancelled) return;
      tab.count = 0;
      tab.selectedRow = null;
      await readPass('Decrypting S0/S2');
      if (tab.cancelled) return;
      result = await requestJson(`/api/finish?id=${encodeURIComponent(id)}`, { method: 'POST' });
    }
    tab.comment = result.comment;
    tab.status = `Ready · ZLF v${result.version} · ${result.records} records` +
      (result.s2Encrypted ? ` · S2 ${result.s2Decrypted}/${result.s2Encrypted} decrypted` : '') +
      (result.s0Encrypted ? ` · S0 ${result.s0Decrypted}/${result.s0Encrypted} decrypted` : '') +
      (result.comment ? ` · ${result.comment}` : '');
    if (activeId === id) render();
  } catch (error) {
    tab.status = `Error: ${error.message}`;
    if (activeId === id) render();
  }
}

async function openLive(url, name) {
  const { id } = await requestJson(url, { method: 'POST' });
  const tab = { id, name, status: 'Connecting…', count: 0, page: 0, cancelled: false };
  tabs.set(id, tab);
  activeId = id;
  render();
  const poll = async () => {
    if (tab.cancelled) return;
    try {
      const result = await requestJson(`/api/live/poll?id=${encodeURIComponent(id)}`);
      if (tab.cancelled) return;
      await storeRows(id, tab.count, result.rows);
      if (tab.cancelled) { await deleteRows(id); return; }
      tab.count += result.rows.length;
      tab.status = result.status === 'error' ? `Capture error: ${result.error}` :
        `${result.status} · ${tab.count} frames`;
      if (activeId === id) render();
      if (result.pending || result.status === 'capturing' || result.status === 'connecting')
        setTimeout(poll, 250);
    } catch (error) {
      tab.status = `Capture error: ${error.message}`;
      if (activeId === id) render();
    }
  };
  poll();
}

async function saveComment() {
  const tab = tabs.get(activeId);
  if (!tab) return;
  const comment = $('comment-text').value;
  try {
    const result = await requestJson(`/api/comment-header?id=${encodeURIComponent(tab.id)}`, {
      method: 'POST', headers: { 'Content-Type': 'text/plain; charset=utf-8' },
      body: new TextEncoder().encode(comment),
    });
    const updated = new Blob([bytesFromHex(result.headerHex), tab.file.slice(2048)],
      { type: 'application/octet-stream' });
    const link = document.createElement('a');
    const url = URL.createObjectURL(updated);
    link.href = url;
    link.download = tab.name.replace(/(\.zw?lf)$/i, '-commented$1');
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 60_000);
    tab.comment = comment;
    $('comment-dialog').close();
    tab.status = `Saved copy with trace comment · ${tab.count} rows`;
    render();
  } catch (error) {
    $('trace-status').textContent = `Save failed: ${error.message}`;
  }
}

$('add-tab').onclick = () => { $('source-note').textContent = ''; $('ip-form').hidden = true; $('serial-form').hidden = true; $('source-dialog').showModal(); };
$('cancel-source').onclick = () => $('source-dialog').close();
$('open-file').onclick = () => { $('source-dialog').close(); $('file-input').click(); };
$('connect-ip').onclick = () => { $('serial-form').hidden = true; $('ip-form').hidden = false; $('ip-host').focus(); };
$('ip-form').onsubmit = (event) => {
  event.preventDefault();
  const host = $('ip-host').value.trim();
  const port = Number($('ip-port').value);
  if (!host || !Number.isInteger(port) || port < 1 || port > 65535) return;
  $('source-dialog').close();
  openLive(`/api/live/ip?host=${encodeURIComponent(host)}&port=${encodeURIComponent(port)}`,
    `${host}:${port}`).catch((error) => { $('service-status').textContent = error.message; });
};
$('connect-serial').onclick = () => { $('ip-form').hidden = true; $('serial-form').hidden = false; $('serial-device').focus(); };
$('serial-form').onsubmit = (event) => {
  event.preventDefault();
  const device = $('serial-device').value.trim();
  const baud = $('serial-baud').value;
  const version = $('serial-version').value;
  if (!device.startsWith('/dev/')) return;
  $('source-dialog').close();
  openLive(`/api/live/serial?device=${encodeURIComponent(device)}&baud=${baud}&version=${version}`,
    device).catch((error) => { $('service-status').textContent = error.message; });
};
$('file-input').onchange = (event) => {
  const file = event.target.files?.[0];
  event.target.value = '';
  if (file) openFile(file).catch((error) => { $('service-status').textContent = error.message; });
};
$('edit-comment').onclick = () => {
  const tab = tabs.get(activeId);
  if (!tab) return;
  $('comment-text').value = tab.comment;
  $('comment-dialog').showModal();
};
$('cancel-comment').onclick = () => $('comment-dialog').close();
$('save-comment').onclick = saveComment;
$('find-next').onclick = findNext;
$('search-text').onkeydown = (event) => { if (event.key === 'Enter') findNext(); };
$('prev-page').onclick = () => { const tab = tabs.get(activeId); if (tab && tab.page > 0) { tab.page--; renderPage(); } };
$('next-page').onclick = () => { const tab = tabs.get(activeId); if (tab && (tab.page + 1) * pageSize < tab.count) { tab.page++; renderPage(); } };
requestJson('/api/health').then(() => { $('service-status').textContent = 'Service online'; })
  .catch(() => { $('service-status').textContent = 'Service unavailable'; });
