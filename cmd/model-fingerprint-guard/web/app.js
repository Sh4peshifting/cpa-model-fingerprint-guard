'use strict';

const apiBase = '/v0/management/model-fingerprint-guard';
const byId = id => document.getElementById(id);

function initializeTheme() {
  const root = document.documentElement;
  let panelRoot;
  try {
    if (window.parent !== window) panelRoot = window.parent.document.documentElement;
  } catch {
    // A panel on another origin cannot share its theme through the DOM.
  }
  if (panelRoot) {
    const sync = () => {
      const theme = panelRoot.dataset.theme;
      root.dataset.theme = theme === 'white' || theme === 'dark' ? theme : 'light';
    };
    const observer = new MutationObserver(sync);
    observer.observe(panelRoot, { attributes: true, attributeFilter: ['data-theme'] });
    window.addEventListener('pagehide', event => {
      if (!event.persisted) observer.disconnect();
    });
    sync();
    return;
  }
  const preference = window.matchMedia('(prefers-color-scheme: dark)');
  const sync = () => { root.dataset.theme = preference.matches ? 'dark' : 'light'; };
  preference.addEventListener('change', sync);
  sync();
}
initializeTheme();

const translations = {
  normal: '正常', isolated: '隔离', cooling: '宿主冷却', disabled: '已停用',
  match: '匹配', mismatch: '不一致', inconclusive: '证据不足', transient: '暂时失败',
  unsupported: '不支持', cancelled: '已取消', error: '上游异常', manual: '手动操作',
  idle: '空闲检测', confirm: '复核', http_status: 'HTTP 状态', error_code: '错误代码',
  recheck: '隔离后自动复检', recheck_kept_isolated: '复检未通过，保持隔离',
  error_text: '错误文本', matched: '匹配，解除插件隔离', recorded: '已记录',
  confirm_again: '等待复核', different_model: '测试模型与异常模型不同，等待人工',
  confirmed_isolation: '已确认不一致，保持隔离',
  held_by_policy: '保持隔离', host_mutation_unavailable: '保持隔离', host_write_failed: '保持隔离',
  persistence_failed: '状态写入失败',
  held_unsupported: '不支持检测，等待人工', retries_exhausted: '重试耗尽',
  retry_scheduled: '等待重试', cooldown_wait: '等待宿主冷却结束',
  gateway_recheck: '业务异常恢复复检', gateway_recheck_scheduled: '保持隔离，等待恢复复检',
};
const translate = value => translations[value] || value || '—';
const localTime = value => value ? new Date(value).toLocaleString() : '—';
const numberText = value => value == null ? '—' : value.toFixed(3);
const identifiedModel = result => result?.detected_class || result?.detected || '—';
let key = '';
let view = null;
let settingsRevision = 0;
let settingsBaseline = null;
let editing = null;
const selected = new Set();
let authLayout = 'cards';
let refreshRequest = null;
let busy = false;
const maxBatchSize = 250;
let lastRender = '';
let noticeTimer;

function element(tag, text, attributes = {}) {
  const node = document.createElement(tag);
  if (text != null) node.textContent = text;
  for (const [name, value] of Object.entries(attributes)) node.setAttribute(name, value);
  return node;
}
function message(text, bad = false) {
  const node = byId('notice');
  const content = byId('notice-text');
  if (text && !node.hidden && content.textContent === text) return;
  clearTimeout(noticeTimer);
  node.hidden = !text;
  node.dataset.tone = bad ? 'error' : text === '正在处理…' ? 'info' : 'success';
  byId('notice-icon').replaceChildren(icon({ error: 'alert', info: 'info', success: 'check' }[node.dataset.tone]));
  content.textContent = text;
  if (text && node.dataset.tone !== 'info') noticeTimer = setTimeout(() => message(''), 5000);
}
byId('dismiss-notice').onclick = () => message('');
async function api(path, method = 'GET', body, timeout = 15000) {
  const headers = { Authorization: 'Bearer ' + key };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const response = await fetch(apiBase + path, {
    // Same-origin access proxies need the browser's existing session cookie.
    method, headers, credentials: 'same-origin', cache: 'no-store', redirect: 'error',
    signal: AbortSignal.timeout(timeout),
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (response.status === 401 || response.status === 403) throw new Error('管理密钥无效或宿主禁止访问。');
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || '管理接口请求失败。');
  return data;
}
function refresh(timeout) {
  if (!key) return Promise.resolve();
  if (refreshRequest) return refreshRequest;
  const request = api('/state', 'GET', undefined, timeout).then(next => {
    const serialized = JSON.stringify(next);
    view = next;
    if (serialized !== lastRender) {
      lastRender = serialized;
      render();
    }
    if (!busy && settingsBaseline !== null && settingsRevision !== view.revision && !settingsDirty()) drawSettings();
    else updateSettingsState();
  }).finally(() => {
    if (refreshRequest === request) refreshRequest = null;
  });
  refreshRequest = request;
  return request;
}
async function refreshLatest() {
  await refreshRequest?.catch(() => {});
  await refresh();
}
function setConnected(connected) {
  byId('login-page').hidden = connected;
  byId('page-header').hidden = !connected;
  byId('workspace').hidden = !connected;
}
function loginStatus(text, bad = false) {
  const status = byId('login-status');
  status.hidden = !text;
  status.classList.toggle('error', bad);
  status.textContent = text;
}
function rememberedPanelKey() {
  try {
    // CLIProxyAPI Management Center v1.29.1 persists an opt-in, reversible v2 record.
    // Read the current origin's record only and bind it to this plugin's root API.
    if (window.top.location.origin !== location.origin || localStorage.getItem('isLoggedIn') !== 'true') return '';
    const prefix = 'enc::v2::';
    const raw = localStorage.getItem('cli-proxy-auth');
    if (!raw?.startsWith(prefix)) return '';
    const mask = new TextEncoder().encode('cli-proxy-api-webui::secure-storage|' + location.host);
    const bytes = Uint8Array.from(atob(raw.slice(prefix.length)),
      (char, index) => char.charCodeAt(0) ^ mask[index % mask.length]);
    const { state } = JSON.parse(new TextDecoder().decode(bytes));
    if (state?.rememberPassword !== true || typeof state.managementKey !== 'string' ||
      typeof state.apiBase !== 'string' || new URL(state.apiBase).href !== location.origin + '/') {
      return '';
    }
    return state.managementKey.trim();
  } catch {
    // Storage can be unavailable in an iframe or hold an unreadable record.
    return '';
  }
}
async function connect(managementKey, automatic = false) {
  const button = byId('connect');
  if (button.disabled || view) return;
  if (!managementKey) return loginStatus('请输入管理密钥。', true);
  key = managementKey;
  const input = byId('key');
  input.disabled = true;
  button.disabled = true;
  button.textContent = '正在连接…';
  byId('login-fields').hidden = automatic;
  loginStatus(automatic ? '正在验证已保存的登录…' : '');
  try {
    await refresh(automatic ? 5000 : undefined);
    drawSettings();
    setConnected(true);
    loginStatus('');
    if (!automatic) byId('tab-overview').focus();
  } catch (error) {
    key = '';
    view = null;
    lastRender = '';
    settingsBaseline = null;
    loginStatus(automatic ? '自动登录未成功，请输入管理密钥。' : error.message, true);
  } finally {
    byId('login-fields').hidden = false;
    input.disabled = false;
    button.disabled = false;
    button.textContent = '连接管理接口';
    if (!view && !automatic) input.focus();
  }
}
byId('login').addEventListener('submit', event => {
  event.preventDefault();
  const input = byId('key');
  const managementKey = input.value.trim();
  input.value = '';
  void connect(managementKey);
});
window.setInterval(() => {
  if (!view || busy || document.hidden) return;
  refresh().catch(error => message(error.message, true));
}, 3000);
const tabs = [...document.querySelectorAll('[role="tab"]')];
function openTab(tab, focus = false) {
  hideDetectionTooltip();
  tab.parentElement.dataset.activeTab = tab.dataset.tab;
  for (const peer of tabs) {
    const active = peer === tab;
    byId(peer.dataset.tab).hidden = !active;
    peer.setAttribute('aria-selected', String(active));
    peer.tabIndex = active ? 0 : -1;
  }
  if (focus) tab.focus();
}
for (const [index, tab] of tabs.entries()) {
  tab.onclick = () => openTab(tab);
  tab.onkeydown = event => {
    let next;
    switch (event.key) {
      case 'ArrowLeft': next = (index + tabs.length - 1) % tabs.length; break;
      case 'ArrowRight': next = (index + 1) % tabs.length; break;
      case 'Home': next = 0; break;
      case 'End': next = tabs.length - 1; break;
      default: return;
    }
    event.preventDefault();
    openTab(tabs[next], true);
  };
}
byId('open-history').onclick = () => openTab(byId('tab-history'), true);
function icon(name) {
  const namespace = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(namespace, 'svg');
  const use = document.createElementNS(namespace, 'use');
  svg.setAttribute('class', 'icon');
  svg.setAttribute('aria-hidden', 'true');
  use.setAttribute('href', '#icon-' + name);
  svg.append(use);
  return svg;
}
function badge(text, tone) {
  return element('span', text, { class: 'badge ' + tone });
}
function resultBadge(status) {
  const tones = { match: 'normal', mismatch: 'disabled', transient: 'cooling', inconclusive: 'cooling' };
  return badge(translate(status), tones[status] || '');
}
function renderRuntimeOptions() {
  const current = view.runtime_settings;
  byId('runtime-options').hidden = !current;
  if (!current) return;
  byId('runtime-native').textContent = current.native_diagnostics ? '开启' : '关闭';
  byId('runtime-auto-update').textContent = current.reference_auto_update ? '开启' : '关闭';
  const interval = current.reference_refresh_interval;
  byId('runtime-refresh-interval').textContent = current.reference_auto_update ? interval : '暂停（已配置 ' + interval + '）';
  byId('runtime-config-error').hidden = !current.config_rejected;
}
function stateName(a) {
  if (a.disabled) return 'disabled';
  if (a.isolated) return 'isolated';
  if (a.cooling) return 'cooling';
  return 'normal';
}
function render() {
  renderRuntimeOptions();
  const auths = view.auths;
  const metrics = [
    ['认证文件', auths.length, 'file'],
    ['启用检测', auths.filter(a => a.policy.enabled).length, 'shield'],
    ['正常调度', auths.filter(a => stateName(a) === 'normal').length, 'check'],
    ['隔离', auths.filter(a => a.isolated && !a.disabled).length, 'lock'],
    ['检测中', auths.filter(a => a.running).length, 'probe'],
    ['待检测', auths.filter(a => a.pending && !a.running).length, 'history'],
    ['宿主冷却', auths.filter(a => a.cooling && !a.disabled).length, 'probe'],
    ['待人工处理', auths.filter(a => a.held && !a.disabled && !a.pending && !a.next_recheck && !a.next_probe).length, 'alert'],
  ];
  byId('metrics').replaceChildren(...metrics.map(([label, value, glyph]) => {
    const card = element('div', null, { class: 'metric' });
    const heading = element('span', label);
    heading.prepend(icon(glyph));
    card.append(heading, element('strong', value));
    return card;
  }));
  const guardStatus = byId('guard-status');
  guardStatus.textContent = view.config.enabled ? '检测已开启' : '检测已关闭';
  guardStatus.classList.toggle('normal', view.config.enabled);

  const warnings = [];
  if (view.reference) {
    warnings.push(['history', '参考库构建于 ' + localTime(view.reference.built_at)]);
    if (view.reference.last_check_failed) warnings.push(['alert', '参考库更新失败，保留当前版本。']);
  }
  if (view.storage_error) warnings.push(['alert', '持久化失败，请检查状态目录权限和磁盘空间。']);
  if (view.inventory_error) warnings.push(['alert', '认证清单读取失败，检测已暂停。']);
  if (view.overload_until) warnings.push(['alert', '全局过载保护至 ' + localTime(view.overload_until)]);
  const health = byId('health');
  health.hidden = warnings.length === 0;
  health.replaceChildren(...warnings.map(([glyph, text]) => {
    const item = element('li', text);
    item.prepend(icon(glyph));
    return item;
  }));

  const recent = auths.filter(a => a.trigger?.at).sort((a, b) => b.trigger.at.localeCompare(a.trigger.at)).slice(0, 6);
  if (recent.length) {
    byId('recent').replaceChildren(...recent.map(a => {
      const item = element('div', null, { class: 'activity-row' });
      const detail = element('div');
      const reason = [translate(a.trigger.reason), a.trigger.http_status, a.trigger.error_code].filter(Boolean).join(' · ');
      detail.append(element('strong', a.name), element('small', reason));
      item.append(icon('alert'), detail, element('time', localTime(a.trigger.at), { datetime: a.trigger.at }));
      return item;
    }));
  } else {
    byId('recent').replaceChildren(element('p', '暂无异常'));
  }
  byId('reference-models').replaceChildren(...view.models.map(name => element('option', null, { value: name })));
  renderAuth();
  renderHistory();
}
function showEmpty(kind, filtered, total) {
  const target = byId(kind + '-empty');
  target.hidden = filtered.length > 0;
  if (target.hidden) return;

  const filteredOut = total > 0;
  const label = kind === 'auth' ? '认证文件' : '检测记录';
  const line = element('div', filteredOut ? '没有符合条件的' + label : '暂无' + label, { class: 'empty-state' });
  line.prepend(icon('inbox'));
  if (filteredOut) {
    const reset = element('button', '清除筛选', { class: 'ghost', type: 'button' });
    reset.onclick = () => {
      byId(kind + '-search').value = '';
      byId(kind + '-filter').value = '';
      if (kind === 'auth') renderAuth(); else renderHistory();
      byId(kind + '-search').focus();
    };
    line.append(reset);
  }
  target.replaceChildren(line);
}
function actionButton(text, name, glyph, fn, disabled = false) {
  const button = element('button', text, { type: 'button', 'data-control': name });
  button.prepend(icon(glyph));
  button.disabled = disabled;
  button.onclick = fn;
  return button;
}
function filteredAuths() {
  const query = byId('auth-search').value.trim().toLowerCase();
  const filter = byId('auth-filter').value;
  return view.auths.filter(a => (!filter || (filter === 'pending' ? a.pending && !a.running : stateName(a) === filter)) &&
    [a.name, a.id, a.provider, a.policy.model, a.policy.expected, identifiedModel(a.last_result)].join(' ').toLowerCase().includes(query));
}
function setSelection(auths, value) {
  for (const a of auths) {
    if (value) selected.add(a.id); else selected.delete(a.id);
  }
  renderAuth();
}
function credentialParts(a) {
  const checkbox = element('input', null, { type: 'checkbox', 'aria-label': '选择 ' + a.name, 'data-control': 'select' });
  checkbox.checked = selected.has(a.id);
  checkbox.onchange = () => setSelection([a], checkbox.checked);
  const identity = element('div', null, { class: 'auth-identity' });
  identity.append(element('strong', a.name), element('small', a.provider));
  const status = element('div', null, { class: 'auth-status' });
  const badges = element('div', null, { class: 'auth-status-badges' });
  const state = stateName(a);
  badges.append(badge(translate(state), state));
  if (a.running) badges.append(badge('检测中', 'pending'));
  else if (a.pending) badges.append(badge(a.pending === 'gateway_recheck' ? '待恢复复检' : '待检测', 'pending'));
  else if (a.next_recheck && !a.disabled) badges.append(badge('待复检', 'pending'));
  status.append(badges, element('small', (a.policy.enabled ? '检测开启' : '检测关闭') +
    (a.held && !a.pending && !a.next_recheck && !a.next_probe && !a.running ? ' · 待人工处理' : !a.probeable ? ' · 诊断不可用' : '')));
  const result = element('div', null, { class: 'auth-result' });
  result.append(resultBadge(a.last_result?.status));
  if (a.trigger?.at || a.abnormal?.confirmed_at || a.next_probe || a.next_recheck) {
    const details = actionButton('详情', 'details', 'info', () => showAuthDetails(a.id));
    details.className = 'ghost';
    details.setAttribute('aria-label', a.name + ' 的检测详情');
    result.append(details);
  }
  const expected = a.last_expected || a.policy.expected || view.config.expected_models?.[a.policy.model] || a.policy.model;
  const models = element('div');
  models.append(element('span', expected || '—'), element('small', identifiedModel(a.last_result)));
  const actions = element('div', null, { class: 'row-actions' });
  actions.append(
    actionButton('设置', 'settings', 'settings', () => editAuth(a)),
    actionButton('检测', 'check', 'probe', () => action('check', [a.id]), a.disabled || !a.policy.enabled || !a.probeable || a.running),
  );
  if ((a.pending || a.next_recheck) && !a.running) {
    const cancel = actionButton('取消检测', 'cancel', 'close', () => action('cancel', [a.id]));
    if (a.pending === 'recheck' || a.pending === 'gateway_recheck' || !a.pending) {
      cancel.title = '取消自动复检，保持隔离并等待人工处理';
    }
    actions.append(cancel);
  }
  actions.append(
    a.isolated
      ? actionButton('解除隔离', 'release', 'unlock', () => action('release', [a.id], true))
      : actionButton('隔离', 'isolate', 'lock', () => action('isolate', [a.id], true), a.disabled),
  );
  return { checkbox, identity, status, models, result, actions };
}
const detectionTooltip = byId('detection-tooltip');
function hideDetectionTooltip() {
  detectionTooltip.hidden = true;
}
byId('auth').addEventListener('pointerover', event => {
  const square = event.target.closest('.detection-square');
  if (!square || event.pointerType === 'touch') return;
  detectionTooltip.textContent = square.getAttribute('aria-label');
  detectionTooltip.hidden = false;
  const anchor = square.getBoundingClientRect();
  const { width, height } = detectionTooltip.getBoundingClientRect();
  const edge = 8;
  const center = anchor.left + anchor.width / 2;
  const left = Math.max(edge, Math.min(center - width / 2, document.documentElement.clientWidth - width - edge));
  const above = anchor.top - height - edge;
  detectionTooltip.style.left = left + 'px';
  detectionTooltip.style.top = (above >= edge ? above : anchor.bottom + edge) + 'px';
});
byId('auth').addEventListener('pointerout', event => {
  if (event.target.closest('.detection-square')) hideDetectionTooltip();
});
document.addEventListener('scroll', hideDetectionTooltip, { capture: true, passive: true });
window.addEventListener('resize', hideDetectionTooltip);

function detectionSummary(records = []) {
  if (!records.length) return element('small', '暂无检测记录');
  const summary = element('div', null, { class: 'detection-summary' });
  const squares = element('div', null, { class: 'detection-squares', role: 'group', 'aria-label': '最近 16 次检测结果' });
  const counts = { match: 0, mismatch: 0, failed: 0 };
  const outcomes = records.map(record => {
    const status = record.result.status;
    const outcome = status === 'match' || status === 'mismatch' ? status : 'failed';
    counts[outcome]++;
    return outcome;
  });
  for (let i = Math.min(records.length, 16) - 1; i >= 0; i--) {
    const label = localTime(records[i].at) + ' · ' + translate(records[i].result.status);
    squares.append(element('span', null, { class: 'detection-square ' + outcomes[i], 'aria-label': label, role: 'img' }));
  }
  const rate = new Intl.NumberFormat('zh-CN', { style: 'percent', maximumFractionDigits: 1 }).format(counts.match / records.length);
  summary.append(squares, element('small',
    '一致 ' + counts.match + ' / 不一致 ' + counts.mismatch + ' / 失败 ' + counts.failed + ' · 一致率 ' + rate,
    { title: '按此认证的全部保留记录统计，证据不足、不支持和取消计入失败。' }));
  return summary;
}
function credential(a, records) {
  const { checkbox, identity, status, models, result, actions } = credentialParts(a);
  const information = [
    ['最后业务', localTime(a.last_business)], ['最后检测', localTime(a.last_check)],
    ['预期 / 识别模型', models], ['结果', result], ['检测记录', detectionSummary(records)],
  ];
  if (authLayout === 'table') {
    const row = element('tr', null, { 'data-auth': a.id });
    for (const value of [checkbox, identity, status, ...information.map(([, value]) => value), actions]) {
      const cell = element('td');
      cell.append(value);
      row.append(cell);
    }
    return row;
  }
  const card = element('article', null, { class: 'panel auth-card', 'data-auth': a.id });
  const heading = element('div', null, { class: 'auth-heading' });
  heading.append(checkbox, icon('file'), identity, status);
  const details = element('dl', null, { class: 'auth-details' });
  for (const [label, value] of information) {
    const detail = element('div');
    const description = element('dd');
    description.append(value);
    detail.append(element('dt', label), description);
    details.append(detail);
  }
  card.append(heading, details, actions);
  return card;
}
function renderAuth() {
  if (!view) return;
  hideDetectionTooltip();
  if (detailsDialog.open) renderAuthDetails();
  const valid = new Set(view.auths.map(a => a.id));
  for (const id of selected) if (!valid.has(id)) selected.delete(id);
  const auths = filteredAuths();
  const checkbox = byId('select-visible');
  const visibleSelected = auths.filter(a => selected.has(a.id)).length;
  checkbox.disabled = !auths.length;
  checkbox.checked = auths.length > 0 && visibleSelected === auths.length;
  checkbox.indeterminate = visibleSelected > 0 && !checkbox.checked;
  byId('auth-count').textContent = '显示 ' + auths.length + ' / ' + view.auths.length + ' 项认证';
  updateBatchActions();

  const active = document.activeElement;
  const activeCredential = active?.closest('[data-auth]');
  byId('auth-cards').hidden = authLayout !== 'cards' || !auths.length;
  byId('auth-table').hidden = authLayout !== 'table' || !auths.length;
  const target = byId(authLayout === 'cards' ? 'auth-cards' : 'auth-rows');
  const recordsByAuth = new Map();
  for (const row of view.history) {
    if (!recordsByAuth.has(row.auth_id)) recordsByAuth.set(row.auth_id, []);
    recordsByAuth.get(row.auth_id).push(row);
  }
  byId(authLayout === 'cards' ? 'auth-rows' : 'auth-cards').replaceChildren();
  target.replaceChildren(...auths.map(auth => credential(auth, recordsByAuth.get(auth.id))));
  if (activeCredential && active.dataset.control) {
    const item = target.querySelector('[data-auth="' + CSS.escape(activeCredential.dataset.auth) + '"]');
    const control = item?.querySelector('[data-control="' + active.dataset.control + '"]:not(:disabled)');
    (control || byId('auth-search')).focus({ preventScroll: true });
  }
  showEmpty('auth', auths, view.auths.length);
}

const detailsDialog = byId('details-dialog');
let detailsAuthId;
function renderAuthDetails() {
  const auth = view.auths.find(item => item.id === detailsAuthId);
  if (!auth) {
    detailsDialog.close();
    return false;
  }
  byId('details-name').textContent = auth.name;
  const rows = [];
  if (auth.trigger?.at) {
    rows.push(['触发原因', translate(auth.trigger.reason)], ['触发时间', localTime(auth.trigger.at)]);
  }
  if (auth.abnormal?.confirmed_at) rows.push(['确认时间', localTime(auth.abnormal.confirmed_at)]);
  if (!auth.running && auth.next_probe && auth.pending !== 'recheck') {
    rows.push(['下次检测', localTime(auth.next_probe)]);
  } else if (!auth.running && auth.next_recheck) {
    rows.push(['下次复检', localTime(auth.next_recheck)]);
  }
  byId('auth-detail-rows').replaceChildren(...rows.flatMap(([label, value]) => [element('dt', label), element('dd', value)]));
  byId('auth-detail-empty').hidden = rows.length > 0;
  return true;
}
function showAuthDetails(id) {
  detailsAuthId = id;
  if (renderAuthDetails()) detailsDialog.showModal();
}
byId('close-details').onclick = () => detailsDialog.close();
detailsDialog.addEventListener('close', () => {
  const trigger = document.querySelector('[data-auth="' + CSS.escape(detailsAuthId) + '"] [data-control="details"]');
  (trigger || byId('auth-search')).focus({ preventScroll: true });
});
for (const button of document.querySelectorAll('[data-layout]')) {
  button.onclick = () => {
    authLayout = button.dataset.layout;
    for (const peer of document.querySelectorAll('[data-layout]')) {
      peer.setAttribute('aria-pressed', String(peer === button));
    }
    renderAuth();
  };
}
byId('auth-search').oninput = renderAuth;
byId('auth-filter').onchange = renderAuth;
byId('select-visible').onchange = event => setSelection(filteredAuths(), event.target.checked);
byId('clear-selection').onclick = () => {
  selected.clear();
  renderAuth();
  byId('auth-search').focus();
};

function renderHistory() {
  if (!view) return;
  const target = byId('history-rows');
  const query = byId('history-search').value.trim().toLowerCase();
  const filter = byId('history-filter').value;
  const history = view.history.filter(row => (!filter || row.result.status === filter) &&
    [row.name, row.auth_id, row.model, row.expected, identifiedModel(row.result), translate(row.action)]
      .join(' ').toLowerCase().includes(query));
  const rows = history.map(row => {
    const tr = element('tr');
    for (const value of [localTime(row.at), row.name, translate(row.trigger.reason), row.model + ' / ' + row.expected,
      identifiedModel(row.result), resultBadge(row.result.status), numberText(row.result.probability),
      (row.duration_ms / 1000).toFixed(2) + ' 秒', translate(row.action)]) {
      const cell = element('td');
      cell.append(value);
      tr.append(cell);
    }
    return tr;
  });
  target.replaceChildren(...rows);
  byId('history-table').hidden = !rows.length;
  byId('history-count').textContent = '显示 ' + rows.length + ' / ' + view.history.length + ' 条记录';
  showEmpty('history', rows, view.history.length);
}
byId('history-search').oninput = renderHistory;
byId('history-filter').onchange = renderHistory;

function updateBatchActions() {
  const tooMany = selected.size > maxBatchSize;
  byId('batch-actions').hidden = !selected.size;
  const count = '已选 ' + selected.size + ' 项' + (tooMany ? ' · 每次最多 ' + maxBatchSize + ' 项' : '');
  const label = byId('selected-count');
  if (label.textContent !== count) label.textContent = count;
  for (const id of ['batch-on', 'batch-off', 'batch-check']) byId(id).disabled = busy || tooMany;
}
function syncWriteControls() {
  updateSettingsState();
  updateBatchActions();
  for (const id of ['reload-settings', 'save-auth', 'close-dialog']) byId(id).disabled = busy;
  byId('settings-fields').inert = busy;
  byId('auth-fields').inert = busy;
}
function formError(id, text = '') {
  const line = byId(id);
  line.hidden = !text;
  line.textContent = text;
}
async function perform(write, { errorId, applied } = {}) {
  if (busy || !view) return;
  busy = true;
  syncWriteControls();
  if (errorId) formError(errorId);
  if (errorId !== 'auth-error') message('正在处理…');
  try {
    const result = await write();
    let refreshed = false;
    try {
      await refreshLatest();
      refreshed = true;
    } catch {
      // The write and subsequent state fetch have separate outcomes.
    }
    applied?.(refreshed);
    message(result.text + (refreshed ? '' : '。状态刷新失败，稍后会自动重试。'), result.failed || !refreshed);
  } catch (error) {
    if (errorId) {
      formError(errorId, error.message);
      message('');
    } else message(error.message, true);
  } finally {
    busy = false;
    syncWriteControls();
  }
}
const confirmation = byId('confirm-dialog');
let resolveConfirmation = null;
function closeConfirmation(confirmed) {
  if (!confirmation.open) return;
  confirmation.close();
  resolveConfirmation?.(confirmed);
  resolveConfirmation = null;
}
byId('confirm-cancel').onclick = () => closeConfirmation(false);
byId('confirm-submit').onclick = () => closeConfirmation(true);
confirmation.addEventListener('cancel', event => {
  event.preventDefault();
  closeConfirmation(false);
});
function confirmAction(title, detail) {
  if (confirmation.open) return Promise.resolve(false);
  byId('confirm-title').textContent = title;
  byId('confirm-detail').textContent = detail;
  byId('confirm-submit').textContent = title;
  confirmation.showModal();
  return new Promise(resolve => { resolveConfirmation = resolve; });
}
const actionLabels = {
  check: ['发起检测', '检测任务已受理'],
  cancel: ['取消检测', '已取消检测'],
  isolate: ['隔离认证', '已隔离认证'],
  release: ['解除隔离', '已解除插件隔离'],
};
async function action(name, ids, confirm = false) {
  if (busy || !view || !ids.length || ids.length > maxBatchSize) return;
  const [title, success] = actionLabels[name];
  const detail = ids.length === 1 ? (view.auths.find(a => a.id === ids[0])?.name || '这项认证') : ids.length + ' 项选中的认证';
  if (confirm && !await confirmAction(title, '对 ' + detail + '执行此操作？')) return;
  await perform(async () => {
    const { results } = await api('/action', 'POST', { action: name, ids });
    const failures = Object.values(results).filter(Boolean);
    if (!failures.length) return { text: success };
    return { text: '成功 ' + (ids.length - failures.length) + ' 项，失败 ' + failures.length + ' 项。' + [...new Set(failures)].join('、'), failed: true };
  });
}
async function bulkEnabled(value) {
  const ids = [...selected];
  if (busy || !view || !ids.length || ids.length > maxBatchSize) return;
  const title = value ? '启用检测' : '关闭检测';
  if (!await confirmAction(title, '更新 ' + ids.length + ' 项选中认证的检测设置？')) return;
  await perform(async () => {
    const auths = Object.fromEntries(ids.map(id => [id, { ...view.config.auths?.[id], enabled: value }]));
    await api('/auth-settings', 'PUT', { revision: view.revision, auths });
    return { text: '批量设置已保存' };
  });
}
byId('batch-on').onclick = () => bulkEnabled(true);
byId('batch-off').onclick = () => bulkEnabled(false);
byId('batch-check').onclick = () => action('check', [...selected], true);

const policyFields = {
  enabled: ['检测开关', 'bool'], idle: ['定时空闲检测', 'bool'], trigger: ['上游异常触发', 'bool'],
  model: ['测试模型', 'text'], expected: ['预期指纹模型', 'model'],
};
const settingsGroups = {
  '基本设置': {
    enabled: ['全局检测', 'bool'], history_limit: ['历史最大保留条数', 'number'],
  },
  '扫描与复检': {
    scan_seconds: ['扫描周期（秒）', 'number'], idle_seconds: ['空闲阈值（秒）', 'number'],
    interval_seconds: ['最短检测间隔（秒）', 'number'], mismatch_recheck_seconds: ['不一致复检间隔（秒）', 'number'],
    gateway_recheck_seconds: ['业务异常恢复复检间隔（秒）', 'number'],
    timeout_seconds: ['单次挑战超时（秒）', 'number'], jitter_seconds: ['最大抖动（秒）', 'number'],
  },
  '异常触发': {
    dedupe_seconds: ['事件去重窗口（秒）', 'number'], trigger_count: ['触发事件数量', 'number'],
    http_statuses: ['HTTP 错误状态码', 'json'], error_codes: ['结构化错误代码', 'json'],
    error_texts: ['错误文本片段', 'json'],
  },
  '判定与隔离': {
    min_probability: ['参考库内最小校准概率', 'number'], confirm_rounds: ['连续不一致确认轮数', 'number'],
  },
  '并发与重试': {
    parallel_challenges: ['并行执行三道挑战', 'bool'],
    max_concurrent: ['全局最大检测并发', 'number'], per_provider: ['单提供商最大检测并发', 'number'],
    retry_seconds: ['首次重试间隔（秒）', 'number'], max_retry_seconds: ['最大退避间隔（秒）', 'number'],
    max_retries: ['最大重试次数', 'number'],
    overload_limit: ['过载保护触发次数', 'number'], overload_pause_seconds: ['过载暂停时间（秒）', 'number'],
  },
  '模型与提供商': {
    prefer_failed_model: ['优先检测已映射的异常模型', 'bool'], expected_models: ['请求模型到预期模型映射', 'json'],
    providers: ['提供商覆盖设置', 'json'],
  },
};
const settingHelp = {
  enabled: '控制检测和复检任务。全局关闭后保留当前隔离状态。',
  idle: '认证无活跃业务且达到空闲阈值时，安排例行检测。',
  trigger: '业务错误达到触发条件时，隔离该认证并安排检测。',
  model: '传给 CPA 的请求模型名，可填写该认证支持的模型别名。',
  expected: '用于比较指纹的参考库模型 ID。',
  history_limit: '所有认证共用的保留上限。认证管理按仍保留的记录统计。',
  scan_seconds: '检查空闲认证和到期的不一致复检的周期。',
  idle_seconds: '距离该认证最后一次业务活动的最短等待时间。',
  interval_seconds: '同一认证两次常规空闲检测之间的最短间隔。',
  mismatch_recheck_seconds: '使用确认时的模型与预期指纹复检。默认两天。',
  gateway_recheck_seconds: '连续遇到 502 或 503 并用完短重试后，定期复检同一业务模型。默认一小时，有 CPA 冷却时需等冷却结束。',
  timeout_seconds: '每道随机数挑战的最长结果等待时间。',
  jitter_seconds: '空闲检测和短重试随机增加的最多秒数，用于错开请求。',
  dedupe_seconds: '窗口内，同一认证的同类重复上游事件只计数一次。',
  trigger_count: '去重后达到此数量，才隔离认证并创建诊断任务。',
  http_statuses: '匹配的 HTTP 状态码，填写 JSON 数字数组，例如 [502, 503]。',
  error_codes: '匹配的上游错误代码，填写 JSON 字符串数组。',
  error_texts: '匹配上游错误文本中包含的片段，填写 JSON 字符串数组。',
  min_probability: '三道挑战有效后，识别结果还须达到此概率才会判定一致或不一致。',
  confirm_rounds: '同一模型和同一版参考库连续判定不一致达到此轮数，才确认隔离。',
  parallel_challenges: '开启时将同一轮的三道随机数挑战同时交给 CPA。默认逐道提交。',
  max_concurrent: '所有提供商同时运行的最大检测轮数，每轮包含三道挑战。',
  per_provider: '同一提供商同时运行的最大检测轮数。',
  retry_seconds: '首次短重试的退避基础间隔。',
  max_retry_seconds: '指数退避的上限，随机抖动另计。',
  max_retries: '首次检测之后允许的短重试次数。等候 CPA 冷却不计入。',
  overload_limit: '全局或提供商达到连续过载轮数后，暂停该范围的检测。',
  overload_pause_seconds: '触发过载保护后，新检测暂停的时长。',
  prefer_failed_model: '业务触发检测时，优先使用已有预期指纹映射的故障模型。',
  expected_models: '填写以请求模型为键、参考库模型 ID 为值的 JSON 对象。',
  providers: '填写以提供商名称为键的 JSON 对象。单认证设置有更高优先级。',
};
let fieldSequence = 0;
function field(container, name, spec, value, inherit = false) {
  const [label, type] = spec;
  const id = 'setting-' + ++fieldSequence;
  const tipId = id + '-help';
  const wrapper = element('div', null, { class: 'field' });
  const title = element('div', null, { class: 'field-title' });
  const tip = element('button', null, {
    class: 'field-tip ghost', type: 'button', 'aria-label': label + '说明', 'aria-describedby': tipId,
  });
  tip.append(icon('info'));
  const description = name === 'enabled' && container.id === 'auth-fields'
    ? '控制该认证是否参与检测。全局开启时才有效。' : settingHelp[name];
  title.append(element('label', label, { for: id }), tip,
    element('span', description, { class: 'field-tooltip', role: 'tooltip', id: tipId }));
  let input;
  if (type === 'bool') {
    input = element('select');
    const choices = [['true', '开启'], ['false', '关闭']];
    if (inherit) choices.unshift(['', '继承']);
    for (const [v, text] of choices) input.append(element('option', text, { value: v }));
    input.value = value == null ? '' : String(value);
  } else if (type === 'json') {
    input = element('textarea', null, { rows: 4, spellcheck: 'false' });
    input.value = JSON.stringify(value ?? {}, null, 2);
    wrapper.classList.add('wide');
  } else {
    input = element('input', null, { type: type === 'number' ? 'number' : 'text' });
    input.value = value ?? '';
    if (type === 'model') input.setAttribute('list', 'reference-models');
    if (type === 'number') {
      input.step = name === 'min_probability' ? 'any' : '1';
      input.required = true;
    }
    if (inherit) input.placeholder = '留空继承';
  }
  input.id = id;
  input.name = name;
  input.dataset.type = type;
  input.setAttribute('aria-describedby', tipId);
  input.autofocus = inherit && name === 'enabled';
  tip.onkeydown = event => {
    if (event.key !== 'Escape') return;
    event.preventDefault();
    event.stopPropagation();
    input.focus({ preventScroll: true });
  };
  wrapper.append(title, input);
  container.append(wrapper);
}
function collect(container, inherit = false) {
  const result = {};
  for (const input of container.querySelectorAll(':scope > .field > [name]')) {
    const { name, value } = input;
    if (inherit && !value.trim()) continue;
    try {
      switch (input.dataset.type) {
        case 'bool': result[name] = value === 'true'; break;
        case 'number': result[name] = Number(value); break;
        case 'json': result[name] = JSON.parse(value); break;
        default: result[name] = value.trim();
      }
    } catch {
      throw new Error(input.labels[0].textContent + '的 JSON 格式有误。');
    }
  }
  return result;
}
function settingsGroup(title, specs, values) {
  const group = element('fieldset', null, { class: 'settings-group panel' });
  group.append(element('legend', title));
  const fields = element('div', null, { class: 'fields' });
  for (const [name, spec] of Object.entries(specs)) field(fields, name, spec, values[name]);
  group.append(fields);
  return group;
}
function settingsSnapshot() {
  const fields = byId('settings-form').querySelectorAll('[name]');
  return JSON.stringify([...fields].map(input => input.value));
}
function settingsDirty() {
  return settingsBaseline !== null && settingsSnapshot() !== settingsBaseline;
}
function updateSettingsState() {
  const dirty = settingsDirty();
  const conflict = dirty && view?.revision !== settingsRevision;
  const text = conflict ? '配置已更新，请重新载入' : dirty ? '有未保存的更改' : '';
  const status = byId('settings-state');
  if (status.textContent !== text) status.textContent = text;
  byId('save-settings').disabled = busy || !dirty || conflict;
}
function drawSettings() {
  if (!view) return;
  settingsRevision = view.revision;
  const container = byId('settings-fields');
  const defaults = settingsGroup('默认认证设置', policyFields, view.config.default);
  defaults.querySelector('.fields').id = 'default-fields';
  const [general, ...groups] = Object.entries(settingsGroups).map(([title, specs]) => {
    const group = settingsGroup(title, specs, view.config);
    group.querySelector('.fields').setAttribute('data-global-fields', '');
    return group;
  });
  container.replaceChildren(general, defaults, ...groups);
  settingsBaseline = settingsSnapshot();
  formError('settings-error');
  updateSettingsState();
}
byId('settings-form').oninput = () => {
  formError('settings-error');
  updateSettingsState();
};
byId('reload-settings').onclick = async () => {
  if (!view || busy) return;
  if (settingsDirty() && !await confirmAction('重新载入', '放弃未保存的更改并载入当前配置？')) return;
  if (!view || busy) return;
  busy = true;
  syncWriteControls();
  try {
    await refreshLatest();
    drawSettings();
    message('已重新载入设置');
  } catch (error) {
    formError('settings-error', error.message);
  } finally {
    busy = false;
    syncWriteControls();
  }
};
byId('settings-form').onsubmit = event => {
  event.preventDefault();
  if (!settingsDirty() || byId('save-settings').disabled) return;
  perform(async () => {
    const groups = document.querySelectorAll('[data-global-fields]');
    const settings = Object.assign({}, ...[...groups].map(group => collect(group)));
    settings.default = collect(byId('default-fields'));
    settings.auths = view.config.auths;
    await api('/settings', 'PUT', { revision: settingsRevision, settings });
    return { text: '全局设置已应用' };
  }, { errorId: 'settings-error', applied: refreshed => { if (refreshed) drawSettings(); } });
};
const authDialog = byId('auth-dialog');
function editAuth(a) {
  if (busy) return;
  editing = { id: a.id, revision: view.revision };
  byId('auth-name').textContent = a.name;
  formError('auth-error');
  const container = byId('auth-fields');
  container.replaceChildren();
  for (const [name, spec] of Object.entries(policyFields)) field(container, name, spec, view.config.auths?.[a.id]?.[name], true);
  authDialog.showModal();
}
byId('close-dialog').onclick = () => authDialog.close();
authDialog.addEventListener('cancel', event => {
  if (busy) event.preventDefault();
});
authDialog.addEventListener('close', () => {
  if (!view || !editing) return;
  const trigger = document.querySelector('[data-auth="' + CSS.escape(editing.id) + '"] [data-control="settings"]');
  (trigger || byId('auth-search')).focus({ preventScroll: true });
  editing = null;
});
byId('auth-form').onsubmit = event => {
  event.preventDefault();
  if (!editing) return;
  perform(async () => {
    const auths = { [editing.id]: collect(byId('auth-fields'), true) };
    await api('/auth-settings', 'PUT', { revision: editing.revision, auths });
    return { text: '认证设置已保存' };
  }, { errorId: 'auth-error', applied: () => authDialog.close() });
};

function tryPanelLogin() {
  const managementKey = rememberedPanelKey();
  if (managementKey) void connect(managementKey, true);
}
tryPanelLogin();
