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
  held_by_policy: '保持隔离', host_mutation_unavailable: '保持隔离，宿主写入接口不可用',
  persistence_failed: '状态写入失败', host_write_failed: '宿主写入失败',
  held_unsupported: '不支持检测，等待人工', retries_exhausted: '重试耗尽',
  retry_scheduled: '等待重试',
};
const translate = value => translations[value] || value || '—';
const localTime = value => value ? new Date(value).toLocaleString() : '—';
const numberText = value => value == null ? '—' : value.toFixed(3);
let key = '';
let view = null;
let settingsRevision = 0;
let editing = null;
let selected = new Set();
let refreshInProgress = false;
let session = 0;
let lastRender = '';

function element(tag, text, attributes = {}) {
  const node = document.createElement(tag);
  if (text != null) node.textContent = text;
  for (const [name, value] of Object.entries(attributes)) node.setAttribute(name, value);
  return node;
}
function message(text, bad = false) {
  const node = byId('notice');
  node.hidden = !text;
  node.className = bad ? 'error' : '';
  node.textContent = text;
}
async function api(path, method = 'GET', body) {
  const headers = { Authorization: 'Bearer ' + key };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const response = await fetch(apiBase + path, {
    method, headers, credentials: 'omit', cache: 'no-store', redirect: 'error',
    signal: AbortSignal.timeout(15000),
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (response.status === 401 || response.status === 403) throw new Error('管理密钥无效或宿主禁止访问。');
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || '管理接口请求失败。');
  return data;
}
async function refresh() {
  if (!key || refreshInProgress) return;
  refreshInProgress = true;
  const requestedSession = session;
  try {
    const next = await api('/state');
    if (requestedSession !== session) return;
    const serialized = JSON.stringify(next);
    view = next;
    byId('login').hidden = true;
    byId('logout').hidden = false;
    byId('workspace').hidden = false;
    if (serialized !== lastRender) {
      lastRender = serialized;
      render();
    }
  } finally {
    refreshInProgress = false;
  }
}
byId('login').addEventListener('submit', async event => {
  event.preventDefault();
  key = byId('key').value.trim();
  byId('key').value = '';
  message('正在连接…');
  try {
    await refresh();
    drawSettings();
    message('');
  } catch (error) {
    key = '';
    message(error.message, true);
  }
});
byId('logout').onclick = () => {
  session++;
  key = '';
  view = null;
  selected.clear();
  lastRender = '';
  byId('workspace').hidden = true;
  byId('logout').hidden = true;
  byId('login').hidden = false;
  byId('auth-dialog').close();
  for (const id of ['auth-rows', 'history-rows', 'recent', 'settings-fields', 'metrics', 'auth-fields']) {
    byId(id).replaceChildren();
  }
  message('');
};
window.setInterval(() => {
  if (key && view && !document.hidden) refresh().catch(error => message(error.message, true));
}, 3000);
for (const tab of document.querySelectorAll('nav button')) {
  tab.onclick = () => {
    for (const peer of document.querySelectorAll('nav button')) {
      byId(peer.dataset.tab).hidden = peer !== tab;
      if (peer === tab) peer.setAttribute('aria-current', 'page');
      else peer.removeAttribute('aria-current');
    }
  };
}
function stateName(a) {
  if (a.disabled) return 'disabled';
  if (a.isolated) return 'isolated';
  if (a.cooling) return 'cooling';
  return 'normal';
}
function render() {
  const auths = view.auths;
  const metrics = {
    '认证文件': auths.length, '启用检测': auths.filter(a => a.policy.enabled).length,
    '正常调度': auths.filter(a => stateName(a) === 'normal').length,
    '隔离': auths.filter(a => a.isolated && !a.disabled).length,
    '检测中': auths.filter(a => a.running).length,
    '插件停用': auths.filter(a => a.abnormal?.plugin_disabled && a.disabled).length,
    '待检测': auths.filter(a => a.pending && !a.running).length,
    '待人工处理': auths.filter(a => a.held && !a.disabled && !a.next_recheck).length,
  };
  byId('metrics').replaceChildren(...Object.entries(metrics).map(([label, value]) => {
    const card = element('div', null, { class: 'metric' });
    card.append(element('span', label), element('strong', value));
    return card;
  }));
  const warnings = [];
  if (view.reference) {
    const reference = view.reference;
    warnings.push('参考库构建时间 ' + localTime(reference.built_at));
    if (reference.last_check_failed) warnings.push('参考库更新失败，保留当前版本。');
  }
  if (!view.can_mutate) warnings.push('当前宿主会保留已确认异常的隔离状态，永久停用由管理员处理。');
  if (view.storage_error) warnings.push('持久化失败，请检查状态目录权限和磁盘空间。');
  if (view.inventory_error) warnings.push('认证清单读取失败，检测已暂停。');
  if (view.overload_until) warnings.push('全局过载保护至 ' + localTime(view.overload_until));
  byId('health').textContent = warnings.join(' ');
  const recent = auths.filter(a => a.trigger?.at).sort((a, b) => b.trigger.at.localeCompare(a.trigger.at)).slice(0, 6);
  byId('recent').replaceChildren(...(recent.length ? recent.map(a => element('p',
    [localTime(a.trigger.at), a.name, translate(a.trigger.reason), a.trigger.http_status || '', a.trigger.error_code || ''].filter(Boolean).join(' · ')))
    : [element('p', '暂无异常')]));
  byId('reference-models').replaceChildren(...view.models.map(name => element('option', null, { value: name })));
  renderAuth();
  renderHistory();
}
function emptyRow(target, count, text) {
  const row = element('tr');
  row.append(element('td', text, { colspan: count, class: 'empty' }));
  target.append(row);
}
function actionButton(text, fn, disabled = false) {
  const button = element('button', text, { type: 'button' });
  button.disabled = disabled;
  button.onclick = fn;
  return button;
}
function filteredAuths() {
  const query = byId('auth-search').value.toLowerCase();
  const filter = byId('auth-filter').value;
  return view.auths.filter(a => (!filter || stateName(a) === filter) &&
    [a.name, a.id, a.provider, a.policy.model, a.policy.expected, a.last_result?.detected].join(' ').toLowerCase().includes(query));
}
function renderAuth() {
  if (!view) return;
  const target = byId('auth-rows');
  const auths = filteredAuths();
  byId('select-visible').checked = auths.length > 0 && auths.every(a => selected.has(a.id));
  byId('select-visible').indeterminate = auths.some(a => selected.has(a.id)) && !byId('select-visible').checked;
  target.replaceChildren();
  for (const a of auths) {
    const row = element('tr');
    const checkbox = element('input', null, { type: 'checkbox', 'aria-label': '选择 ' + a.name });
    checkbox.checked = selected.has(a.id);
    checkbox.onchange = () => {
      if (checkbox.checked) selected.add(a.id); else selected.delete(a.id);
      renderAuth();
    };
    const selector = element('td');
    selector.append(checkbox);
    const authName = element('td');
    authName.append(element('strong', a.name), element('small', a.provider));
    const result = element('td');
    result.append(element('span', translate(a.last_result?.status)));
    if (a.trigger?.at) result.append(element('small', translate(a.trigger.reason) + ' · ' + localTime(a.trigger.at)));
    if (a.abnormal?.confirmed_at) result.append(element('small', '确认 ' + localTime(a.abnormal.confirmed_at)));
    if (a.next_recheck && !a.running) result.append(element('small', '下次复检 ' + localTime(a.next_recheck)));
    const actions = element('td', null, { class: 'row-actions' });
    actions.append(
      actionButton('设置', () => editAuth(a)),
      actionButton('检测', () => action('check', [a.id]), a.disabled || !a.policy.enabled || !a.probeable || a.running),
      a.isolated
        ? actionButton('解除隔离', () => action('release', [a.id], true), a.abnormal?.plugin_disabled)
        : actionButton('隔离', () => action('isolate', [a.id], true), a.disabled),
    );
    if (view.can_mutate && a.abnormal?.plugin_disabled && a.disabled) {
      actions.append(actionButton('恢复认证', () => action('recover', [a.id], true)));
    }
    const models = element('td');
    const expected = a.last_expected || a.policy.expected || view.config.expected_models?.[a.policy.model] || a.policy.model;
    models.append(element('span', expected || '—'), element('small', a.last_result?.detected || '—'));
    const status = element('td');
    const heldLabel = a.next_recheck ? ' · 待复检' : ' · 待人工';
    status.append(element('span', translate(stateName(a)), { class: 'badge ' + stateName(a) }),
      element('small', (a.policy.enabled ? '检测开启' : '检测关闭') + (a.running ? ' · 检测中' : a.held ? heldLabel : !a.probeable ? ' · 诊断不可用' : '')));
    row.append(selector, authName, status, element('td', localTime(a.last_business)),
      element('td', localTime(a.last_check)), models, result, actions);
    target.append(row);
  }
  if (!auths.length) emptyRow(target, 8, '没有符合条件的认证文件');
}
byId('auth-search').oninput = renderAuth;
byId('auth-filter').onchange = renderAuth;
byId('select-visible').onchange = event => {
  for (const a of filteredAuths()) {
    if (event.target.checked) selected.add(a.id); else selected.delete(a.id);
  }
  renderAuth();
};
function renderHistory() {
  if (!view) return;
  const target = byId('history-rows');
  const query = byId('history-search').value.toLowerCase();
  const filter = byId('history-filter').value;
  target.replaceChildren();
  for (const row of view.history) {
    if (filter && row.result.status !== filter) continue;
    if (![row.name, row.auth_id, row.model, row.expected, row.result.detected, translate(row.action)]
      .join(' ').toLowerCase().includes(query)) continue;
    const tr = element('tr');
    for (const value of [localTime(row.at), row.name, translate(row.trigger.reason), row.model + ' / ' + row.expected,
      row.result.detected || '—', translate(row.result.status), numberText(row.result.score) + ' / ' + numberText(row.result.probability),
      (row.duration_ms / 1000).toFixed(2) + ' 秒', translate(row.action)]) tr.append(element('td', value));
    target.append(tr);
  }
  if (!target.children.length) emptyRow(target, 9, '没有符合条件的检测记录');
}
byId('history-search').oninput = renderHistory;
byId('history-filter').onchange = renderHistory;

async function perform(fn) {
  try {
    const text = await fn();
    message(text || '已保存');
    await refresh();
  } catch (error) {
    message(error.message, true);
  }
}
function action(name, ids, confirm = false) {
  if (!ids.length) return message('请先选择认证文件。', true);
  if (confirm && !window.confirm('确认对选定的 ' + ids.length + ' 个认证执行此操作？')) return;
  perform(async () => {
    const { results } = await api('/action', 'POST', { action: name, ids });
    const failures = Object.values(results).filter(Boolean);
    if (failures.length) throw new Error('已受理 ' + (ids.length - failures.length) + ' 项。失败：' + [...new Set(failures)].join('；'));
    return name === 'check' ? '检测任务已受理' : '操作已保存';
  });
}
function bulkEnabled(value) {
  const ids = [...selected];
  if (!ids.length) return message('请先选择认证文件。', true);
  if (!window.confirm('确认更新 ' + ids.length + ' 个认证？')) return;
  const auths = Object.fromEntries(ids.map(id => [id, { ...view.config.auths?.[id], enabled: value }]));
  perform(() => api('/auth-settings', 'PUT', { revision: view.revision, auths }).then(() => '批量设置已保存'));
}
byId('batch-on').onclick = () => bulkEnabled(true);
byId('batch-off').onclick = () => bulkEnabled(false);
byId('batch-check').onclick = () => action('check', [...selected], true);

const policyFields = {
  enabled: ['检测开关', 'bool'], idle: ['定时空闲检测', 'bool'], trigger: ['上游异常触发', 'bool'],
  model: ['测试模型', 'text'], expected: ['预期指纹模型', 'model'],
};
const settingsFields = {
  enabled: ['全局检测', 'bool'], prefer_failed_model: ['优先检测已映射的异常模型', 'bool'],
  scan_seconds: ['扫描周期（秒）', 'number'], idle_seconds: ['空闲阈值（秒）', 'number'],
  interval_seconds: ['最短检测间隔（秒）', 'number'], mismatch_recheck_seconds: ['不一致复检间隔（秒）', 'number'],
  timeout_seconds: ['单次挑战超时（秒）', 'number'],
  jitter_seconds: ['最大抖动（秒）', 'number'], dedupe_seconds: ['事件去重窗口（秒）', 'number'],
  trigger_count: ['触发事件数量', 'number'], http_statuses: ['HTTP 错误状态码', 'json'],
  error_codes: ['结构化错误代码', 'json'], error_texts: ['错误文本片段', 'json'],
  min_probability: ['参考库内最小校准概率', 'number'], confirm_rounds: ['连续不一致确认轮数', 'number'],
  auto_disable: ['确认后自动停用', 'bool'], max_concurrent: ['全局最大检测并发', 'number'],
  per_provider: ['单提供商最大检测并发', 'number'], retry_seconds: ['首次重试间隔（秒）', 'number'],
  max_retry_seconds: ['最大退避间隔（秒）', 'number'], max_retries: ['最大重试次数', 'number'],
  max_isolation_seconds: ['自动隔离期限（秒）', 'number'], expiry: ['隔离期限到期策略', 'expiry'],
  overload_limit: ['过载保护触发次数', 'number'], overload_pause_seconds: ['过载暂停时间（秒）', 'number'],
  history_limit: ['历史最大保留条数', 'number'], expected_models: ['请求模型到预期模型映射', 'json'],
  providers: ['提供商覆盖设置', 'json'],
};
function field(container, name, spec, value, inherit = false) {
  const [label, type] = spec;
  const wrapper = element('label', label);
  let input;
  if (type === 'bool' || type === 'expiry') {
    input = element('select');
    const choices = type === 'expiry' ? [['hold', '等待人工'], ['release', '到期解除']] : [['true', '开启'], ['false', '关闭']];
    if (inherit) choices.unshift(['', '继承']);
    for (const [v, text] of choices) input.append(element('option', text, { value: v }));
    input.value = value == null ? '' : String(value);
  } else if (type === 'json') {
    input = element('textarea', null, { rows: 4, spellcheck: 'false' });
    input.value = JSON.stringify(value ?? {}, null, 2);
    wrapper.className = 'wide';
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
  if (name === 'auto_disable' && !view.can_mutate) {
    input.disabled = true;
    wrapper.append(element('small', '当前宿主缺少原子认证修改接口'));
  }
  input.name = name;
  input.dataset.type = type;
  wrapper.append(input);
  container.append(wrapper);
}
function collect(container, inherit = false) {
  const result = {};
  for (const input of container.querySelectorAll(':scope > label [name]')) {
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
      throw new Error(input.closest('label').childNodes[0].textContent + '的 JSON 格式有误。');
    }
  }
  return result;
}
function drawSettings() {
  if (!view) return;
  settingsRevision = view.revision;
  const container = byId('settings-fields');
  container.replaceChildren();
  for (const [name, spec] of Object.entries(settingsFields)) field(container, name, spec, view.config[name]);
  const defaults = element('fieldset', null, { class: 'wide fields', id: 'default-fields' });
  defaults.append(element('legend', '默认认证设置'));
  for (const [name, spec] of Object.entries(policyFields)) field(defaults, name, spec, view.config.default[name]);
  container.append(defaults);
}
byId('reload-settings').onclick = drawSettings;
byId('settings-form').onsubmit = event => {
  event.preventDefault();
  perform(async () => {
    const container = byId('settings-fields');
    const settings = collect(container);
    settings.default = collect(byId('default-fields'));
    settings.enabled = container.querySelector('select[name="enabled"]').value === 'true';
    settings.auths = view.config.auths;
    await api('/settings', 'PUT', { revision: settingsRevision, settings });
    await refresh();
    drawSettings();
    return '全局设置已应用';
  });
};
function editAuth(a) {
  editing = { id: a.id, revision: view.revision };
  byId('auth-name').textContent = a.name;
  const container = byId('auth-fields');
  container.replaceChildren();
  for (const [name, spec] of Object.entries(policyFields)) field(container, name, spec, view.config.auths?.[a.id]?.[name], true);
  byId('auth-dialog').showModal();
}
byId('close-dialog').onclick = () => byId('auth-dialog').close();
byId('auth-form').onsubmit = event => {
  event.preventDefault();
  perform(async () => {
    const auths = { [editing.id]: collect(byId('auth-fields'), true) };
    await api('/auth-settings', 'PUT', { revision: editing.revision, auths });
    byId('auth-dialog').close();
    return '认证设置已保存';
  });
};
