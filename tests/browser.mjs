import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';

const pluginPath = '/v0/resource/plugins/model-fingerprint-guard/index.html';
const pluginURL = process.argv[2] + pluginPath;
const fixtureKey = 'fixture-management-only';
const manualLogin = `(() => {
  document.getElementById('key').value = ${JSON.stringify(fixtureKey)};
  document.getElementById('login').requestSubmit();
})()`;

// Mirror the v1.29.1 panel's remembered Zustand record using fixture credentials.
function panelRecord(host, state) {
  const mask = Buffer.from('cli-proxy-api-webui::secure-storage|' + host);
  const bytes = Buffer.from(JSON.stringify({ state, version: 0 }));
  return 'enc::v2::' + bytes.map((byte, i) => byte ^ mask[i % mask.length]).toString('base64');
}
const profile = await mkdtemp(join(tmpdir(), 'mfg-browser-'));
const chrome = spawn(process.env.MFG_CHROMIUM || 'chromium', [
  '--headless', '--no-sandbox', '--no-first-run', '--disable-background-networking',
  '--remote-debugging-port=0', '--user-data-dir=' + profile, 'about:blank',
], { stdio: 'ignore' });
chrome.on('error', error => console.error(error.message));
const exit = new Promise(resolve => chrome.once('close', resolve));

async function until(check) {
  for (let attempt = 0; attempt < 75; attempt++) {
    const result = await check();
    if (result) return result;
    await sleep(150);
  }
  assert.fail('Timed out waiting for the browser flow');
}

try {
  const port = await until(async () => {
    try {
      return (await readFile(join(profile, 'DevToolsActivePort'), 'utf8')).split('\n')[0];
    } catch {
      return '';
    }
  });
  const tabs = await fetch('http://127.0.0.1:' + port + '/json/list').then(response => response.json());
  const socket = new WebSocket(tabs.find(tab => tab.type === 'page').webSocketDebuggerUrl);
  const listeners = new Map();
  let sequence = 0;
  socket.addEventListener('message', event => {
    const data = JSON.parse(event.data);
    if (data.id && listeners.has(data.id)) {
      const [resolve, reject] = listeners.get(data.id);
      listeners.delete(data.id);
      if (data.error) reject(new Error(data.error.message));
      else resolve(data.result);
    }
  });
  await new Promise((resolve, reject) => {
    socket.addEventListener('open', resolve, { once: true });
    socket.addEventListener('error', reject, { once: true });
  });
  function send(method, params) {
    return new Promise((resolve, reject) => {
      sequence++;
      listeners.set(sequence, [resolve, reject]);
      socket.send(JSON.stringify({ id: sequence, method, params }));
    });
  }
  async function evaluate(expression) {
    const result = await send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true });
    if (result.exceptionDetails) throw new Error(result.exceptionDetails.text);
    return result.result.value;
  }
  async function hover(selector) {
    const point = await evaluate(`(async () => {
      const target = document.querySelector(${JSON.stringify(selector)});
      target.scrollIntoView({ block: 'center', inline: 'center' });
      await new Promise(resolve => requestAnimationFrame(resolve));
      const { x, y, width, height } = target.getBoundingClientRect();
      return { x: x + width / 2, y: y + height / 2 };
    })()`);
    await send('Input.dispatchMouseEvent', { type: 'mouseMoved', ...point });
  }
  async function checkDetectionTooltip(selector) {
    await hover(selector);
    await until(() => evaluate(`(() => {
      const tooltip = document.getElementById('detection-tooltip');
      const anchor = document.querySelector(${JSON.stringify(selector)});
      const { left, right, top, bottom } = tooltip.getBoundingClientRect();
      return !tooltip.hidden && tooltip.textContent === anchor.getAttribute('aria-label')
        && /\\d{1,2}:\\d{2}:\\d{2}/.test(tooltip.textContent)
        && left >= 0 && right <= innerWidth && top >= 0 && bottom <= innerHeight;
    })()`));
    await send('Input.dispatchMouseEvent', { type: 'mouseMoved', x: 0, y: 0 });
    await until(() => evaluate('document.getElementById("detection-tooltip").hidden'));
  }
  const emulateTheme = value => send('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-color-scheme', value }] });
  await emulateTheme('light');
  await send('Emulation.setDeviceMetricsOverride', { width: 1024, height: 768, deviceScaleFactor: 1, mobile: false });
  await send('Page.navigate', { url: pluginURL });
  await until(() => evaluate('document.readyState === "complete" && !!document.querySelector("#login")'));
  assert.equal(await evaluate('getComputedStyle(document.documentElement).backgroundColor'), 'rgb(250, 249, 245)');
  const centeredLogin = `(() => {
    const { x, y, width, height } = document.getElementById('login').getBoundingClientRect();
    return width > 0 && Math.abs(x + width / 2 - innerWidth / 2) < 8
      && Math.abs(y + height / 2 - innerHeight / 2) < 8;
  })()`;
  assert(await evaluate(centeredLogin));
  await send('Emulation.setDeviceMetricsOverride', { width: 375, height: 760, deviceScaleFactor: 1, mobile: true });
  assert(await evaluate(centeredLogin));
  await send('Emulation.clearDeviceMetricsOverride');
  await evaluate(manualLogin);
  await until(() => evaluate('!document.getElementById("workspace").hidden'));
  assert(await evaluate('!document.querySelector("#refresh, #logout")'));
  assert.equal(await evaluate('document.getElementById("key").value'), '');
  assert.equal(await evaluate('document.getElementById("runtime-native").textContent'), '开启');
  assert.equal(await evaluate('document.getElementById("runtime-auto-update").textContent'), '关闭');
  assert.equal(await evaluate('document.getElementById("runtime-refresh-interval").textContent'), '暂停（已配置 24h0m0s）');
  await emulateTheme('dark');
  await until(() => evaluate('getComputedStyle(document.documentElement).backgroundColor === "rgb(21, 20, 18)"'));
  await emulateTheme('light');
  await send('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-reduced-motion', value: 'no-preference' }] });
  assert.equal(await evaluate('getComputedStyle(document.querySelector("nav"), "::before").transitionDuration'), '0.2s');
  await evaluate(`(() => {
    const overview = document.querySelector('#tab-overview');
    overview.focus();
    overview.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowRight', bubbles: true }));
  })()`);
  assert(await evaluate('document.activeElement.id === "tab-auth" && !document.getElementById("auth").hidden'));
  assert.equal(await evaluate('document.querySelector("nav").dataset.activeTab'), 'auth');
  assert.equal(await evaluate('getComputedStyle(document.getElementById("auth")).animationName'), 'reveal');
  await send('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-reduced-motion', value: 'reduce' }] });
  assert.equal(await evaluate('getComputedStyle(document.getElementById("auth")).animationName'), 'none');
  assert.equal(await evaluate('getComputedStyle(document.querySelector("nav"), "::before").transitionDuration'), '0s');
  await emulateTheme('light');
  await send('Emulation.setFocusEmulationEnabled', { enabled: true });
  await evaluate('document.querySelector("[data-tab=settings]").click()');
  assert(await evaluate('document.getElementById("save-settings").disabled'));
  const recoveryField = '.field:has([name="gateway_recheck_seconds"])';
  const recoveryTip = `getComputedStyle(document.querySelector('${recoveryField} .field-tooltip')).visibility`;
  await hover(recoveryField + ' label');
  assert.equal(await evaluate(recoveryTip), 'hidden');
  await hover(recoveryField + ' .field-tip');
  await until(async () => await evaluate(recoveryTip) === 'visible');
  const configured = await evaluate(`(() => {
    const input = document.querySelector('input[name="history_limit"]');
    const interval = document.querySelector('input[name="mismatch_recheck_seconds"]');
    const recovery = document.querySelector('input[name="gateway_recheck_seconds"]');
    const parallel = document.querySelector('select[name="parallel_challenges"]');
    if (interval?.value !== '172800' || interval.closest('fieldset').querySelector('legend').textContent !== '扫描与复检') return 'confirmed mismatch interval: ' + interval?.value;
    if (recovery?.value !== '3600' || parallel?.value !== 'true') return 'recovery interval and parallel challenges: ' + recovery?.value + ', ' + parallel?.value;
    if (document.querySelector('[name="auto_disable"], [name="max_isolation_seconds"], [name="expiry"]')) return 'retired setting is visible';
    recovery.value = 7200;
    parallel.value = 'false';
    input.value = 42;
    interval.value = 43200;
    interval.dispatchEvent(new Event('input', { bubbles: true }));
    return !document.getElementById('save-settings').disabled;
  })()`);
  assert.equal(configured, true);
  const modelMappings = await evaluate(`document.querySelector('textarea[name="expected_models"]').value`);
  await evaluate(`(() => {
    document.querySelector('textarea[name="expected_models"]').value = '{';
    document.getElementById('save-settings').click();
  })()`);
  await until(() => evaluate('!document.getElementById("settings-error").hidden && document.getElementById("settings-error").textContent.includes("JSON 格式有误")'));
  await evaluate(`(() => {
    const mappings = document.querySelector('textarea[name="expected_models"]');
    mappings.value = ${JSON.stringify(modelMappings)};
    mappings.dispatchEvent(new Event('input', { bubbles: true }));
  })()`);
  assert(await evaluate('document.getElementById("settings-error").hidden'));
  await until(() => evaluate('performance.getEntriesByType("resource").filter(entry => entry.name.endsWith("/model-fingerprint-guard/state")).length > 1'));
  assert.equal(await evaluate('document.getElementById("settings-state").textContent'), '有未保存的更改');
  await evaluate('document.getElementById("reload-settings").click()');
  assert(await evaluate('document.getElementById("confirm-dialog").open && document.getElementById("confirm-title").textContent === "重新载入"'));
  await evaluate('document.getElementById("confirm-cancel").click()');
  assert.equal(await evaluate(`document.querySelector('input[name="mismatch_recheck_seconds"]').value`), '43200');
  await evaluate('document.getElementById("save-settings").click()');
  await until(() => evaluate('document.getElementById("notice-text").textContent === "全局设置已应用"'));
  assert.equal(await evaluate('getComputedStyle(document.getElementById("notice")).position'), 'fixed');
  await evaluate('document.getElementById("dismiss-notice").click()');
  assert(await evaluate('document.getElementById("notice").hidden'));
  assert.equal(await evaluate(`document.querySelector('input[name="mismatch_recheck_seconds"]').value`), '43200');
  assert.equal(await evaluate(`document.querySelector('input[name="gateway_recheck_seconds"]').value`), '7200');
  assert.equal(await evaluate(`document.querySelector('select[name="parallel_challenges"]').value`), 'false');
  assert(await evaluate('document.getElementById("save-settings").disabled'));
  await evaluate('document.querySelector("[data-tab=auth]").click()');
  assert.equal(await evaluate('document.querySelectorAll("#auth-cards article").length'), 2);
  assert(await evaluate('document.querySelector("#auth-cards article").textContent.includes("预期 / 识别模型")'));
  assert.equal(await evaluate('document.querySelector("#auth-cards article .badge.pending")?.textContent'), '待检测');
  const failedSquares = await evaluate('document.querySelectorAll("#auth-cards .detection-squares .failed").length');
  assert(failedSquares > 0);
  assert.match(await evaluate('document.querySelector("#auth-cards .detection-summary")?.textContent'),
    new RegExp('一致 0 / 不一致 0 / 失败 ' + failedSquares + ' · 一致率 0%'));
  await checkDetectionTooltip('#auth-cards .detection-square');
  await evaluate(`(() => {
    const search = document.getElementById('auth-search');
    search.value = 'no-matching-credential';
    search.dispatchEvent(new Event('input', { bubbles: true }));
  })()`);
  assert(await evaluate('!document.getElementById("auth-empty").hidden'));
  await evaluate('document.querySelector("#auth-empty button").click()');
  assert.equal(await evaluate('document.querySelectorAll("#auth-cards article").length'), 2);
  await evaluate('document.querySelector("#auth-cards input[type=checkbox]").click()');
  assert(await evaluate('!document.getElementById("batch-actions").hidden && document.getElementById("selected-count").textContent === "已选 1 项"'));
  await evaluate('document.getElementById("batch-check").click()');
  assert(await evaluate('document.getElementById("confirm-dialog").open && document.getElementById("confirm-title").textContent === "发起检测"'));
  await evaluate('document.getElementById("confirm-cancel").click()');
  await evaluate('document.getElementById("batch-on").click()');
  assert(await evaluate('document.getElementById("confirm-dialog").open && document.getElementById("confirm-title").textContent === "启用检测"'));
  await evaluate('document.getElementById("confirm-submit").click()');
  await until(() => evaluate('document.getElementById("notice-text").textContent === "批量设置已保存"'));
  await evaluate('document.querySelector(\'[data-layout="table"]\').click()');
  assert.equal(await evaluate('document.querySelectorAll("#auth-rows tr").length'), 2);
  assert(await evaluate('document.querySelector("#auth thead").textContent.includes("认证 / 提供商")'));
  assert(await evaluate('document.querySelector("#auth thead").textContent.includes("预期 / 识别模型")'));
  assert.equal(await evaluate('document.querySelector("#auth thead th:nth-child(7)").textContent'), '结果');
  const badgesAligned = await evaluate(`(() => {
    const status = document.querySelector('#auth-rows .auth-status');
    const [state, queue] = status.querySelectorAll('.badge');
    const enabled = status.querySelector('small');
    return state.getBoundingClientRect().top === queue.getBoundingClientRect().top
      && state.getBoundingClientRect().left === enabled.getBoundingClientRect().left;
  })()`);
  assert(badgesAligned);
  assert(await evaluate('document.querySelector("#auth-rows input[type=checkbox]").checked'));
  await evaluate('document.getElementById("clear-selection").click()');
  assert(await evaluate('document.getElementById("batch-actions").hidden'));
  await evaluate('document.querySelector("#auth-rows [data-control=details]").click()');
  assert(await evaluate('document.getElementById("details-dialog").open'));
  const detailLabels = await evaluate('Array.from(document.querySelectorAll("#auth-detail-rows dt"), node => node.textContent)');
  assert.deepEqual(detailLabels, ['触发原因', '触发时间', '下次检测']);
  assert.equal(await evaluate('document.querySelector("#auth-detail-rows dd").textContent'), 'HTTP 状态');
  assert(await evaluate('!document.getElementById("auth-rows").textContent.includes("下次检测")'));
  await evaluate('document.getElementById("close-details").click()');
  await send('Emulation.setDeviceMetricsOverride', { width: 375, height: 760, deviceScaleFactor: 1, mobile: true });
  assert(await evaluate(`(() => {
    const table = document.querySelector('#auth .table-wrap');
    return document.documentElement.scrollWidth === 375 && table.scrollWidth > table.clientWidth;
  })()`));
  await checkDetectionTooltip('#auth-rows .detection-square');
  await evaluate('document.querySelector("#auth-rows [data-control=settings]").click()');
  assert.equal(await evaluate('document.activeElement.name'), 'enabled');
  const authTip = 'getComputedStyle(document.querySelector("#auth-fields .field-tooltip")).visibility';
  assert.equal(await evaluate(authTip), 'hidden');
  await hover('#auth-fields .field-tip');
  await until(async () => await evaluate(authTip) === 'visible');
  await evaluate(`(() => {
    const row = document.querySelector('#auth-fields select[name="idle"]');
    row.value = 'false';
    document.getElementById('auth-form').requestSubmit();
  })()`);
  await until(() => evaluate('document.getElementById("notice-text").textContent === "认证设置已保存"'));
  await evaluate('document.querySelector("#auth-rows [data-control=cancel]").click()');
  await until(() => evaluate('document.getElementById("notice-text").textContent === "已取消本次检测"'));
  assert(await evaluate('!document.querySelector("#auth-rows [data-control=cancel], #auth-rows .badge.pending")'));
  assert(await evaluate('document.querySelector("#auth-rows .badge.isolated")'));
  await evaluate('document.querySelector("[data-tab=history]").click()');
  assert.deepEqual(await evaluate('Array.from(document.querySelectorAll("#history thead th")).slice(3, 5).map(cell => cell.textContent)'),
    ['测试 / 预期模型', '识别模型']);
  assert(await evaluate('document.getElementById("history-rows").textContent.includes("证据不足")'));
  assert.equal(await evaluate('document.querySelector("#history thead th:nth-child(7)").textContent'), '概率');
  assert.equal(await evaluate('document.querySelector("#history-rows tr").cells[6].textContent'), '—');
  assert(await evaluate('localStorage.length === 0 && sessionStorage.length === 0'));
  // Use a same-origin host page for the parent. The plugin's policy blocks nested frames.
  await send('Page.navigate', { url: new URL('/healthz', pluginURL).href });
  await until(() => evaluate('location.pathname === "/healthz" && document.readyState === "complete"'));
  await evaluate(`(() => {
    const frame = document.createElement('iframe');
    frame.id = 'theme-fixture';
    document.documentElement.dataset.theme = 'dark';
    frame.src = ${JSON.stringify(pluginURL)};
    frame.hidden = true;
    document.body.append(frame);
  })()`);
  const frameTheme = () => evaluate('document.querySelector("#theme-fixture").contentDocument?.documentElement?.dataset.theme');
  await until(async () => await frameTheme() === 'dark');
  await evaluate('document.documentElement.dataset.theme = "white"');
  await until(async () => await frameTheme() === 'white');
  assert.equal(await evaluate(`(() => {
    const frame = document.querySelector('#theme-fixture');
    return frame.contentWindow.getComputedStyle(frame.contentDocument.documentElement).backgroundColor;
  })()`), 'rgb(255, 255, 255)');
  await evaluate('document.documentElement.removeAttribute("data-theme")');
  await until(async () => await frameTheme() === 'light');
  const { host, origin } = new URL(pluginURL);
  const remembered = { apiBase: origin, managementKey: fixtureKey, rememberPassword: true };
  async function openPluginWithRecord(raw, loggedIn = true) {
    await evaluate(`(() => {
      localStorage.setItem('cli-proxy-auth', ${JSON.stringify(raw)});
      localStorage.setItem('isLoggedIn', ${JSON.stringify(String(loggedIn))});
      const oldFrame = document.querySelector('#theme-fixture');
      const frame = oldFrame.cloneNode();
      oldFrame.replaceWith(frame);
    })()`);
    await until(() => evaluate(`(() => {
      const doc = document.querySelector('#theme-fixture').contentDocument;
      return doc.readyState === 'complete' && !!doc.getElementById('login');
    })()`));
  }
  function pluginFrame(expression) {
    return evaluate(`(() => {
      const doc = document.getElementById('theme-fixture').contentDocument;
      return (${expression});
    })()`);
  }
  const manualForm = "!doc.getElementById('login-page').hidden && !doc.getElementById('login-fields').hidden && !doc.getElementById('connect').disabled";
  const workspaceOpen = "!doc.getElementById('workspace').hidden && doc.getElementById('login-page').hidden";
  for (const [record, loggedIn] of [
    ['enc::v2::invalid!', true],
    [panelRecord(host, { ...remembered, apiBase: origin + '/other-instance' }), true],
    [panelRecord(host, { ...remembered, apiBase: 'https://other.example' }), true],
    [panelRecord(host, { ...remembered, rememberPassword: false }), true],
    [panelRecord(host, remembered), false],
  ]) {
    await openPluginWithRecord(record, loggedIn);
    assert(await pluginFrame(manualForm + " && doc.getElementById('login-status').hidden"));
  }
  const validRecord = panelRecord(host, remembered);
  await openPluginWithRecord(validRecord);
  await until(() => pluginFrame(workspaceOpen));
  assert(await pluginFrame("doc.getElementById('key').value === ''"));
  await openPluginWithRecord(validRecord);
  await until(() => pluginFrame(workspaceOpen));
  assert(await evaluate(`localStorage.length === 2 && localStorage.getItem('isLoggedIn') === 'true'
    && localStorage.getItem('cli-proxy-auth') === ${JSON.stringify(validRecord)} && sessionStorage.length === 0`));
  await openPluginWithRecord(panelRecord(host, { ...remembered, managementKey: 'fixture-expired' }));
  await until(() => pluginFrame(manualForm + " && doc.getElementById('login-status').textContent.includes('自动登录未成功')"));
  assert(await pluginFrame("doc.getElementById('key').value === ''"));
  await pluginFrame(`(() => {
    doc.getElementById('key').value = ${JSON.stringify(fixtureKey)};
    doc.getElementById('login').requestSubmit();
  })()`);
  await until(() => pluginFrame(workspaceOpen));

  if (process.argv[3]) {
    const accessOrigin = new URL(process.argv[3]);
    const protectedURL = new URL(pluginPath, accessOrigin).href;
    await send('Page.navigate', { url: protectedURL });
    await until(() => evaluate(`location.href === ${JSON.stringify(protectedURL)} && document.readyState === 'complete'`));
    await evaluate(manualLogin);
    await until(() => evaluate('!document.getElementById("login-status").hidden'));
    assert(await evaluate('document.getElementById("workspace").hidden'));

    const cookie = await send('Network.setCookie', {
      url: protectedURL, name: 'CF_Authorization', value: 'fixture-access-session',
      path: '/', httpOnly: true, sameSite: 'Lax',
    });
    assert(cookie.success);
    assert(await evaluate('!document.cookie.includes("CF_Authorization")'));
    await evaluate(manualLogin);
    await until(() => evaluate('!document.getElementById("workspace").hidden || document.querySelector("#login-status.error") !== null'));
    assert(await evaluate('!document.getElementById("workspace").hidden'), 'Manual login with an Access session cookie');

    const record = panelRecord(accessOrigin.host, { ...remembered, apiBase: accessOrigin.origin });
    await evaluate(`(() => {
      localStorage.setItem('cli-proxy-auth', ${JSON.stringify(record)});
      localStorage.setItem('isLoggedIn', 'true');
    })()`);
    const parentURL = new URL('/healthz', accessOrigin).href;
    await send('Page.navigate', { url: parentURL });
    await until(() => evaluate(`location.href === ${JSON.stringify(parentURL)} && document.readyState === 'complete'`));
    await evaluate(`(() => {
      const frame = document.createElement('iframe');
      frame.id = 'theme-fixture';
      frame.src = ${JSON.stringify(protectedURL)};
      frame.hidden = true;
      document.body.append(frame);
    })()`);
    await until(() => pluginFrame("doc?.getElementById('workspace') && (" + workspaceOpen + ")"));
    console.log('Chromium: manual and automatic login through a cookie-protected management endpoint passed');
  }
  socket.close();
  console.log('Chromium: login, session reload, themes, credential queue and history, settings tooltips and toast passed');
} finally {
  chrome.kill();
  await exit;
  await rm(profile, { recursive: true, force: true, maxRetries: 6, retryDelay: 100 });
}
