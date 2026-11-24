import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';

const pluginURL = process.argv[2] + '/v0/resource/plugins/model-fingerprint-guard/index.html';
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
  const emulateTheme = value => send('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-color-scheme', value }] });
  await emulateTheme('light');
  await send('Page.navigate', { url: pluginURL });
  await until(() => evaluate('document.readyState === "complete" && !!document.querySelector("#login")'));
  assert.equal(await evaluate('getComputedStyle(document.documentElement).backgroundColor'), 'rgb(250, 249, 245)');
  await evaluate(`(() => {
    const key = document.getElementById('key');
    key.value = 'fixture-management-only';
    document.getElementById('login').requestSubmit();
  })()`);
  await until(() => evaluate('!document.getElementById("workspace").hidden'));
  assert.equal(await evaluate('document.getElementById("key").value'), '');
  await emulateTheme('dark');
  await until(() => evaluate('getComputedStyle(document.documentElement).backgroundColor === "rgb(21, 20, 18)"'));
  await emulateTheme('light');
  await evaluate('document.querySelector("[data-tab=settings]").click()');
  const configured = await evaluate(`(() => {
    const input = document.querySelector('input[name="history_limit"]');
    const interval = document.querySelector('input[name="mismatch_recheck_seconds"]');
    if (interval?.value !== '172800') return false;
    input.value = 42;
    interval.value = 43200;
    document.getElementById('settings-form').requestSubmit();
    return !!input;
  })()`);
  assert(configured);
  await until(() => evaluate('document.getElementById("notice").textContent.includes("全局设置已应用")'));
  assert.equal(await evaluate(`document.querySelector('input[name="mismatch_recheck_seconds"]').value`), '43200');
  await evaluate('document.querySelector("[data-tab=auth]").click()');
  assert.equal(await evaluate('document.querySelectorAll("#auth-rows tr").length'), 2);
  assert(await evaluate('document.querySelector("#auth thead").textContent.includes("认证 / 提供商")'));
  await send('Emulation.setDeviceMetricsOverride', { width: 375, height: 760, deviceScaleFactor: 1, mobile: true });
  assert(await evaluate(`(() => {
    const table = document.querySelector('#auth .table-wrap');
    return document.documentElement.scrollWidth === 375 && table.scrollWidth > table.clientWidth;
  })()`));
  await evaluate(`(() => {
    document.querySelector('#auth-rows .row-actions button').click();
    const row = document.querySelector('#auth-fields select[name="idle"]');
    row.value = 'false';
    document.getElementById('auth-form').requestSubmit();
  })()`);
  await until(() => evaluate('document.getElementById("notice").textContent.includes("认证设置已保存")'));
  await evaluate('document.querySelector("[data-tab=history]").click()');
  assert(await evaluate('document.getElementById("history-rows").textContent.includes("证据不足")'));
  assert(await evaluate(`(() => {
    const cells = document.querySelector('#history-rows tr').cells;
    return cells[3].textContent.includes(' / ') && cells[6].textContent.includes(' / ');
  })()`));
  await evaluate('document.getElementById("logout").click()');
  assert(await evaluate('document.getElementById("workspace").hidden && localStorage.length === 0 && sessionStorage.length === 0'));
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
  await evaluate('document.querySelector("#theme-fixture").remove()');
  socket.close();
  console.log('Chromium: authentication, theme switching, mobile tables, live settings, credential controls, history and logout passed');
} finally {
  chrome.kill();
  await exit;
  await rm(profile, { recursive: true, force: true, maxRetries: 6, retryDelay: 100 });
}
