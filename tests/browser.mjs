import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';

const URL = process.argv[2] + '/v0/resource/plugins/model-fingerprint-guard/index.html';
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
  await send('Page.navigate', { url: URL });
  await until(() => evaluate('document.readyState === "complete" && !!document.querySelector("#login")'));
  await evaluate(`(() => {
    const key = document.getElementById('key');
    key.value = 'fixture-management-only';
    document.getElementById('login').requestSubmit();
  })()`);
  await until(() => evaluate('!document.getElementById("workspace").hidden'));
  assert.equal(await evaluate('document.getElementById("key").value'), '');
  await evaluate('document.querySelector("[data-tab=settings]").click()');
  const configured = await evaluate(`(() => {
    const input = document.querySelector('input[name="history_limit"]');
    input.value = 42;
    document.getElementById('settings-form').requestSubmit();
    return !!input;
  })()`);
  assert(configured);
  await until(() => evaluate('document.getElementById("notice").textContent.includes("全局设置已应用")'));
  await evaluate('document.querySelector("[data-tab=auth]").click()');
  assert.equal(await evaluate('document.querySelectorAll("#auth-rows tr").length'), 2);
  await evaluate(`(() => {
    document.querySelector('#auth-rows .row-actions button').click();
    const row = document.querySelector('#auth-fields select[name="idle"]');
    row.value = 'false';
    document.getElementById('auth-form').requestSubmit();
  })()`);
  await until(() => evaluate('document.getElementById("notice").textContent.includes("认证设置已保存")'));
  await evaluate('document.querySelector("[data-tab=history]").click()');
  assert(await evaluate('document.getElementById("history-rows").textContent.includes("证据不足")'));
  await evaluate('document.getElementById("logout").click()');
  assert(await evaluate('document.getElementById("workspace").hidden && localStorage.length === 0 && sessionStorage.length === 0'));
  socket.close();
  console.log('Chromium: authentication, live settings, credential controls, history and logout passed');
} finally {
  chrome.kill();
  await exit;
  await rm(profile, { recursive: true, force: true });
}
