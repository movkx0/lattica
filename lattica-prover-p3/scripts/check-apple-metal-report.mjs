#!/usr/bin/env node
// Browser validation runs after proving has finished, using an isolated profile.
import {spawn} from 'node:child_process';
import {readFile, writeFile, mkdir, access} from 'node:fs/promises';
import {join, resolve} from 'node:path';
import {pathToFileURL} from 'node:url';

if (process.argv.length !== 4) throw new Error('Usage: node check-apple-metal-report.mjs REPORT.html NEW_OUTPUT_DIRECTORY');
const report = resolve(process.argv[2]);
const out = resolve(process.argv[3]);
await access(report);
await mkdir(out);
const profile = join(out, 'isolated-browser-profile');
await mkdir(profile);
const browser = process.env.CHROMIUM_EXECUTABLE || '/Applications/Chromium.app/Contents/MacOS/Chromium';
const child = spawn(browser, [
  '--headless', '--disable-gpu', '--no-first-run', '--no-default-browser-check',
  '--disable-background-networking', '--disable-component-update', '--disable-sync',
  '--disable-extensions', '--remote-debugging-address=127.0.0.1', '--remote-debugging-port=0',
  `--user-data-dir=${profile}`, 'about:blank',
], {stdio:['ignore', 'ignore', 'pipe']});
let stderr = '', socket;
child.stderr.on('data', value => { stderr += value; });
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const pending = new Map(), errors = [], requests = [], screenshots = [];
let nextId = 0;
try {
  let endpoint;
  for (let i = 0; i < 150; i++) {
    if (child.exitCode !== null) throw new Error(`Chromium exited ${child.exitCode}: ${stderr}`);
    try {
      const [port, path] = (await readFile(join(profile, 'DevToolsActivePort'), 'utf8')).trim().split('\n');
      endpoint = `ws://127.0.0.1:${port}${path}`; break;
    } catch {}
    await delay(100);
  }
  if (!endpoint) throw new Error('Chromium did not expose its local debugging endpoint');
  socket = new WebSocket(endpoint);
  await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('WebSocket connection timeout')), 10000);
    socket.addEventListener('open', () => { clearTimeout(timeout); resolve(); }, {once:true});
    socket.addEventListener('error', error => { clearTimeout(timeout); reject(error); }, {once:true});
  });
  socket.addEventListener('message', event => {
    const message = JSON.parse(event.data);
    if (message.id) {
      const item = pending.get(message.id);
      if (!item) return;
      pending.delete(message.id); clearTimeout(item.timeout);
      if (message.error) item.reject(new Error(JSON.stringify(message.error))); else item.resolve(message.result);
    } else if (message.method === 'Runtime.exceptionThrown') errors.push(message.params.exceptionDetails);
    else if (message.method === 'Network.requestWillBeSent') requests.push(message.params.request.url);
  });
  const send = (method, params = {}, sessionId) => new Promise((resolve, reject) => {
    const id = ++nextId;
    const timeout = setTimeout(() => { pending.delete(id); reject(new Error(`CDP timeout: ${method}`)); }, 15000);
    pending.set(id, {resolve, reject, timeout});
    socket.send(JSON.stringify({id, method, params, ...(sessionId ? {sessionId} : {})}));
  });
  const {targetId} = await send('Target.createTarget', {url:'about:blank'});
  const {sessionId} = await send('Target.attachToTarget', {targetId, flatten:true});
  const command = (method, params = {}) => send(method, params, sessionId);
  const evaluate = async expression => {
    const result = await command('Runtime.evaluate', {expression, returnByValue:true, awaitPromise:true});
    if (result.exceptionDetails) throw new Error(JSON.stringify(result.exceptionDetails));
    return result.result.value;
  };
  await command('Page.enable'); await command('Runtime.enable'); await command('Network.enable');
  await send('Browser.setDownloadBehavior', {behavior:'allow', downloadPath:out});
  await command('Emulation.setDeviceMetricsOverride', {width:1400, height:1100, deviceScaleFactor:1, mobile:false});
  await command('Page.navigate', {url:pathToFileURL(report).href});
  let ready = false;
  for (let i = 0; i < 100; i++) {
    ready = await evaluate('document.readyState === "complete" && !!document.getElementById("chart-mode")');
    if (ready) break; await delay(100);
  }
  if (!ready) throw new Error('Report did not load');
  await evaluate('document.fonts.ready.then(() => true)');
  const capture = async name => {
    await delay(150);
    const {data} = await command('Page.captureScreenshot', {format:'png', captureBeyondViewport:false});
    await writeFile(join(out, name), Buffer.from(data, 'base64')); screenshots.push(name);
  };
  const overflow = () => evaluate('({viewport:innerWidth,pageWidth:document.documentElement.scrollWidth})');
  const desktop = await overflow();
  if (desktop.pageWidth > desktop.viewport) throw new Error('Desktop horizontal overflow');
  const documentCheck = await evaluate(`({unresolved:/@@[A-Z_]+@@/.test(document.body.innerText), images:[...document.images].map(i=>({loaded:i.complete&&i.naturalWidth>0,alt:i.alt})), sections:document.querySelectorAll('section').length})`);
  if (documentCheck.unresolved || documentCheck.images.some(i => !i.loaded || !i.alt)) throw new Error('Unresolved template or unloaded/unlabeled graph');
  await capture('desktop-overview.png');
  await evaluate("document.querySelectorAll('section')[0].scrollIntoView()");
  await capture('desktop-baseline.png');
  const toggle = await evaluate(`(()=>{const menu=document.getElementById('chart-mode');menu.value='relative';menu.dispatchEvent(new Event('change',{bubbles:true}));return {secondsHidden:document.getElementById('seconds-chart').hidden,relativeHidden:document.getElementById('relative-chart').hidden};})()`);
  if (!toggle.secondsHidden || toggle.relativeHidden) throw new Error('Chart selector did not switch views');
  await capture('desktop-relative.png');
  const pipelineThreads = await evaluate("[...document.querySelectorAll('.pipeline-case')].map(e => Number(e.dataset.threads))");
  for (const threads of pipelineThreads) {
    await evaluate(`document.querySelector('.pipeline-case[data-threads="${threads}"]').scrollIntoView()`);
    await capture(`desktop-pipeline-${threads}t.png`);
  }
  await evaluate("document.getElementById('download-evidence').click()");
  const download = join(out, 'lattica-apple-metal-benchmark-evidence.json');
  for (let i = 0; i < 100; i++) { try { await access(download); break; } catch { await delay(100); } }
  const downloaded = JSON.parse(await readFile(download, 'utf8'));
  if (downloaded.results.status !== 'COMPLETE_VERIFIED_COMPARISON' || ![56,74].includes(downloaded.results.trials.length) || downloaded.results.trials.some(t => !t.verified) || downloaded.results.trials.filter(t => t.phase === 'measured' && t.threads === 18 && t.level === 'baseline').length !== 9) throw new Error('Downloaded evidence is incomplete');
  const expectedPipelineThreads = [...new Set(downloaded.results.trials.filter(t => t.level !== 'baseline').map(t => t.threads))].sort((a,b) => a-b);
  if (JSON.stringify(pipelineThreads) !== JSON.stringify(expectedPipelineThreads)) throw new Error('Pipeline charts do not match the measured thread settings');
  const embedded = await evaluate('document.getElementById("evidence").textContent');
  if (JSON.stringify(JSON.parse(embedded)) !== JSON.stringify(downloaded)) throw new Error('Evidence download differs from embedded data');
  await command('Emulation.setDeviceMetricsOverride', {width:390, height:844, deviceScaleFactor:1, mobile:false});
  await evaluate(`(()=>{const menu=document.getElementById('chart-mode');menu.value='seconds';menu.dispatchEvent(new Event('change',{bubbles:true}));window.scrollTo(0,0);})()`);
  await capture('mobile-overview.png');
  await evaluate("document.getElementById('seconds-chart').scrollIntoView()");
  await capture('mobile-baseline.png');
  for (const threads of pipelineThreads) {
    await evaluate(`document.querySelector('.pipeline-case[data-threads="${threads}"]').scrollIntoView()`);
    await capture(`mobile-pipeline-${threads}t.png`);
  }
  await evaluate("document.querySelectorAll('details').forEach(d=>d.open=true)");
  const mobile = await overflow();
  if (mobile.pageWidth > mobile.viewport) throw new Error(`Mobile overflow with details open: ${JSON.stringify(mobile)}`);
  if (errors.length) throw new Error('JavaScript runtime errors: ' + JSON.stringify(errors));
  if (requests.some(url => /^https?:/.test(url))) throw new Error('Unexpected network dependency');
  const result = {status:'PASS', browser:'Chromium headless, isolated profile', desktop, mobile,
    chart_selector:toggle, document_check:documentCheck, pipeline_threads:pipelineThreads, evidence_download:'PASS', javascript_errors:0,
    external_requests:0, screenshots};
  await writeFile(join(out, 'html-validation.json'), JSON.stringify(result, null, 2) + '\n');
  console.log(JSON.stringify(result, null, 2));
  await Promise.race([send('Browser.close'), delay(1000)]);
} catch (error) {
  await writeFile(join(out, 'html-validation.json'), JSON.stringify({status:'FAIL', error:String(error)}, null, 2) + '\n');
  throw error;
} finally {
  for (const item of pending.values()) clearTimeout(item.timeout);
  socket?.close(); child.kill('SIGTERM'); child.stderr.destroy(); child.unref();
  await writeFile(join(out, 'browser-validation.log'), stderr);
}
