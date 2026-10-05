#!/usr/bin/env node
// Browser validation runs after proving has finished, using an isolated profile.
import {spawn} from 'node:child_process';
import {readFile, writeFile, mkdir, access} from 'node:fs/promises';
import {join, resolve} from 'node:path';
import {pathToFileURL} from 'node:url';

if (![4,5].includes(process.argv.length)) throw new Error('Usage: node check-apple-optimization-report.mjs REPORT.html NEW_OUTPUT_DIRECTORY [EXPECTED_MEASURED_RUNS]');
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
  for (let i=0;i<600;i++) {
    ready=await evaluate('document.readyState === "complete" && document.getElementById("status")?.hidden');
    if (ready) break; await delay(100);
  }
  if (!ready) throw new Error('Report did not finish loading');
  const capture=async name=>{const {data}=await command('Page.captureScreenshot',{format:'png',captureBeyondViewport:false});await writeFile(join(out,name),Buffer.from(data,'base64'));screenshots.push(name)};
  const overflow=()=>evaluate('({viewport:innerWidth,pageWidth:document.documentElement.scrollWidth})');
  const desktop=await overflow();
  if(desktop.pageWidth>desktop.viewport)throw new Error('Desktop overflow');
  const check=await evaluate(`({error:document.getElementById('load-error').textContent,visible:!document.getElementById('apple-results').hidden,bars:document.querySelectorAll('#apple-bars .apple-row').length,measured:catalog.runs.filter(r=>r.configuration?.apple_metal?.campaign_id===document.getElementById('apple-campaign').value&&r.kind==='solving').length,components:catalog.runs.filter(r=>r.adapter==='apple-field').length})`);
  if(check.error||!check.visible||!check.bars)throw new Error('Apple charts unavailable: '+JSON.stringify(check));
  if(process.argv[4]&&check.measured!==Number(process.argv[4]))throw new Error('Incorrect measured trial count');
  if(process.argv[4]&&check.components!==12)throw new Error('Missing SME2 component comparisons');
  if(Number(process.argv[4])===2){
    const screen=await evaluate(`({runs:catalog.runs.filter(r=>r.configuration?.apple_metal?.campaign_id===document.getElementById('apple-campaign').value&&r.configuration.apple_metal.screening).length,reused:catalog.runs.filter(r=>r.configuration?.apple_metal?.campaign_id===document.getElementById('apple-campaign').value&&r.configuration.apple_metal.screening_reused&&r.kind==='diagnostic').length,note:document.getElementById('apple-scope').textContent})`);
    if(screen.runs!==3||screen.reused!==1||check.bars!==3||!screen.note.includes('One observation'))throw new Error('Incorrect screening display: '+JSON.stringify(screen));
  }
  await capture('desktop-overview.png');
  await evaluate("document.getElementById('apple-results').scrollIntoView()");
  await capture('desktop-apple-18t.png');
  await evaluate("document.getElementById('apple-threads').value='24';document.getElementById('apple-threads').onchange()");
  await capture('desktop-apple-24t.png');
  await evaluate("document.getElementById('apple-threads').value='18';document.getElementById('apple-threads').onchange()");
  await evaluate("document.querySelector('#apple-bars button').click()");
  for(let i=0;i<200;i++){if(await evaluate('document.getElementById("status").hidden'))break;await delay(100)}
  const selected=await evaluate('({id:current.run_id,root:current.verification.root_sha256,audit:current.verification.cpu_audited})');
  if(!selected.audit||!selected.root)throw new Error('Run evidence is not independently audited');
  await evaluate("document.querySelector('#run-detail button').click()");
  const downloaded=join(out,selected.id+'.json');
  let payload;
  for(let i=0;i<200;i++){try{payload=JSON.parse(await readFile(downloaded,'utf8'));break}catch{}await delay(100)}
  const expected=JSON.parse(await readFile(resolve(report,'..','runs',selected.id+'.json'),'utf8'));
  if(JSON.stringify(payload)!==JSON.stringify(expected))throw new Error('Downloaded JSON differs from retained evidence');
  if(check.components){await evaluate("document.getElementById('apple-field').scrollIntoView()");await capture('desktop-sme2.png')}
  await command('Emulation.setDeviceMetricsOverride',{width:390,height:844,deviceScaleFactor:1,mobile:true});
  await evaluate("document.getElementById('apple-results').scrollIntoView()");await delay(150);await capture('mobile-apple.png');
  await evaluate("document.querySelectorAll('#apple-results details').forEach(d=>d.open=true)");
  const mobile=await overflow();
  if(mobile.pageWidth>mobile.viewport)throw new Error('Mobile overflow');
  if(errors.length)throw new Error('JavaScript errors: '+JSON.stringify(errors));
  if(requests.some(url=>/^https?:/.test(url)))throw new Error('Unexpected external request');
  const result={status:'PASS',desktop,mobile,...check,evidence_download:'PASS',javascript_errors:0,external_requests:0,screenshots};
  await writeFile(join(out,'html-validation.json'),JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result,null,2));
  await Promise.race([send('Browser.close'),delay(1000)]);
} catch (error) {
  await writeFile(join(out, 'html-validation.json'), JSON.stringify({status:'FAIL', error:String(error)}, null, 2) + '\n');
  throw error;
} finally {
  for (const item of pending.values()) clearTimeout(item.timeout);
  socket?.close(); child.kill('SIGTERM'); child.stderr.destroy(); child.unref();
  await writeFile(join(out, 'browser-validation.log'), stderr);
}
