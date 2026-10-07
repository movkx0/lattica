// Optional browser QA. Install Playwright externally or set PLAYWRIGHT_MODULE.
// node scripts/test-block-v2-benchmark-browser.mjs [absolute path to index.html]
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import {fileURLToPath, pathToFileURL} from "node:url";

const {chromium} = await import(process.env.PLAYWRIGHT_MODULE || "playwright");
const report = process.argv[2] || fileURLToPath(new URL("../../docs/benchmarks/index.html", import.meta.url));
const output = await fs.mkdtemp(path.join(os.tmpdir(), "lattica-report-browser-"));
const browser = await chromium.launch({
  executablePath: process.env.CHROMIUM || "/usr/bin/chromium",
  headless: true, args: ["--disable-gpu", "--disable-dev-shm-usage"],
});
try {
  const context = await browser.newContext({viewport: {width: 1440, height: 1080}, offline: true});
  const page = await context.newPage(), errors = [], requests = [];
  page.on("pageerror", e => errors.push(e.message));
  page.on("request", r => {if (/^https?:/.test(r.url())) requests.push(r.url());});
  await page.goto(pathToFileURL(report).href);
  await page.waitForFunction(() => document.querySelector("#status").hidden, {timeout: 60000});
  assert.equal(await page.locator("#load-error").innerText(), "");
  assert.equal(await page.locator("#ledger .phase").count(), 6);
  const mixed = await page.evaluate(() => catalog.comparisons.filter(c =>
    c.scope === "typed_recursive_aggregation" && c.aggregate && c.windows.length >= 5 &&
    c.windows.every(w => w.recorded?.repeat_qualified === true)));
  if (mixed.some(c => c.id.endsWith(":concurrent")) && mixed.some(c => c.id.endsWith(":sequential"))) {
    const note = await page.locator("#latest-note").innerText();
    assert.match(note, /Repeated mixed-root comparison/);
    assert.match(note, /useful inputs.*issuance/);
    assert.match(note, /exclude issuance, wallet proving and durable application/);
    assert.equal(await page.locator("#overview .card .value").count(), 3);
    for (const value of (await page.locator("#overview .card .value").allTextContents()).slice(0, 2)) {
      assert.match(value, /[0-9].*tx\/min/);
    }
  }
  const qualification = await page.evaluate(() => catalog.qualification);
  const nativeCache = await page.evaluate(() => (catalog.campaigns || []).map(c => c.document).filter(d =>
    d.record_type === 'opening_cache_native_matched_comparison_qualification' &&
    ['passed', 'incomplete'].includes(d.status) && Number.isInteger(d.completed_pairs) && d.completed_pairs > 0)
    .sort((a,b) => String(b.captured_utc).localeCompare(String(a.captured_utc)))[0]);
  if (nativeCache) {
    assert.equal(await page.locator('#native-cache-comparison tbody tr').count(), 4);
    const text = await page.locator('#native-cache-comparison').innerText();
    assert.ok(text.includes('Median reduction within pairs'));
    assert.ok(text.includes('Within-pair range'));
    assert.ok(text.includes('sustained transaction throughput remains unqualified'));
    const pending = page.waitForEvent('download');
    await page.getByRole('button', {name: 'Download native comparison JSON', exact: true}).click();
    const download = await pending;
    const destination = path.join(output, download.suggestedFilename());
    await download.saveAs(destination);
    assert.deepEqual(JSON.parse(await fs.readFile(destination, 'utf8')), nativeCache);
  }
  if (qualification) {
    assert.equal(await page.locator("#qualification-view tbody").first().locator("tr").count(), 8);
    const readyDownload = page.waitForEvent("download");
    await page.locator("#download-qualification").click();
    const exported = await readyDownload;
    const destination = path.join(output, exported.suggestedFilename());
    await exported.saveAs(destination);
    const ready = JSON.parse(await fs.readFile(destination, "utf8"));
    assert.equal(ready.status, qualification.status);
    assert.equal(ready.pilot_started, false);
    assert.equal(ready.planned_user_requests, 504);
    assert.equal(ready.schedule_is_measured_data, false);
  }
  if (!(await page.evaluate(() => (catalog.transaction_campaigns || []).length))) {
    assert.match(await page.locator("#tx-campaign-view").innerText(), /No delivered-transaction campaign/);
  }
  await page.screenshot({path: path.join(output, "desktop.png")});
  const auditedEight = await page.evaluate(() => catalog.runs.find(r =>
    r.verification.cpu_audited === true && r.workload.user_transactions === 8)?.run_id);
  assert.ok(auditedEight, "An audited eight-input run is required for the download check");
  await page.locator("#search").fill(auditedEight);
  assert.equal(await page.locator("#run-rows tr").count(), 1);
  await page.locator("#run-rows button").first().click();
  await page.waitForFunction(() => document.querySelector("#status").hidden);
  const downloaded = page.waitForEvent("download");
  await page.getByRole("button", {name: "Download full run JSON"}).click();
  const download = await downloaded;
  const file = path.join(output, download.suggestedFilename());
  await download.saveAs(file);
  const record = JSON.parse(await fs.readFile(file, "utf8"));
  assert.equal(record.run_id, auditedEight);
  assert.equal(record.workload.user_transactions, 8);
  assert.equal(record.verification.cpu_audited, true);
  const pairedComparisons = await page.evaluate(() => catalog.comparisons.filter(c =>
    c.windows.length && c.windows.every(w => w.recorded?.candidate_construction === "paired" &&
      w.recorded.repeat_qualified)));
  if (pairedComparisons.length) {
    await page.getByText("Matched campaign throughput and latency", {exact: true}).click();
  }
  for (const comparison of pairedComparisons) {
    assert.equal(comparison.windows.length, 5);
    assert.equal(comparison.aggregate.processed_user_transactions, 15);
    assert.ok(comparison.aggregate.transactions_per_minute > 0);
    assert.ok(comparison.windows.every(w => w.complete_mapping && w.run_ids.length === 1));
    assert.ok((await page.locator("#comparison-summary").innerText()).includes(comparison.label));
  }
  if (pairedComparisons.length) {
    await page.getByText("Matched campaign throughput and latency", {exact: true}).click();
  }
  const pairedId = await page.evaluate(() => catalog.runs.find(r =>
    r.configuration?.construction === "paired" && r.verification.cpu_audited &&
    r.workload.user_transactions === 3 && r.workload.issuance_transactions === 1)?.run_id);
  if (pairedId) {
    await page.evaluate(id => selectRun(id), pairedId);
    await page.waitForFunction(() => document.querySelector("#status").hidden, {timeout: 60000});
    const pairedDownload = page.waitForEvent("download");
    await page.getByRole("button", {name: "Download full run JSON"}).click();
    const exported = await pairedDownload;
    const pairedPath = path.join(output, exported.suggestedFilename());
    await exported.saveAs(pairedPath);
    const paired = JSON.parse(await fs.readFile(pairedPath, "utf8"));
    assert.equal(paired.run_id, pairedId);
    assert.equal(paired.configuration.registry_keys, 12);
    assert.equal(paired.proofs.length, 4);
    assert.equal(paired.configuration.recorded_fresh_proofs, 4);
    assert.equal(paired.workload.user_transactions, 3);
    assert.equal(paired.workload.issuance_transactions, 1);
    assert.equal(paired.verification.cpu_audited, true);
  }
  const typedWorkerId = await page.evaluate(() => catalog.runs.find(r =>
    r.configuration?.execution_backend === "typed-dag" && r.configuration?.recorded_fresh_proofs === 8 &&
    r.verification.cpu_audited)?.run_id);
  if (typedWorkerId) {
    await page.evaluate(id => selectRun(id), typedWorkerId);
    await page.waitForFunction(() => document.querySelector("#status").hidden, {timeout: 60000});
    const typedDownload = page.waitForEvent("download");
    await page.getByRole("button", {name: "Download full run JSON"}).click();
    const exported = await typedDownload;
    const typedPath = path.join(output, exported.suggestedFilename());
    await exported.saveAs(typedPath);
    const typed = JSON.parse(await fs.readFile(typedPath, "utf8"));
    assert.equal(typed.run_id, typedWorkerId);
    assert.equal(typed.configuration.execution_result.workspace_released_after_gpu_teardown, true);
    assert.equal(typed.configuration.execution_result.arrival_backend_integrated, false);
    assert.equal(typed.proofs.length, 8);
    assert.equal(typed.proofs.reduce((sum, proof) => sum + proof.cache_hits, 0), 4);
    assert.equal(typed.proofs.reduce((sum, proof) => sum + proof.setups, 0), 4);
    assert.equal(typed.verification.cpu_audited, true);
    await page.getByText("Recursive proof durations · 8 records", {exact: true}).click();
    await page.locator("#process").screenshot({path: path.join(output, "typed-worker.png")});
  }
  const processWorkerId = await page.evaluate(() => catalog.runs.find(r =>
    r.configuration?.execution_backend === "typed-process-dag" &&
    r.configuration?.recorded_fresh_proofs === 8 && r.verification.cpu_audited)?.run_id);
  if (processWorkerId) {
    await page.evaluate(id => selectRun(id), processWorkerId);
    await page.waitForFunction(() => document.querySelector("#status").hidden, {timeout: 60000});
    const saved = page.waitForEvent("download");
    await page.getByRole("button", {name: "Download full run JSON"}).click();
    const exported = await saved;
    const file = path.join(output, exported.suggestedFilename());
    await exported.saveAs(file);
    const run = JSON.parse(await fs.readFile(file, "utf8"));
    const execution = run.configuration.execution_result;
    assert.equal(execution.execution_backend, "typed_process_dag_v1");
    assert.notEqual(execution.worker_pid, execution.coordinator_pid);
    assert.equal(execution.worker_process_exited, true);
    assert.equal(execution.workspace_released_after_gpu_teardown, true);
    assert.equal(run.proofs.reduce((sum, p) => sum + p.cache_hits, 0), 4);
    assert.equal(run.proofs.reduce((sum, p) => sum + p.setups, 0), 4);
    assert.match(await page.locator("#process").innerText(), /persistent GPU child/);
    if (run.configuration.benchmark_monitor_interruption) {
      assert.ok(run.limitations.some(message => message.includes("telemetry gap")));
      assert.equal(run.configuration.benchmark_monitor_interruption.dag_coordinator_restarted, false);
    }
    await page.locator("#process").screenshot({path: path.join(output, "persistent-worker.png")});
  }
  await page.locator("#reset").click();
const queryComparisons = await page.evaluate(() => catalog.comparisons.filter(c => c.windows.length &&
  c.windows.every(w => w.recorded?.type === "typed_query_comparison" && w.recorded.repeat_qualified)));
if (queryComparisons.length) {
  await page.getByText("Matched campaign throughput and latency", {exact: true}).click();
  for (const comparison of queryComparisons) {
    assert.ok(comparison.aggregate.transactions_per_minute > 0);
    assert.ok(comparison.windows.every(w => w.complete_mapping && w.run_ids.length === 1));
    assert.ok((await page.locator("#comparison-summary").innerText()).includes(comparison.label));
  }
  await page.getByText("Matched campaign throughput and latency", {exact: true}).click();
}
const gatherId = await page.evaluate(() => catalog.runs.find(r =>
  r.configuration?.query_readback_layout === "gather" && r.configuration.construction === "paired" &&
  r.verification.cpu_audited && r.workload.user_transactions === 3 && r.workload.issuance_transactions === 1)?.run_id);
if (gatherId) {
  await page.evaluate(id => selectRun(id), gatherId);
  await page.waitForFunction(() => document.querySelector("#status").hidden, {timeout: 60000});
  const download = page.waitForEvent("download");
  await page.getByRole("button", {name: "Download full run JSON"}).click();
  const exported = await download;
  const file = path.join(output, exported.suggestedFilename());
  await exported.saveAs(file);
  const gather = JSON.parse(await fs.readFile(file, "utf8"));
  assert.equal(gather.run_id, gatherId);
  assert.equal(gather.configuration.query_readback_layout, "gather");
  assert.equal(gather.configuration.registry_keys, 12);
  assert.equal(gather.proofs.length, 4);
  assert.equal(gather.verification.cpu_audited, true);
  await page.locator("#reset").click();
}
const id = await page.evaluate(() => catalog.runs.filter(r => r.timeline_events > 100000)
    .sort((a,b) => b.timeline_events-a.timeline_events)[0].run_id);
  await page.evaluate(id => selectRun(id), id);
  await page.waitForFunction(() => document.querySelector("#status").hidden, {timeout: 60000});
  await page.locator("input[type=range]").nth(1).fill("20");
  await page.locator("input[type=range]").nth(1).dispatchEvent("input");
  assert.match(await page.locator(".chart-caption").first().innerText(), /retained intervals/);
  await page.locator("#process").scrollIntoViewIfNeeded();
  await page.screenshot({path: path.join(output, "timeline.png")});
  const chartSelections = await page.locator("#process select").evaluateAll(
    elements => elements.map(element => element.value));
  await page.setViewportSize({width: 390, height: 844});
  await page.waitForFunction(() => {
    const charts = [...document.querySelectorAll("#process canvas")];
    return charts.length > 0 && charts.every(canvas =>
      canvas.width === Math.floor(Math.max(300, canvas.clientWidth) * devicePixelRatio));
  });
  assert.deepEqual(await page.locator("#process select").evaluateAll(
    elements => elements.map(element => element.value)), chartSelections);
  assert.equal(await page.locator("input[type=range]").nth(1).inputValue(), "20");
  await page.evaluate(() => window.scrollTo(0,0));
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
  await page.screenshot({path: path.join(output, "mobile.png")});
  await page.emulateMedia({media: "print"});
  assert.equal(await page.locator("nav").isVisible(), false);
  assert.deepEqual(errors, []);
  assert.deepEqual(requests, []);
  console.log(JSON.stringify({status: "passed", network_requests: requests.length,
                             browser_errors: errors.length, artifacts: output}));
} finally {
  await browser.close();
}
