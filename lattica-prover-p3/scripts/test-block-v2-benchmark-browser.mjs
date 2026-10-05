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
  const qualification = await page.evaluate(() => catalog.qualification);
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
  await page.locator("#search").fill("round-1-concurrent");
  assert.equal(await page.locator("#run-rows tr").count(), 2);
  await page.locator("#run-rows button").first().click();
  await page.waitForFunction(() => document.querySelector("#status").hidden);
  const downloaded = page.waitForEvent("download");
  await page.getByRole("button", {name: "Download full run JSON"}).click();
  const download = await downloaded;
  const file = path.join(output, download.suggestedFilename());
  await download.saveAs(file);
  const record = JSON.parse(await fs.readFile(file, "utf8"));
  assert.equal(record.workload.user_transactions, 8);
  assert.equal(record.verification.cpu_audited, true);
  await page.locator("#reset").click();
  const id = await page.evaluate(() => catalog.runs.filter(r => r.timeline_events > 100000)
    .sort((a,b) => b.timeline_events-a.timeline_events)[0].run_id);
  await page.evaluate(id => selectRun(id), id);
  await page.waitForFunction(() => document.querySelector("#status").hidden, {timeout: 60000});
  await page.locator("input[type=range]").nth(1).fill("20");
  await page.locator("input[type=range]").nth(1).dispatchEvent("input");
  assert.match(await page.locator(".chart-caption").first().innerText(), /retained intervals/);
  await page.locator("#process").scrollIntoViewIfNeeded();
  await page.screenshot({path: path.join(output, "timeline.png")});
  await page.setViewportSize({width: 390, height: 844});
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
