// The daily witness: copies each new checkpoint into agent-count/YYYY/YYYY-MM-DD.json, after
// verifying the whole public log. Files are only ever added: if the service now publishes
// different content for a day that is already witnessed, this fails and changes nothing.
//
//   npx tsx witness/update.ts [--origin https://centralcity.ai] [--folder agent-count]
//
// Exit codes: 0 up to date (files may have been added), 1 verification failed or a witnessed day
// changed, 2 network error. "Not published yet" (404) exits 0 without changes.
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { NotPublished, fetchLog } from '../verifier/fetch.js';
import { verifyLog, witnessPlan } from '../verifier/verify.js';

const argv = process.argv.slice(2);
const option = (name: string, fallback: string) => {
  const index = argv.indexOf(`--${name}`);
  return index >= 0 && argv[index + 1] ? argv[index + 1]! : fallback;
};
const origin = option('origin', 'https://centralcity.ai');
const folder = option('folder', 'agent-count');

async function main(): Promise<number> {
  let log;
  try {
    log = await fetchLog(origin);
  } catch (error) {
    if (error instanceof NotPublished) {
      console.log(`The count log is not published yet (${error.message}); nothing to witness.`);
      return 0;
    }
    console.error(`Could not read the public log: ${(error as Error).message}`);
    return 2;
  }
  const report = await verifyLog(log);
  if (!report.ok) {
    for (const problem of report.problems) console.error(`FAIL ${problem}`);
    return 1;
  }
  const plan = witnessPlan(folder, log.checkpoints, (path) =>
    existsSync(path) ? readFileSync(path, 'utf8') : undefined,
  );
  for (const date of plan.refused)
    console.error(`FAIL ${date}: the service publishes per-category counts; nothing is written`);
  if (plan.refused.length) return 1;
  for (const file of plan.add) {
    mkdirSync(dirname(file.path), { recursive: true });
    writeFileSync(file.path, file.content);
  }
  const added = plan.add.length;
  if (plan.changed.length) {
    for (const path of plan.changed) console.error(`FAIL ${path}: the service now publishes different content for a witnessed day`);
    return 1;
  }
  console.log(`Verified ${report.checkpoints} checkpoints; added ${added} witness file(s).`);
  return 0;
}

process.exitCode = await main();
