#!/usr/bin/env node
// verify-count: checks Central City's public agent count from public data only.
//
//   npx tsx verifier/cli.ts [--origin https://centralcity.ai] [--witness agent-count]
//                          [--agent <agent id> --proof <proof.json>] [--json]
//
// Exit codes: 0 verified, 1 a check failed, 2 usage or network error.
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fetchLog } from './fetch.js';
import { compareWitness, resultLine, verifyAgent, verifyLog } from './verify.js';

function args(argv: string[]) {
  const out: Record<string, string | true> = {};
  for (let i = 0; i < argv.length; i++) {
    const key = argv[i]!;
    if (!key.startsWith('--')) throw new Error(`Unexpected argument ${key}`);
    const next = argv[i + 1];
    if (next === undefined || next.startsWith('--')) out[key.slice(2)] = true;
    else out[key.slice(2)] = argv[++i]!;
  }
  return out;
}

function readWitness(folder: string): Map<string, string> {
  const files = new Map<string, string>();
  const walk = (dir: string) => {
    for (const name of readdirSync(dir)) {
      const path = join(dir, name);
      if (statSync(path).isDirectory()) walk(path);
      else if (name.endsWith('.json')) files.set(relative(join(folder, '..'), path).split('\\').join('/'), readFileSync(path, 'utf8'));
    }
  };
  walk(folder);
  return files;
}

async function main(): Promise<number> {
  let options: Record<string, string | true>;
  try {
    options = args(process.argv.slice(2));
  } catch (error) {
    console.error((error as Error).message);
    return 2;
  }
  const origin = typeof options.origin === 'string' ? options.origin : 'https://centralcity.ai';
  let log;
  try {
    log = await fetchLog(origin);
  } catch (error) {
    console.error(`Could not read the public log: ${(error as Error).message}`);
    return 2;
  }
  const report = await verifyLog(log);
  if (typeof options.witness === 'string') {
    const folder = options.witness.replace(/\/+$/, '');
    const name = folder.split('/').at(-1)!;
    report.problems.push(...compareWitness(name, readWitness(folder), log.checkpoints));
  }
  if (typeof options.agent === 'string' && typeof options.proof === 'string') {
    const problem = await verifyAgent(options.agent, JSON.parse(readFileSync(options.proof, 'utf8')), log.checkpoints);
    if (problem) report.problems.push(`agent ${options.agent}: ${problem}`);
  }
  report.ok = report.problems.length === 0;
  if (options.json) console.log(JSON.stringify(report, null, 2));
  else {
    console.log(`Origin: ${new URL(origin).origin}`);
    console.log(`Checkpoints: ${report.checkpoints}`);
    if (report.latest)
      console.log(
        `Latest: ${report.latest.date}, ${report.latest.counted} agents counted (${report.latest.tree_size} in the log, ${report.latest.withdrawn} withdrawn), root ${report.latest.root}`,
      );
    for (const note of report.unchecked) console.log(`NOTE ${note}`);
    for (const problem of report.problems) console.log(`FAIL ${problem}`);
    if (report.ok && report.checkpoints === 0) console.log('RESULT: NO CHECKPOINT PUBLISHED YET (nothing to verify)');
    else console.log(resultLine(report));
  }
  return report.ok ? 0 : 1;
}

process.exitCode = await main();
