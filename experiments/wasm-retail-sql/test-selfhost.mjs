// Explicit opt-in local Docker fixture; never connects to the production VM.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { createServer } from 'node:net';
import { mkdir, writeFile } from 'node:fs/promises';
import { sourceFiles } from './pack.mjs';

const image = 'ghcr.io/usefulsoftwareco/executor-selfhost:2.0.0-beta.12@sha256:89a2b829150d01bc26305f844159ca8064ea8a4ace047490d09b6a3c8bdcf600';
const name = 'tunnel-kit-wasm-fixture-' + randomUUID();
assert.ok(!process.env.DOCKER_HOST && !process.env.DOCKER_CONTEXT,
  'Fixture refuses DOCKER_HOST and DOCKER_CONTEXT overrides; select a local context explicitly first');
const docker = (...args) => execFileSync('docker', args, { encoding: 'utf8', timeout: 120000 }).trim();
const endpoint = JSON.parse(docker('context', 'inspect'))[0].Endpoints.docker.Host;
assert.ok(endpoint.startsWith('unix://'), 'Fixture requires a local Unix Docker endpoint');
const identity = JSON.parse(docker('image', 'inspect', image))[0];
assert.ok(identity.RepoDigests.some(digest => digest.endsWith(image.split('@')[1])));
let started = false;
try {
  const reservation = createServer();
  await new Promise(accept => reservation.listen(0, '127.0.0.1', accept));
  const port = reservation.address().port;
  await new Promise(accept => reservation.close(accept));
  const origin = `http://127.0.0.1:${port}`;
  console.log('Starting disposable beta.12 with tmpfs-only data and loopback-only HTTP.');
  docker('run', '--detach', '--rm', '--name', name, '--user', '1000:1000',
    '--label', 'mcp-tunnel-kit.fixture=wasm-retail-sql',
    '--cap-drop=ALL', '--security-opt=no-new-privileges', '--memory=1g', '--cpus=2', '--pids-limit=128',
    '--tmpfs', '/app/data:uid=1000,gid=1000,mode=0700,size=256m',
    '--tmpfs', '/app/motel-data:uid=1000,gid=1000,mode=0700,size=32m',
    '--env', 'DO_NOT_TRACK=1', '--env', 'EXECUTOR_DISABLE_ANALYTICS=1',
    '--env', `BETTER_AUTH_URL=${origin}`,
    '--publish', `127.0.0.1:${port}:4400`, image);
  started = true;
  let cookie = '';
  const jar = new Map();
  async function request(path, body) {
    const response = await fetch(origin + path, {
      method: body === undefined ? 'GET' : 'POST',
      headers: { 'Content-Type': 'application/json', Origin: origin, Cookie: cookie },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      signal: AbortSignal.timeout(90000),
    });
    const cookies = response.headers.getSetCookie();
    for (const value of cookies) {
      const pair = value.split(';')[0];
      jar.set(pair.slice(0, pair.indexOf('=')), pair);
    }
    cookie = [...jar.values()].join('; ');
    const data = await response.json();
    assert.equal(response.status, 200, JSON.stringify({ path, status: response.status, data }));
    return data;
  }
  const deadline = Date.now() + 45000;
  while (true) {
    try { await request('/api/auth/self-host/config'); break; }
    catch (error) {
      if (Date.now() > deadline) throw error;
      await new Promise(accept => setTimeout(accept, 250));
    }
  }
  await request('/api/auth/self-host/setup', {
    name: 'Synthetic WASM fixture', email: 'wasm-fixture@example.test',
    password: randomUUID() + randomUUID(), organizationName: 'Disposable WASM lab',
  });
  const organizations = await request('/api/auth/organization/list');
  assert.equal(organizations.length, 1);
  const prefix = '/api/organizations/' + organizations[0].id;
  console.log('Deploying reviewed source through beta.12 package installer and static WASM plugin.');
  const app = await request(prefix + '/apps/deploy', { name: 'WASM Retail SQL', files: await sourceFiles() });
  const catalog = await request(`${prefix}/apps/${app.id}/tools`);
  assert.deepEqual(catalog.items.map(tool => [tool.name, tool.readOnly]).sort(),
    [['inventory', true], ['margin', true], ['outliers', true]]);
  const results = {};
  for (const tool of ['margin', 'inventory', 'outliers']) {
    results[tool] = await request(`${prefix}/apps/${app.id}/tools/call`, { tool, input: {}, kind: 'query' });
    assert.equal(results[tool].report, tool);
    assert.equal(results[tool].provenance.wasmInstance, true);
    assert.equal(results[tool].provenance.queryOnly, true);
    assert.equal(results[tool].provenance.orderRows, 50000);
    assert.equal(results[tool].provenance.inventoryRows, 100);
    assert.equal(results[tool].provenance.wasmSha256,
      '0734155c83e493983d1f2ff5b09a4fab6e35a32e9449c7e4e545756439f62d73');
    assert.ok(results[tool].provenance.memoryBytes <= 64 * 1024 * 1024);
    assert.equal(results[tool].rows.length, tool === 'margin' ? 5 : 10);
    assert.ok(JSON.stringify(results[tool]).length < 16000);
  }
  assert.deepEqual(await request(`${prefix}/apps/${app.id}/tools/call`,
    { tool: 'margin', input: {}, kind: 'query' }), results.margin);
  await mkdir('.build', { recursive: true });
  await writeFile('.build/selfhost-results.json', JSON.stringify({ image, catalog, results }, null, 2));
  console.log('beta.12 installed acceptance passed; results in .build/selfhost-results.json.');
} finally {
  if (started) docker('stop', '--time=5', name);
}
