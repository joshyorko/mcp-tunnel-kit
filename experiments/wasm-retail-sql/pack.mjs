import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';

export async function sourceFiles() {
  const paths = ['index.ts', 'engine.ts', 'dataset.ts', 'output.ts', 'dynamic-schema.ts', 'dynamic.ts', 'select.ts', 'sqlite-glue.js', 'SQLJS-LICENSE'];
  const files = await Promise.all(paths.map(async path => ({ path, content: await readFile(path, 'utf8') })));
  const manifest = JSON.parse(await readFile('package.json', 'utf8'));
  files.push({ path: 'package.json', content: JSON.stringify({
    name: manifest.name, version: manifest.version, private: true, type: 'module',
    dependencies: manifest.dependencies,
  }, null, 2) + '\n' });
  return files;
}

if (process.argv[1]?.endsWith('/pack.mjs')) {
  const files = await sourceFiles();
  await mkdir('.build', { recursive: true });
  await writeFile('.build/files.json', JSON.stringify(files));
  await writeFile('.build/source-hashes.json', JSON.stringify(files.map(file => ({
    path: file.path, sha256: createHash('sha256').update(file.content).digest('hex'),
  })), null, 2) + '\n');
  console.log('Prepared .build/files.json and .build/source-hashes.json; nothing installed.');
}
