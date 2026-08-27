import { execFile } from 'node:child_process';
import { constants } from 'node:fs';
import { access, lstat, mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';
import { randomUUID } from 'node:crypto';

const execFileAsync = promisify(execFile);

async function exists(target) {
  try {
    await access(target, constants.F_OK);
    return true;
  } catch (error) {
    if (error.code === 'ENOENT') return false;
    throw error;
  }
}

function validateTarget(target) {
  const resolved = path.resolve(target);
  if (resolved === path.parse(resolved).root) throw new Error('Refusing to use a filesystem root as an output bundle.');
  return resolved;
}

async function rejectLink(target) {
  if (!(await exists(target))) return;
  const stats = await lstat(target);
  if (stats.isSymbolicLink()) throw new Error(`Refusing symbolic-link or junction output target: ${target}`);
}

function validateFilename(filename) {
  if (!filename || filename === '.' || filename === '..' || path.basename(filename) !== filename) {
    throw new Error(`Unsafe artifact filename: ${filename}`);
  }
  if (process.platform === 'win32' && /[<>:"/\\|?*]/u.test(filename)) {
    throw new Error(`Artifact filename is not valid on Windows: ${filename}`);
  }
}

async function writePart(directory, part) {
  validateFilename(part.filename);
  const target = path.join(directory, part.filename);
  const data = part.encoding === 'binary' ? Buffer.from(part.data) : String(part.data);
  await writeFile(target, data, { flag: 'wx', mode: part.secret ? 0o600 : 0o644 });
}

async function currentWindowsSid() {
  const { stdout } = await execFileAsync('whoami.exe', ['/user', '/fo', 'csv', '/nh'], { windowsHide: true });
  const match = stdout.match(/"(S-[0-9-]+)"/u);
  if (!match) throw new Error('Could not determine the current Windows user SID.');
  return match[1];
}

async function secureWindowsDirectory(directory) {
  const sid = await currentWindowsSid();
  const recursiveFlags = ['/T', '/C'];
  await execFileAsync('icacls.exe', [
    directory,
    '/inheritance:r',
    ...recursiveFlags,
  ], { windowsHide: true });
  await execFileAsync('icacls.exe', [
    directory,
    '/grant:r',
    `*${sid}:F`,
    '*S-1-5-18:F',
    ...recursiveFlags,
  ], { windowsHide: true });
}

async function writeManifest(directory, preset, artifacts) {
  const manifest = {
    generator: 'secretgen',
    preset,
    generatedAt: new Date().toISOString(),
    artifacts: artifacts.map((artifact, index) => ({
      index: index + 1,
      metadata: artifact.metadata,
      parts: artifact.parts.map(({ role, filename, mediaType, secret, encoding }) => ({
        role, filename, mediaType, secret, encoding,
      })),
    })),
  };
  await writeFile(path.join(directory, 'secretgen-manifest.json'), JSON.stringify(manifest, null, 2), { flag: 'wx', mode: 0o600 });
}

async function safeRemoveCreated(target, expectedParent, expectedPrefix) {
  const resolved = path.resolve(target);
  if (path.dirname(resolved) !== expectedParent || !path.basename(resolved).startsWith(expectedPrefix)) {
    throw new Error(`Refusing to remove unexpected recovery path: ${resolved}`);
  }
  await rm(resolved, { recursive: true, force: true });
}

export async function writeArtifactBundle(targetPath, preset, artifacts, { force = false } = {}) {
  const target = validateTarget(targetPath);
  const parent = path.dirname(target);
  const basename = path.basename(target);
  await mkdir(parent, { recursive: true });
  await rejectLink(target);
  const targetExists = await exists(target);
  if (targetExists && !force) throw new Error(`Output bundle already exists: ${target}. Pass --force to replace it.`);

  const stagingPrefix = `.${basename}.secretgen-staging-`;
  const backupPrefix = `.${basename}.secretgen-backup-`;
  const staging = path.join(parent, `${stagingPrefix}${randomUUID()}`);
  const backup = path.join(parent, `${backupPrefix}${randomUUID()}`);
  await mkdir(staging, { mode: 0o700 });

  let backupCreated = false;
  try {
    const width = Math.max(3, String(artifacts.length).length);
    for (let i = 0; i < artifacts.length; i += 1) {
      const directory = artifacts.length === 1 ? staging : path.join(staging, String(i + 1).padStart(width, '0'));
      if (artifacts.length > 1) await mkdir(directory, { mode: 0o700 });
      for (const part of artifacts[i].parts) await writePart(directory, part);
    }
    await writeManifest(staging, preset, artifacts);
    if (process.platform === 'win32') await secureWindowsDirectory(staging);

    if (targetExists) {
      await rename(target, backup);
      backupCreated = true;
    }
    await rename(staging, target);
    if (backupCreated) {
      try {
        await safeRemoveCreated(backup, parent, backupPrefix);
      } catch (cleanupError) {
        await rename(target, staging);
        await rename(backup, target);
        backupCreated = false;
        throw cleanupError;
      }
    }
    return target;
  } catch (error) {
    if (backupCreated && !(await exists(target)) && await exists(backup)) await rename(backup, target);
    if (await exists(staging)) await safeRemoveCreated(staging, parent, stagingPrefix);
    throw error;
  }
}

export async function readPassphraseFile(filename) {
  let value = await readFile(filename, 'utf8');
  value = value.replace(/\r?\n$/u, '');
  if (!value || value.includes('\0')) throw new Error('Passphrase file must contain a non-empty value without NUL characters.');
  return value;
}
