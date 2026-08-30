import process from 'node:process';
import path from 'node:path';
import { generate, generateArtifact, getPreset, getPresets } from './index.js';
import { writeArtifactBundle, readPassphraseFile } from './artifact-files.js';
import { chooseArtifactOutput, choosePreset, configurePreset } from './interactive.js';
import { getCountLimit, resolvePresetOptions } from './schema.js';

const VERSION = '0.2.0';

function parseInteger(value, flag) {
  if (!/^\d+$/u.test(value ?? '')) throw new Error(`${flag} requires a positive integer.`);
  return Number(value);
}

function optionDefinitions() {
  const definitions = new Map();
  for (const preset of getPresets()) {
    for (const option of preset.options) {
      if (!option.cliName) continue;
      const existing = definitions.get(option.cliName);
      if (existing && existing.type !== option.type) throw new Error(`Internal option schema conflict for --${option.cliName}.`);
      definitions.set(option.cliName, option);
    }
  }
  return definitions;
}

function takeValue(argv, index, flag) {
  const value = argv[index + 1];
  if (value === undefined || value.startsWith('--')) throw new Error(`${flag} requires a value.`);
  return value;
}

export function parseArgs(argv) {
  const parsed = {
    preset: null,
    rawOptions: {},
    count: 1,
    format: null,
    envName: null,
    outputDir: null,
    part: null,
    force: false,
    passphraseEnv: null,
    passphraseFile: null,
    list: false,
    help: false,
    version: false,
    info: null,
    interactive: false,
  };
  const definitions = optionDefinitions();

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (!arg.startsWith('-')) {
      if (parsed.preset) throw new Error(`Unexpected positional argument: ${arg}`);
      parsed.preset = arg;
      continue;
    }

    switch (arg) {
      case '-b':
      case '--bytes':
        parsed.rawOptions.bytes = takeValue(argv, i, arg);
        i += 1;
        break;
      case '--length':
        parsed.rawOptions.length = takeValue(argv, i, arg);
        i += 1;
        break;
      case '-n':
      case '--count':
        parsed.count = parseInteger(takeValue(argv, i, arg), arg);
        i += 1;
        break;
      case '--format':
        parsed.format = takeValue(argv, i, arg);
        i += 1;
        if (!['raw', 'env', 'json'].includes(parsed.format)) throw new Error('--format must be one of: raw, env, json.');
        break;
      case '--env-name':
        parsed.envName = takeValue(argv, i, arg);
        i += 1;
        break;
      case '--output-dir':
        parsed.outputDir = takeValue(argv, i, arg);
        i += 1;
        break;
      case '--part':
        parsed.part = takeValue(argv, i, arg);
        i += 1;
        break;
      case '--force': parsed.force = true; break;
      case '--passphrase-env':
        parsed.passphraseEnv = takeValue(argv, i, arg);
        i += 1;
        break;
      case '--passphrase-file':
        parsed.passphraseFile = takeValue(argv, i, arg);
        i += 1;
        break;
      case '--list':
      case '-l': parsed.list = true; break;
      case '--info':
        parsed.info = takeValue(argv, i, arg);
        i += 1;
        break;
      case '-i':
      case '--interactive': parsed.interactive = true; break;
      case '-h':
      case '--help': parsed.help = true; break;
      case '-v':
      case '--version': parsed.version = true; break;
      default: {
        const negative = arg.startsWith('--no-');
        const name = negative ? arg.slice(5) : arg.slice(2);
        const definition = definitions.get(name);
        if (!arg.startsWith('--') || !definition) throw new Error(`Unknown argument: ${arg}`);
        if (definition.type === 'boolean') {
          parsed.rawOptions[definition.name] = !negative;
        } else {
          if (negative) throw new Error(`${arg} is only valid for boolean options.`);
          parsed.rawOptions[definition.name] = takeValue(argv, i, arg);
          i += 1;
        }
      }
    }
  }

  if (parsed.passphraseEnv && parsed.passphraseFile) throw new Error('--passphrase-env and --passphrase-file are mutually exclusive.');
  return parsed;
}

function parseOptionValue(option, raw) {
  if (typeof raw === 'boolean') return raw;
  if (option.type === 'integer') return parseInteger(raw, `--${option.cliName}`);
  if (option.type === 'enum') {
    const value = option.choices.find((choice) => choice.toLowerCase() === raw.toLowerCase());
    if (!value) throw new Error(`--${option.cliName} must be one of: ${option.choices.join(', ')}.`);
    return value;
  }
  return raw;
}

function coerceOptions(preset, rawOptions) {
  const definitions = new Map(preset.options.map((option) => [option.name, option]));
  const supplied = {};
  for (const [name, raw] of Object.entries(rawOptions)) {
    const option = definitions.get(name);
    if (!option) throw new Error(`${preset.id} does not accept option: ${name}.`);
    supplied[name] = parseOptionValue(option, raw);
  }
  return supplied;
}

function printHelp() {
  process.stdout.write(`secretgen ${VERSION}\n\n`);
  process.stdout.write('Generate cryptographically secure secrets and key artifacts.\n\n');
  process.stdout.write('Usage:\n');
  process.stdout.write('  secretgen                              Interactive preset and option prompts\n');
  process.stdout.write('  secretgen <preset> [options]           Generate directly\n');
  process.stdout.write('  secretgen --list                       List all presets\n');
  process.stdout.write('  secretgen --info <preset>              Show preset details\n\n');
  process.stdout.write('Common options:\n');
  process.stdout.write('  -b, --bytes <n>             Random byte count when supported\n');
  process.stdout.write('      --length <n>            Character count when supported\n');
  process.stdout.write('  -n, --count <n>             Generate multiple values or artifacts\n');
  process.stdout.write('      --format <type>         Scalar: raw | env | json; artifact: json or raw with --part\n');
  process.stdout.write('      --env-name <name>       Override the scalar environment variable name\n');
  process.stdout.write('      --output-dir <path>     Write an artifact or scalar bundle directory\n');
  process.stdout.write('      --part <role|filename>  Write one artifact part to stdout\n');
  process.stdout.write('      --force                 Replace an existing output bundle\n');
  process.stdout.write('      --passphrase-env <var>  Read a private-key passphrase from an environment variable\n');
  process.stdout.write('      --passphrase-file <p>   Read a private-key passphrase from a file\n');
  process.stdout.write('  -i, --interactive           Prompt for the selected preset options\n');
  process.stdout.write('  -l, --list                  List presets\n');
  process.stdout.write('  -h, --help                  Show help\n');
  process.stdout.write('  -v, --version               Show version\n\n');
  process.stdout.write('Preset-specific options are shown by --info. Examples:\n');
  process.stdout.write('  secretgen generic:password --length 48 --count 3\n');
  process.stdout.write('  secretgen totp:provisioning --account alice@example.com --issuer Example\n');
  process.stdout.write('  secretgen pem:keypair --algorithm rsa --bits 4096 --output-dir ./keys\n');
}

function optionSummary(option) {
  const flag = option.cliName ? `--${option.cliName}` : option.name;
  if (option.type === 'integer') return `${flag} ${option.min}..${option.max} (default ${option.default})`;
  if (option.type === 'enum') return `${flag} ${option.choices.join('|')} (default ${option.default})`;
  if (option.type === 'boolean') return `${flag}/--no-${option.cliName} (default ${option.default})`;
  return `${flag}${option.default !== undefined ? ` (default ${option.secret ? '<hidden>' : option.default})` : ''}`;
}

function printList() {
  const presets = getPresets();
  let currentCategory = null;
  for (const preset of presets) {
    if (preset.category !== currentCategory) {
      currentCategory = preset.category;
      process.stdout.write(`\n${currentCategory}\n`);
    }
    const configurable = preset.options.filter((option) => option.cliName).map((option) => `--${option.cliName}`).join(', ');
    process.stdout.write(`  ${preset.id.padEnd(31)} ${preset.label}${configurable ? ` [${configurable}]` : ''}\n`);
  }
  process.stdout.write(`\n${presets.length} presets total.\n`);
}

function printInfo(name) {
  const preset = getPreset(name);
  if (!preset) throw new Error(`Unknown preset: ${name}`);
  process.stdout.write(`${preset.id}\n`);
  process.stdout.write(`  ${preset.label}\n`);
  process.stdout.write(`  Category: ${preset.category}\n`);
  process.stdout.write(`  Kind: ${preset.kind}\n`);
  if (preset.kind === 'scalar') process.stdout.write(`  Sensitivity: ${preset.sensitivity}\n`);
  process.stdout.write(`  ${preset.description}\n`);
  process.stdout.write(`  Aliases: ${preset.aliases.join(', ') || '(none)'}\n`);
  if (preset.env) process.stdout.write(`  Suggested env: ${preset.env}\n`);
  if (preset.options.length === 0) process.stdout.write('  Options: fixed\n');
  else {
    process.stdout.write('  Options:\n');
    for (const option of preset.options.filter((item) => !item.secret)) {
      const condition = option.when ? `; when ${JSON.stringify(option.when)}` : '';
      process.stdout.write(`    ${optionSummary(option)}${condition}\n`);
    }
  }
}

function shellEnvValue(value) {
  return `'${String(value).replaceAll("'", "'\\''")}'`;
}

function formatValues(preset, values, format, envName) {
  if (format === 'raw') return values.join('\n');
  if (format === 'json') return JSON.stringify(values.length === 1 ? { preset: preset.id, value: values[0] } : { preset: preset.id, values }, null, 2);
  if (preset.multiline) throw new Error(`${preset.id} is multiline and does not support --format env; use raw or json.`);
  const key = envName || preset.env;
  if (!key) throw new Error(`${preset.id} has no default environment variable name; pass --env-name.`);
  return values.length === 1
    ? `${key}=${shellEnvValue(values[0])}`
    : values.map((value, index) => `${key}_${index + 1}=${shellEnvValue(value)}`).join('\n');
}

function serializeArtifact(artifact) {
  return {
    kind: artifact.kind,
    metadata: artifact.metadata,
    parts: artifact.parts.map((part) => ({
      role: part.role,
      filename: part.filename,
      mediaType: part.mediaType,
      secret: part.secret,
      encoding: part.encoding,
      data: part.encoding === 'binary' ? Buffer.from(part.data).toString('base64') : String(part.data),
    })),
  };
}

function artifactJson(preset, artifacts) {
  const serialized = artifacts.map(serializeArtifact);
  return JSON.stringify(artifacts.length === 1
    ? { preset: preset.id, artifact: serialized[0] }
    : { preset: preset.id, artifacts: serialized }, null, 2);
}

function scalarArtifact(preset, value) {
  const sensitivity = preset.sensitivity ?? 'secret';
  return {
    kind: 'artifact',
    metadata: { sensitivity },
    parts: [{
      role: preset.bundleRole ?? 'value',
      filename: preset.bundleFilename ?? 'value.txt',
      mediaType: 'text/plain',
      secret: sensitivity !== 'public',
      encoding: 'utf8',
      data: value,
    }],
  };
}

function writeSelectedPart(artifact, selector) {
  const matches = artifact.parts.filter((part) => part.role === selector || part.filename === selector);
  if (matches.length === 0) throw new Error(`Artifact has no part named ${selector}.`);
  if (matches.length > 1) throw new Error(`Artifact part selector is ambiguous: ${selector}.`);
  const part = matches[0];
  process.stdout.write(part.encoding === 'binary' ? Buffer.from(part.data) : String(part.data));
  if (part.encoding !== 'binary' && !String(part.data).endsWith('\n')) process.stdout.write('\n');
}

async function loadPassphrase(args) {
  if (args.passphraseEnv) {
    const value = process.env[args.passphraseEnv];
    if (!value) throw new Error(`Environment variable ${args.passphraseEnv} is missing or empty.`);
    return value;
  }
  if (args.passphraseFile) return readPassphraseFile(args.passphraseFile);
  return undefined;
}

export async function runCLI(argv = process.argv.slice(2)) {
  try {
    const args = parseArgs(argv);
    if (args.help) return printHelp();
    if (args.version) return process.stdout.write(`${VERSION}\n`);
    if (args.list) return printList();
    if (args.info) return printInfo(args.info);

    let preset = args.preset ? getPreset(args.preset) : null;
    if (args.preset && !preset) throw new Error(`Unknown preset: ${args.preset}. Run secretgen --list to see available presets.`);
    let supplied;
    while (true) {
      if (!preset) {
        preset = await choosePreset();
        if (!preset) return;
      }
      supplied = coerceOptions(preset, args.rawOptions);
      if (args.interactive || !args.preset) {
        supplied = await configurePreset(preset, supplied);
        if (supplied === null) {
          if (args.preset) return;
          preset = null;
          continue;
        }
      }
      break;
    }

    if (preset.kind === 'scalar' && (args.part || args.passphraseEnv || args.passphraseFile)) {
      throw new Error('--part and passphrase flags are only valid for artifact presets.');
    }
    const passphrase = await loadPassphrase(args);
    if (passphrase !== undefined) {
      if (!preset.options.some((option) => option.name === 'passphrase')) throw new Error(`${preset.id} does not support private-key passphrase encryption.`);
      if (supplied.encryptPrivateKey === false) throw new Error('A passphrase source conflicts with --no-encrypt-private-key.');
      supplied = { ...supplied, encryptPrivateKey: true, passphrase };
    }
    if (!args.interactive && supplied.encryptPrivateKey === true && supplied.passphrase === undefined) {
      throw new Error('Encrypted private keys require --passphrase-env or --passphrase-file.');
    }

    const options = resolvePresetOptions(preset, supplied);
    const countLimit = getCountLimit(preset, options);
    if (args.count < 1 || args.count > countLimit) throw new Error(`--count for ${preset.id} must be between 1 and ${countLimit}.`);

    if (preset.kind === 'scalar') {
      if (args.outputDir && (args.format || args.envName)) throw new Error('--output-dir cannot be combined with --format or --env-name.');
      if (args.force && !args.outputDir) throw new Error('--force requires --output-dir.');
      let outputDir = args.outputDir;
      if ((args.interactive || !args.preset) && !outputDir) outputDir = await chooseArtifactOutput('stdout');
      const values = Array.from({ length: args.count }, () => generate(preset.id, options));
      if (outputDir) {
        const artifacts = values.map((value) => scalarArtifact(preset, value));
        const written = await writeArtifactBundle(outputDir, preset.id, artifacts, { force: args.force });
        process.stdout.write(`${path.resolve(written)}\n`);
        return;
      }
      process.stdout.write(`${formatValues(preset, values, args.format ?? 'raw', args.envName)}\n`);
      return;
    }

    if (args.envName) throw new Error('--env-name is only valid for scalar presets.');
    if (args.format === 'env') throw new Error('Artifact presets do not support --format env.');
    if (args.part && args.count !== 1) throw new Error('--part requires --count 1.');
    if (args.part && args.outputDir) throw new Error('--part and --output-dir are mutually exclusive.');
    if (args.part && args.format && args.format !== 'raw') throw new Error('--part only supports --format raw.');
    if (args.outputDir && args.format) throw new Error('--format cannot be combined with --output-dir.');
    if (args.format === 'raw' && !args.part) throw new Error('Artifact --format raw requires --part.');
    if (args.force && !args.outputDir) throw new Error('--force requires --output-dir.');

    let outputDir = args.outputDir;
    if ((args.interactive || !args.preset) && !outputDir && !args.part) outputDir = await chooseArtifactOutput();
    const artifacts = [];
    for (let i = 0; i < args.count; i += 1) artifacts.push(await generateArtifact(preset.id, options));

    if (outputDir) {
      const written = await writeArtifactBundle(outputDir, preset.id, artifacts, { force: args.force });
      process.stdout.write(`${path.resolve(written)}\n`);
    } else if (args.part) {
      writeSelectedPart(artifacts[0], args.part);
    } else {
      process.stdout.write(`${artifactJson(preset, artifacts)}\n`);
    }
  } catch (error) {
    process.stderr.write(`secretgen: ${error.message}\n`);
    process.exitCode = error.exitCode ?? 1;
  }
}
