import readline from 'node:readline';
import { createInterface } from 'node:readline/promises';
import { getPresets } from './registry.js';
import { optionIsActive } from './schema.js';

const CLEAR = '\x1b[2J\x1b[H';
const HIDE_CURSOR = '\x1b[?25l';
const SHOW_CURSOR = '\x1b[?25h';
const DIM = '\x1b[2m';
const RESET = '\x1b[0m';
const CYAN = '\x1b[36m';
const BOLD = '\x1b[1m';

export async function choosePreset() {
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    throw new Error('Interactive mode requires a TTY. Specify a preset or run with --list.');
  }

  const presets = getPresets();
  let query = '';
  let cursor = 0;
  let filtered = presets;

  readline.emitKeypressEvents(process.stdin);
  process.stdin.setRawMode(true);
  process.stdin.resume();
  process.stdout.write(HIDE_CURSOR);

  const cleanup = () => {
    process.stdin.setRawMode(false);
    process.stdin.pause();
    process.stdout.write(SHOW_CURSOR + RESET);
  };

  const refresh = () => {
    const q = query.trim().toLowerCase();
    filtered = q
      ? presets.filter((p) => [p.id, p.label, p.category, ...p.aliases].join(' ').toLowerCase().includes(q))
      : presets;

    if (cursor >= filtered.length) cursor = Math.max(0, filtered.length - 1);

    const terminalRows = process.stdout.rows || 24;
    const maxVisible = Math.max(6, Math.min(14, terminalRows - 9));
    const start = Math.max(0, Math.min(cursor - Math.floor(maxVisible / 2), Math.max(0, filtered.length - maxVisible)));
    const visible = filtered.slice(start, start + maxVisible);

    let out = CLEAR;
    out += `${BOLD}secretgen${RESET} — choose a secret preset\n`;
    out += `${DIM}↑/↓ or j/k move · type to filter · Backspace edits · Enter selects · Esc/q exits${RESET}\n\n`;
    out += `Search: ${CYAN}${query || '…'}${RESET}\n\n`;

    if (visible.length === 0) {
      out += '  No matching presets.\n';
    } else {
      for (let i = 0; i < visible.length; i += 1) {
        const absolute = start + i;
        const preset = visible[i];
        const pointer = absolute === cursor ? `${CYAN}❯${RESET}` : ' ';
        const selected = absolute === cursor ? BOLD : '';
        out += `${pointer} ${selected}${preset.id.padEnd(30)}${RESET} ${DIM}${preset.label}${RESET}\n`;
      }
    }

    out += `\n${DIM}${filtered.length} / ${presets.length} presets${RESET}`;
    if (filtered[cursor]) {
      out += `\n${DIM}${filtered[cursor].description}${RESET}`;
    }
    process.stdout.write(out);
  };

  refresh();

  return new Promise((resolve, reject) => {
    const onKey = (str, key) => {
      if (key.ctrl && key.name === 'c') {
        process.stdin.off('keypress', onKey);
        cleanup();
        process.stdout.write('\n');
        process.exitCode = 130;
        resolve(null);
        return;
      }

      if (key.name === 'escape' || (key.name === 'q' && query === '')) {
        process.stdin.off('keypress', onKey);
        cleanup();
        process.stdout.write('\n');
        resolve(null);
        return;
      }

      if (key.name === 'up' || (key.name === 'k' && query === '')) {
        if (filtered.length) cursor = (cursor - 1 + filtered.length) % filtered.length;
        refresh();
        return;
      }

      if (key.name === 'down' || (key.name === 'j' && query === '')) {
        if (filtered.length) cursor = (cursor + 1) % filtered.length;
        refresh();
        return;
      }

      if (key.name === 'return') {
        const selected = filtered[cursor];
        if (!selected) return;
        process.stdin.off('keypress', onKey);
        cleanup();
        process.stdout.write(CLEAR);
        resolve(selected);
        return;
      }

      if (key.name === 'backspace') {
        query = query.slice(0, -1);
        cursor = 0;
        refresh();
        return;
      }

      if (!key.ctrl && !key.meta && str && str >= ' ' && str !== '\x7f') {
        query += str;
        cursor = 0;
        refresh();
      }
    };

    process.stdin.on('keypress', onKey);
    process.stdin.once('error', (error) => {
      process.stdin.off('keypress', onKey);
      cleanup();
      reject(error);
    });
  });
}

function optionPrompt(option) {
  if (option.type === 'integer') {
    return `${option.name} (${option.unit ?? 'number'}, ${option.min}..${option.max}) [${option.default}]: `;
  }
  if (option.type === 'enum') return `${option.name} (${option.choices.join(' | ')}) [${option.default}]: `;
  if (option.type === 'boolean') return `${option.name} (${option.default ? 'Y/n' : 'y/N'}): `;
  return `${option.name}${option.default !== undefined ? ` [${option.default}]` : ''}: `;
}

const BACK = Symbol('interactive-back');

function parseInteractiveValue(option, answer) {
  if (answer === '') return option.default;
  if (option.type === 'integer') {
    if (!/^\d+$/u.test(answer)) throw new Error('Enter an integer.');
    const value = Number(answer);
    if (value < option.min || value > option.max) throw new Error(`Enter a value between ${option.min} and ${option.max}.`);
    return value;
  }
  if (option.type === 'enum') {
    const choice = option.choices.find((value) => value.toLowerCase() === answer.toLowerCase());
    if (!choice) throw new Error(`Choose one of: ${option.choices.join(', ')}.`);
    return choice;
  }
  if (option.type === 'boolean') {
    if (/^(y|yes)$/iu.test(answer)) return true;
    if (/^(n|no)$/iu.test(answer)) return false;
    throw new Error('Enter y or n.');
  }
  return answer;
}

async function hiddenQuestion(prompt) {
  const input = process.stdin;
  const output = process.stdout;
  readline.emitKeypressEvents(input);
  input.setRawMode(true);
  input.resume();
  output.write(prompt);

  return new Promise((resolve, reject) => {
    let value = '';
    const cleanup = () => {
      input.off('keypress', onKey);
      input.off('error', onError);
      input.setRawMode(false);
      input.pause();
    };
    const onError = (error) => {
      cleanup();
      reject(error);
    };
    const onKey = (str, key) => {
      if (key.ctrl && key.name === 'c') {
        cleanup();
        output.write('\n');
        const error = new Error('Interactive input cancelled.');
        error.exitCode = 130;
        reject(error);
        return;
      }
      if (key.name === 'return') {
        cleanup();
        output.write('\n');
        resolve(value);
        return;
      }
      if (key.name === 'escape') {
        cleanup();
        output.write('\n');
        resolve(BACK);
        return;
      }
      if (key.name === 'backspace') {
        value = value.slice(0, -1);
        return;
      }
      if (!key.ctrl && !key.meta && str && str >= ' ' && str !== '\x7f') value += str;
    };
    input.on('keypress', onKey);
    input.once('error', onError);
  });
}

export async function configurePreset(preset, supplied = {}) {
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    throw new Error('Interactive configuration requires a TTY.');
  }

  const values = { ...supplied };
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  const prompted = [];
  try {
    process.stdout.write(`\n${BOLD}${preset.id}${RESET}\n${DIM}${preset.description}${RESET}\n\n`);
    process.stdout.write(`${DIM}Enter accepts the default · Esc or :back returns to the previous option${RESET}\n\n`);
    for (let index = 0; index < preset.options.length;) {
      const option = preset.options[index];
      if (option.secret || supplied[option.name] !== undefined || !optionIsActive(option, values)) {
        index += 1;
        continue;
      }
      while (true) {
        let escapeRequested = false;
        const onKeypress = (_str, key) => {
          if (key.name === 'escape') {
            escapeRequested = true;
            rl.write(null, { name: 'return' });
          }
        };
        readline.emitKeypressEvents(process.stdin, rl);
        process.stdin.on('keypress', onKeypress);
        let answer;
        try {
          answer = await rl.question(optionPrompt(option));
        } finally {
          process.stdin.off('keypress', onKeypress);
        }
        if (escapeRequested || answer.trim() === ':back') {
          const previous = prompted.pop();
          if (previous === undefined) return null;
          delete values[preset.options[previous].name];
          index = previous;
          break;
        }
        try {
          const value = parseInteractiveValue(option, answer.trim());
          if (value !== undefined) values[option.name] = value;
          prompted.push(index);
          index += 1;
          break;
        } catch (error) {
          process.stdout.write(`  ${error.message}\n`);
        }
      }
    }
  } finally {
    rl.close();
  }

  if (values.encryptPrivateKey) {
    while (true) {
      const first = await hiddenQuestion('Private-key passphrase: ');
      if (first === BACK) return null;
      if (!first) {
        process.stdout.write('  Passphrase may not be empty.\n');
        continue;
      }
      const second = await hiddenQuestion('Confirm passphrase: ');
      if (second === BACK) continue;
      if (first !== second) {
        process.stdout.write('  Passphrases do not match.\n');
        continue;
      }
      values.passphrase = first;
      break;
    }
  }
  return values;
}

export async function chooseArtifactOutput() {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  try {
    const answer = (await rl.question('Output bundle directory, or Enter for stdout JSON: ')).trim();
    return answer || null;
  } finally {
    rl.close();
  }
}
