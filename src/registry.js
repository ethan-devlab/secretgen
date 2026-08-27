import { ALL_PRESETS } from './catalog.js';
import { normalizePreset } from './schema.js';

const index = new Map();
const presets = ALL_PRESETS.map(normalizePreset);
for (const preset of presets) {
  for (const key of [preset.id, ...preset.aliases]) {
    const normalized = key.toLowerCase();
    if (index.has(normalized)) {
      throw new Error(`Duplicate preset id/alias: ${key}`);
    }
    index.set(normalized, preset);
  }
}

export function getPresets() {
  return presets.map((preset) => ({
    ...preset,
    aliases: [...preset.aliases],
    options: preset.options.map((option) => ({
      ...option,
      ...(option.choices ? { choices: [...option.choices] } : {}),
      ...(option.when ? { when: { ...option.when } } : {}),
    })),
  }));
}

export function getPreset(name) {
  if (!name) return null;
  return index.get(String(name).toLowerCase()) ?? null;
}

export function requirePreset(name) {
  const preset = getPreset(name);
  if (!preset) {
    throw new Error(`Unknown preset: ${name}. Run secretgen --list to see available presets.`);
  }
  return preset;
}

export function getCategories() {
  const categories = new Map();
  for (const preset of presets) {
    if (!categories.has(preset.category)) categories.set(preset.category, []);
    categories.get(preset.category).push(preset);
  }
  return categories;
}
