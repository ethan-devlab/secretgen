import { getPreset, getPresets, requirePreset } from './registry.js';
import { resolvePresetOptions } from './schema.js';

export function generate(name, options = {}) {
  const preset = requirePreset(name);
  if (preset.kind !== 'scalar') {
    throw new Error(`${preset.id} is an artifact preset; use generateArtifact().`);
  }
  return preset.generate(resolvePresetOptions(preset, options));
}

export async function generateArtifact(name, options = {}) {
  const preset = requirePreset(name);
  if (preset.kind !== 'artifact') {
    throw new Error(`${preset.id} is a scalar preset; use generate().`);
  }
  const artifact = await preset.generate(resolvePresetOptions(preset, options));
  if (!artifact || artifact.kind !== 'artifact' || !Array.isArray(artifact.parts) || artifact.parts.length === 0) {
    throw new Error(`${preset.id} returned an invalid artifact.`);
  }
  return { preset: preset.id, ...artifact };
}

export { getPreset, getPresets };
