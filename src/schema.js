function cloneOption(option) {
  return {
    ...option,
    ...(option.choices ? { choices: [...option.choices] } : {}),
    ...(option.when ? { when: { ...option.when } } : {}),
  };
}

export function normalizePreset(preset) {
  const options = preset.options ?? (preset.option ? [
    {
      ...preset.option,
      type: 'integer',
      cliName: preset.option.name,
      unit: preset.option.name === 'bytes' ? 'bytes' : 'characters',
    },
  ] : []);

  return {
    kind: 'scalar',
    countLimit: 1000,
    ...preset,
    options: options.map(cloneOption),
  };
}

export function optionIsActive(option, values) {
  if (!option.when) return true;
  return Object.entries(option.when).every(([name, expected]) => values[name] === expected);
}

function validateInteger(option, value) {
  if (!Number.isInteger(value)) {
    throw new Error(`--${option.cliName ?? option.name} must be an integer.`);
  }
  if ((option.min !== undefined && value < option.min) || (option.max !== undefined && value > option.max)) {
    if (option.min !== undefined && option.max !== undefined) {
      throw new Error(`--${option.cliName ?? option.name} must be an integer between ${option.min} and ${option.max}.`);
    }
    if (option.min !== undefined) throw new Error(`--${option.cliName ?? option.name} must be at least ${option.min}.`);
    throw new Error(`--${option.cliName ?? option.name} may not exceed ${option.max}.`);
  }
}

function validateOption(option, value) {
  if (option.type === 'integer') return validateInteger(option, value);
  if (option.type === 'enum') {
    if (typeof value !== 'string' || !option.choices.includes(value)) {
      throw new Error(`--${option.cliName ?? option.name} must be one of: ${option.choices.join(', ')}.`);
    }
    return;
  }
  if (option.type === 'boolean') {
    if (typeof value !== 'boolean') throw new Error(`--${option.cliName ?? option.name} must be a boolean.`);
    return;
  }
  if (option.type === 'string') {
    if (typeof value !== 'string') throw new Error(`--${option.cliName ?? option.name} must be a string.`);
    if (option.required && value.length === 0) throw new Error(`--${option.cliName ?? option.name} may not be empty.`);
    if (option.minLength !== undefined && value.length < option.minLength) {
      throw new Error(`--${option.cliName ?? option.name} must contain at least ${option.minLength} characters.`);
    }
    if (option.maxLength !== undefined && value.length > option.maxLength) {
      throw new Error(`--${option.cliName ?? option.name} may not exceed ${option.maxLength} characters.`);
    }
    return;
  }
  throw new Error(`Unsupported option type for ${option.name}: ${option.type}`);
}

export function resolvePresetOptions(preset, supplied = {}) {
  if (!supplied || typeof supplied !== 'object' || Array.isArray(supplied)) {
    throw new TypeError('options must be an object');
  }

  const definitions = new Map(preset.options.map((option) => [option.name, option]));
  if (definitions.size === 0 && (supplied.bytes !== undefined || supplied.length !== undefined)) {
    throw new Error(`${preset.id} has a fixed format and does not accept --bytes or --length.`);
  }
  for (const name of Object.keys(supplied)) {
    if (!definitions.has(name)) throw new Error(`${preset.id} does not accept option: ${name}.`);
  }

  const values = {};
  for (const option of preset.options) {
    const value = supplied[option.name] ?? option.default;
    if (value !== undefined) values[option.name] = value;
  }

  for (const option of preset.options) {
    if (!optionIsActive(option, values)) {
      if (supplied[option.name] !== undefined) {
        throw new Error(`--${option.cliName ?? option.name} is not valid with the selected options.`);
      }
      delete values[option.name];
      continue;
    }
    const value = values[option.name];
    if (value === undefined) {
      if (option.required) throw new Error(`--${option.cliName ?? option.name} is required.`);
      continue;
    }
    validateOption(option, value);
  }

  if (preset.validateOptions) preset.validateOptions(values);
  return values;
}

export function getCountLimit(preset, options) {
  return typeof preset.countLimit === 'function' ? preset.countLimit(options) : preset.countLimit;
}
