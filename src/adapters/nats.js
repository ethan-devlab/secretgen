const constructors = {
  user: 'createUser',
  account: 'createAccount',
  operator: 'createOperator',
  server: 'createServer',
  cluster: 'createCluster',
};

export async function generateNatsKeyPair(type) {
  const module = await import('@nats-io/nkeys');
  const nkeys = module.default ?? module;
  const constructor = nkeys[constructors[type]];
  if (!constructor) throw new Error(`Unsupported NATS NKey type: ${type}`);
  const pair = constructor();
  return {
    seed: new TextDecoder().decode(pair.getSeed()),
    publicKey: pair.getPublicKey(),
  };
}
