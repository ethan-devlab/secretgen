# @ethan-devlab/secretgen

A Node.js 22+ CLI and library for cryptographically secure secrets, provisioning bundles, public nonce/salt material, and asymmetric key artifacts. It includes **67 presets**: the original 30 scalar presets plus 37 new presets.

## Quick start

```bash
npx -y @ethan-devlab/secretgen
npx -y @ethan-devlab/secretgen django
npx -y @ethan-devlab/secretgen generic:password --length 48
npx -y @ethan-devlab/secretgen --list
```

The interactive terminal first lets you search for a preset. It then prompts for that preset's length, byte count, algorithm, encoding, or other options. Press Enter at an option prompt to accept its displayed default.

Install as a CLI or library:

```bash
npm install -g @ethan-devlab/secretgen
npm install @ethan-devlab/secretgen
```

```js
import { generate, generateArtifact } from '@ethan-devlab/secretgen';

const password = generate('generic:password', { length: 48 });
const passphrase = generate('generic:passphrase', { words: 8, separator: 'hyphen' });
const keypair = await generateArtifact('pem:keypair', { algorithm: 'ed25519' });
```

`generate()` remains the synchronous scalar API. Multi-part presets use the asynchronous `generateArtifact()` API.

## Presets

Run `secretgen --list` for all aliases and configurable flags, or `secretgen --info <preset>` for option ranges and defaults.

The 30 original presets remain available:

- Generic and Python: `generic:hex`, `generic:base64`, `generic:base64url`, `generic:alphanumeric`, `generic:password`, `python:token-hex`, `python:token-urlsafe`
- Frameworks: `django:secret-key`, `flask:secret-key`, `fastapi:jwt-secret`, `cryptography:fernet`, `express:session-secret`, `express:cookie-secret`, `authjs:secret`, `iron-session:password`, `rails:secret-key-base`, `laravel:app-key`, `symfony:app-secret`, `phoenix:secret-key-base`, `wordpress:salts`
- Cryptography: `jwt:hs256`, `jwt:hs384`, `jwt:hs512`, `aes:128`, `aes:192`, `aes:256`, `chacha20-poly1305:key`, `hmac:sha256`, `hmac:sha512`, `totp:secret`

The 37 additions are:

- Scalars and application secrets: `generic:base32`, `generic:urlsafe-string`, `generic:passphrase`, `uuid:v4`, `uuid:v7`, `better-auth:secret`, `nuxt:session-password`, `adonis:app-key`, `codeigniter:encryption-key`, `spring:base64-key`, `github:webhook-secret`, `oauth:pkce-verifier`, `rails:master-key`, `wireguard:preshared-key`, `paseto:v4-local-key`, `hmac:sha384`, `hotp:secret`, `sodium:secretbox-key`
- Provisioning and material bundles: `hotp:provisioning`, `totp:provisioning`, `mfa:recovery-codes`, `aspnet:machine-key`, `salt:argon2`, `nonce:aes-gcm`, `nonce:chacha20-poly1305`, `nonce:xchacha20-poly1305`, `iv:aes-cbc`
- Key artifacts: `pem:keypair`, `jwk:keypair`, `jwks:keyset`, `openssh:keypair`, `wireguard:keypair`, `age:keypair`, `paseto:v4-public-keypair`, `sodium:box-keypair`, `sodium:sign-keypair`, `dkim:keypair`

Provider-issued API keys, access tokens, certificates, CSRs, password hashes, and legacy weak formats are intentionally out of scope. Those values require an issuer, an application policy, or a different lifecycle than local random generation.

## CLI

```text
secretgen                              # searchable menu, then option prompts
secretgen <preset> [preset options]   # direct generation
secretgen --list
secretgen --info <preset>

-b, --bytes <n>                       # byte-configurable presets
    --length <n>                      # character-configurable presets
-n, --count <n>                       # scalar or artifact batch
    --format raw|env|json             # scalar output; artifacts default to JSON
    --env-name <NAME>                 # scalar env output
    --output-dir <path>               # artifact bundle directory
    --part <role|filename>            # one raw artifact part on stdout
    --force                           # replace an existing bundle
    --passphrase-env <NAME>           # private-key passphrase source
    --passphrase-file <path>          # private-key passphrase source
-i, --interactive                     # prompt for a named preset's options
```

Direct examples:

```bash
secretgen generic:password --length 64
secretgen generic:passphrase --words 8 --separator underscore
secretgen totp:provisioning --account alice@example.com --issuer Example
secretgen totp:provisioning --part provisioning-uri
secretgen jwk:keypair --algorithm ec --curve P-384 --output-dir ./signing-key
secretgen dkim:keypair --selector mail --domain example.com --output-dir ./dkim
```

Scalar raw mode prints only generated values to stdout. Artifact mode prints a JSON envelope by default. Binary parts in that envelope use Base64. `--part` selects one role or filename and writes its raw content.

Artifact batches use numbered subdirectories. RSA and DKIM RSA generation is limited to 10 artifacts per command; other artifact presets are limited to 100; scalar presets are limited to 1,000.

## Private-key encryption

`pem:keypair` and `openssh:keypair` can encrypt private keys. Interactive mode asks for the passphrase twice without echo. Scripts must use an environment variable or file; secretgen deliberately has no literal `--passphrase` argument.

```bash
export SECRETGEN_KEY_PASSPHRASE='use a secret source in real automation'
secretgen pem:keypair --encrypt-private-key \
  --passphrase-env SECRETGEN_KEY_PASSPHRASE \
  --output-dir ./keys
```

For a batch, one passphrase encrypts all private keys generated by that command. Passphrase files may end in one newline; the newline is not part of the passphrase.

## Artifact file safety

Artifact output is written to a sibling staging directory before it is moved into place. Existing targets are rejected unless `--force` is present. Symbolic-link and junction targets are rejected.

- POSIX: bundle directories use mode `0700`; secret parts and the manifest use `0600`; public parts use `0644`.
- Windows: inherited ACLs are removed from the bundle and every file. Access is granted only to the current user and Local System. If ACL hardening fails, generation fails before the bundle is installed.
- `secretgen-manifest.json` describes roles, filenames, media types, encodings, and metadata. It never duplicates part contents.

Treat stdout JSON as sensitive for keypair and provisioning presets because it can contain private keys or OTP seeds.

## Security design

- Secret randomness comes from Node.js `node:crypto` or the selected cryptographic library's CSPRNG.
- No `Math.random()`, seed option, telemetry, or network calls.
- Fixed-format presets reject incompatible size overrides.
- EFF long-list passphrases use unbiased CSPRNG word selection.
- UUID v4 and v7 set their required version and variant bits.
- Salts, nonces, and IV presets label their material as public and unique-per-operation. They are not reusable encryption keys.
- Aliases resolve through one registry, and typed option validation is shared by the CLI and library APIs.

An ecosystem preset generates a locally created value in the documented format. It does not contact or impersonate the named provider or framework.

## Local development

```bash
npm install
npm test
npm run check
node ./bin/secretgen.js generic:password --length 48
```
