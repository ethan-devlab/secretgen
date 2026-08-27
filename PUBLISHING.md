# Publishing @ethan-devlab/secretgen to npm

## 1. Sign in and verify your npm account

```bash
npm login
npm whoami
```

For an initial manual publish, configure npm account 2FA first. Do not store an npm access token in this repository.

## 2. Validate before publishing

```bash
npm test
npm pack --dry-run
```

Inspect the dry-run output. This package intentionally publishes only `bin/`, `src/`, `README.md`, `LICENSE`, and `package.json`.

Optionally build the exact tarball and install it into a clean temporary project:

```bash
npm pack
mkdir /tmp/secretgen-smoke
cd /tmp/secretgen-smoke
npm init -y
npm install /absolute/path/to/ethan-devlab-secretgen-0.1.0.tgz
./node_modules/.bin/secretgen django
./node_modules/.bin/secretgen fernet
```

## 3. First public publish

A scoped package is private by default unless published with public access. For the first public release:

```bash
npm publish --access public
```

Then test the registry package from a directory that is not the repository:

```bash
npx -y @ethan-devlab/secretgen django
npx -y @ethan-devlab/secretgen fernet
npx -y @ethan-devlab/secretgen
```

The third command requires an interactive TTY and opens the searchable menu.

## 4. Publish later versions

Never reuse an already-published version. For a patch release:

```bash
npm version patch
npm test
npm pack --dry-run
npm publish
```

Use `npm version minor` or `npm version major` when SemVer requires it.

## 5. CI/CD later

Once the package and repository are stable, prefer npm Trusted Publishing (OIDC) for GitHub Actions or another supported CI provider instead of maintaining a long-lived publish token.

## Release checklist

- Tests pass.
- `npm pack --dry-run` contains only intended files.
- Package scope and README examples use `@ethan-devlab/secretgen`.
- Version is new and follows SemVer.
- No secrets, `.env` files, credentials, or private fixtures are present.
- Manual publish uses an account protected by 2FA.
- After publishing, both direct `npx` mode and interactive `npx` mode are smoke-tested from outside the repository.
