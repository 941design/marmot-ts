# Contributing to @internet-privacy/marmot-ts

Thank you for your interest in contributing to marmot-ts! This document provides guidelines and information for contributors.

## Getting Started

### Prerequisites

- Node.js LTS (>= 20.x)
- pnpm 10 (`npm install -g pnpm@10`)
- Git

### Setting Up Your Development Environment

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/marmot-ts.git
   cd marmot-ts
   ```
3. Install dependencies:
   ```bash
   pnpm install
   ```
4. Create a new branch for your changes:
   ```bash
   git checkout -b feature/your-feature-name
   ```

## Development Workflow

### Available Scripts

- `pnpm build` - Clean and compile the TypeScript code
- `pnpm compile` - Compile TypeScript files only (no clean)
- `pnpm test` / `pnpm vitest run` - Run the test suite
- `pnpm format` - Format code with Prettier
- `pnpm lint` - Check formatting

### Making Changes

1. Make your changes in the appropriate files
2. Add or update tests for your changes
3. Run linting and formatting:
   ```bash
   pnpm format
   pnpm lint
   ```
4. Run the test suite to ensure everything passes:
   ```bash
   pnpm vitest run
   ```
5. Build the project to ensure it compiles:
   ```bash
   pnpm build
   ```

## ts-mls Peer Dependency

`ts-mls` is declared as a **peer dependency** of `marmot-ts`. This is intentional and important: `ts-mls` uses nominal (branded) types (`unique symbol` properties on types like `CustomExtension`). If two physically distinct copies of `ts-mls` are present in the module graph, those brands are incompatible even at identical versions, causing `TS2345` type errors in consumers.

### Developing against a local marmot-ts (workspace topology)

If you are building an application that consumes a local fork or checkout of `marmot-ts`, use a **pnpm workspace** — not a `file:` link. The workspace ensures pnpm satisfies `marmot-ts`'s `ts-mls` peer from the workspace root, keeping a single shared instance:

```yaml
# your-project/pnpm-workspace.yaml
packages:
  - packages/marmot-ts   # your marmot-ts fork/checkout
  - packages/your-app
```

```jsonc
// your-project/packages/your-app/package.json
{
  "dependencies": {
    "@internet-privacy/marmot-ts": "workspace:*",
    "ts-mls": "2.0.0-rc.10"
  }
}
```

**Do not use a bare `file:` link** (e.g. `"@internet-privacy/marmot-ts": "file:../marmot-ts"`). The dev tree's `node_modules/ts-mls` (from its own `devDependencies`) is still found via the symlink realpath, creating a second instance and breaking TypeScript type-checking.

### Running the downstream type-check fixture locally

A minimal fixture at `fixtures/type-check-consumer/` verifies that `ts-mls` types are compatible across the module boundary. To run it:

```bash
# From the repo root
pnpm build && pnpm pack --pack-destination fixtures/type-check-consumer
cd fixtures/type-check-consumer
TARBALL=$(ls *.tgz | head -1)
pnpm add "file:./${TARBALL}" "ts-mls@2.0.0-rc.10" "typescript@~6.0.3"
pnpm run typecheck
```

This simulates a real consumer installing the packed (published) marmot-ts tarball alongside `ts-mls`, and confirms there is exactly one `ts-mls` instance in the module graph.
