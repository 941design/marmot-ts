# marmot-ts

TypeScript implementation of the [Marmot protocol](https://github.com/marmot-protocol/marmot) — end-to-end encrypted group messaging on Nostr using [MLS (Messaging Layer Security)](https://messaginglayersecurity.rocks/).

> [!WARNING]
> This library is in **Alpha** and under heavy development. The API is subject to breaking changes without notice. It relies on [ts-mls](https://github.com/LukaJCB/ts-mls) for MLS cryptographic guarantees. Do not use in production yet.

## Features

- 🔐 **End-to-end encrypted** group messaging using MLS (RFC 9420)
- 🌐 **Decentralized** — groups operate across Nostr relays
- 🔑 **Key package lifecycle** — publishing, rotation, deletion
- 📦 **Storage-agnostic** — bring any `GenericKeyValueStore` backend (LocalForage, IndexedDB, in-memory, …)
- 🔌 **Network-agnostic** — works with any Nostr client library
- 📱 **Cross-platform** — browsers and Node.js (v20+)

## Marmot Protocol Compliance

`marmot-ts` currently supports the following [Marmot Improvement Proposals (MIPs)](https://github.com/marmot-protocol/mips):

| MIP                                                                        | Description                             | Status       |
| -------------------------------------------------------------------------- | --------------------------------------- | ------------ |
| [MIP-00](https://github.com/marmot-protocol/mips/blob/main/mips/mip-00.md) | Introduction and Basic Operations       | ✅ Supported |
| [MIP-01](https://github.com/marmot-protocol/mips/blob/main/mips/mip-01.md) | Network Transport & Relay Communication | ✅ Supported |
| [MIP-02](https://github.com/marmot-protocol/mips/blob/main/mips/mip-02.md) | Identities and Keys                     | ✅ Supported |
| [MIP-03](https://github.com/marmot-protocol/mips/blob/main/mips/mip-03.md) | Group State & Memberships               | ✅ Supported |

## Installation

`ts-mls` is a **peer dependency** — you must install it alongside `marmot-ts`. This ensures there is exactly one copy of `ts-mls` in your module graph, which is required because `ts-mls` uses nominal (branded) types. Two copies would make its types structurally incompatible.

```bash
npm install @internet-privacy/marmot-ts ts-mls@2.0.0-rc.10
# or
pnpm add @internet-privacy/marmot-ts ts-mls@2.0.0-rc.10
```

### Co-development topology (workspace)

If you are developing against an unreleased or locally-modified `marmot-ts`, use a **pnpm workspace** that contains both packages. This ensures pnpm satisfies `marmot-ts`'s `ts-mls` peer dependency from the workspace root, keeping a single shared instance:

```yaml
# pnpm-workspace.yaml at your repo root
packages:
  - packages/marmot-ts   # your marmot-ts fork/checkout
  - packages/your-app    # your consumer
```

```jsonc
// packages/your-app/package.json
{
  "dependencies": {
    "@internet-privacy/marmot-ts": "workspace:*",
    "ts-mls": "2.0.0-rc.10"
  }
}
```

A `file:`-link to a dev tree **without** a workspace (e.g. `"@internet-privacy/marmot-ts": "file:../marmot-ts"`) does not reliably deduplicate `ts-mls` — the dev tree's own `node_modules/ts-mls` (from its `devDependencies`) is found via realpath and creates a second instance, causing TypeScript `TS2345` brand-mismatch errors at build time. Use a workspace instead.

## Concepts

A `MarmotClient` needs four things to operate:

1. **A signer** (`EventSigner`) — signs Nostr events on behalf of the user.
2. **A network interface** (`NostrNetworkInterface`) — publishes, requests, and subscribes to events on relays.
3. **A group state store** — persists serialized MLS group state.
4. **A key package store** — persists local key package material.

Both stores share a single interface: `GenericKeyValueStore<T>`.

## Storage

```ts
interface GenericKeyValueStore<T> {
  getItem(key: string): Promise<T | null>;
  setItem(key: string, value: T): Promise<T>;
  removeItem(key: string): Promise<void>;
  clear(): Promise<void>;
  keys(): Promise<string[]>;
}
```

Any backend that matches this shape works. [LocalForage](https://github.com/localForage/localForage) instances satisfy it directly:

To begin using the client, you need an `EventSigner` (e.g. from `applesauce-core`), a `NostrNetworkInterface` implementation, and two `GenericKeyValueStore` backends — one for serialized group state bytes and one for key package metadata.

```typescript
import { MarmotClient, generateKeyPackageSlot } from "@internet-privacy/marmot-ts";
import localforage from "localforage";

// Mint a per-device slot once and persist it (e.g. in localStorage). Calling
// generateKeyPackageSlot() afresh on every page load would defeat the point of
// an addressable key-package slot — relays replace events under the same
// (pubkey, kind, d) coordinate, so the d value must be stable for the device.
const slotStore = window.localStorage;
let clientId = slotStore.getItem("marmot.clientId");
if (!clientId) {
  clientId = generateKeyPackageSlot();
  slotStore.setItem("marmot.clientId", clientId);
}

const client = new MarmotClient({
  signer: yourNostrSigner,
  // Any GenericKeyValueStore<SerializedClientState>. A LocalForage instance
  // works directly because it already implements the getItem/setItem/keys API.
  groupStateStore: localforage.createInstance({ name: "marmot-groups" }),
  // Any GenericKeyValueStore<StoredKeyPackage> for key package metadata.
  keyPackageStore: localforage.createInstance({ name: "marmot-keypackages" }),
  // Your NostrNetworkInterface implementation (publish, request, subscription, getUserInboxRelays).
  network: yourNetworkInterface,
  // Stable per-device slot identifier (`d` tag) for addressable (kind 30443) key
  // packages. MUST be 64 lowercase hex characters per MIP-00; free-form labels
  // such as "my-app-desktop" are rejected at create()/rotate() time.
  clientId,
});
```

For tests or short-lived processes, the library ships an in-memory implementation:

```ts
import { InMemoryKeyValueStore } from "@internet-privacy/marmot-ts";

const groupStateStore = new InMemoryKeyValueStore();
const keyPackageStore = new InMemoryKeyValueStore();
```

## Quick Start

### Create the client

```ts
import { MarmotClient } from "@internet-privacy/marmot-ts";

const client = new MarmotClient({
  signer, // your EventSigner (e.g. from applesauce-core)
  network, // your NostrNetworkInterface implementation
  groupStateStore, // GenericKeyValueStore<SerializedClientState>
  keyPackageStore, // GenericKeyValueStore<StoredKeyPackage>
  clientId: "my-app-desktop", // stable d-tag for kind 30443 key packages
});
```

### Publish a key package

Other users invite you by referencing a key package you've published to relays.

```ts
await client.keyPackages.create({
  relays: ["wss://relay.example.com"],
});
```

### Create a group

```ts
const group = await client.groups.create("My Secret Group", {
  description: "A private discussion",
  relays: ["wss://relay.example.com"],
});
```

### Send a message

```ts
await group.sendChatMessage("Hello, world!");
```

### Invite a member

Look up their key package event on a relay, then invite by event:

```ts
const [keyPackageEvent] = await client.network.request(
  ["wss://relay.example.com"],
  [{ kinds: [30443], authors: [memberPubkey], limit: 1 }],
);

if (keyPackageEvent) {
  await group.inviteByKeyPackageEvent(keyPackageEvent);
}
```

### Join a group from an invite

When you receive a kind 1059 gift wrap, decrypt it to a kind 444 rumor and pass it to `joinGroupFromWelcome`:

```ts
const { group } = await client.joinGroupFromWelcome({ welcomeRumor });
```

### Receive messages

Subscribe to the group's relays for kind 445 events and feed them to `group.ingest`:

```ts
import { bytesToHex } from "@noble/hashes/utils.js";

const subscription = client.network.subscription(group.relays, [
  { kinds: [445], "#h": [bytesToHex(group.groupData.nostrGroupId)] },
]);

subscription.subscribe({
  next: async (event) => {
    for await (const result of group.ingest([event])) {
      if (result.kind === "applicationMessage") {
        console.log(result.message);
      }
    }
  },
});
```

## Documentation

Full documentation is in `docs/` and served via VitePress. Run `pnpm docs:dev` to browse locally.

- **[Getting Started](docs/getting-started.md)** — first-run walkthrough
- **[Architecture](docs/guide/architecture.md)** — component overview and Nostr/MLS mapping
- **[Client Module](docs/client/)** — `MarmotClient`, `MarmotGroup`, storage, network, UI integration
- **[Core Module](docs/core/)** — protocol, credentials, key packages, groups, messages, welcome

## Development

```bash
pnpm install    # Install dependencies
pnpm build      # Compile TypeScript
pnpm test       # Run tests (watch mode)
pnpm format     # Format code with Prettier
pnpm docs:dev   # Serve documentation locally
pnpm docs:build # Build documentation
```
