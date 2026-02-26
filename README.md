![CI](https://github.com/holepunchto/hyper-multisig/actions/workflows/ci.yml/badge.svg)

# Hyper Multisig

Create and manage multisig hypercores and hyperdrives.

Includes sanity checks to avoid common mistakes and risky releases (detecting conflicts before committing, ensuring all cores are seeded by multiple peers, etc.)

End users most likely want to use [hyper-multisig-cli](https://github.com/holepunchto/hyper-multisig-cli) instead of interacting directly with this module.

## Installation

```
npm install -g hyper-multisig
```

## API

#### `const multisig = new HyperMultisig(store, swarm)`

Create a new HyperMultisig instance.

- `store` - a [Corestore](https://github.com/holepunchto/corestore) instance
- `swarm` - a [Hyperswarm](https://github.com/holepunchto/hyperswarm) instance

#### `const { manifest, key, core } = await multisig.createCore(publicKeys, namespace, [options])`

Create a multisig hypercore.

- `publicKeys` - array of z32-encoded public keys from all signers
- `namespace` - string to avoid collisions (the combination of signers and namespace must be globally unique, as it deterministically defines the key of the resulting multisig hypercore)

Options include:
- quorum: minimum number of signatures required, defaults to half of public keys + 1

Returns `{ manifest, key, core }` where `core` is a read-only Hypercore.

#### `const { manifest, key, core, blobsManifest, blobsKey, blobsCore } = await multisig.createDrive(publicKeys, namespace, [options])`

Create a multisig hyperdrive (with associated blobs core).

Same parameters and options as `createCore`.

#### `const runner = multisig.requestCore(publicKeys, namespace, srcCore, length, [options])`

Generate a signing request from a source core.

- `publicKeys` - array of public keys
- `namespace` - namespace string
- `srcCore` - source Hypercore to create a request for
- `length` - length of the source core to use for the request

Options include:

```js
{
  force: false, // skip verification checks
  quorum, // override default quorum
  peerUpdateTimeout: 5000 // timeout in ms for peer updates
}
```

Call `await runner.done()` to get `{ manifest, request }`. The `request` is the signing request, as a buffer.

#### `const runner = multisig.requestDrive(publicKeys, namespace, srcDrive, length, [options])`

Generate a signing request for a source drive.

Same parameters and options as `requestCore`, but takes a Hyperdrive instead of a Hypercore.

Call `await runner.done()` to get `{ manifest, request }`.

#### `const runner = multisig.commitCore(publicKeys, namespace, srcCore, request, responses, [options])`

Commit signed data to a multisig core.

- `publicKeys` - array of public keys
- `namespace` - namespace string
- `srcCore` - source Hypercore that was signed
- `request` - the signing request
- `responses` - array of signed responses from signers

Options include:

```js
{
  quorum, // override default quorum
  dryRun: false, // perform validation without committing
  force: false, // advanced option, and dangerous
  skipTargetChecks: false, // only useful for the first commit
  peerUpdateTimeout: 5000, // timeout in ms for peer updates
  minFullCopies: 2 // minimum number of peers with a full copy of the core
}
```

Call `await runner.done()` to get `{ manifest, core, quorum, result }` where `quorum` is the amount of valid signatures.

The runner emits events during the commit process:

- `'verify-committable-start'` - fired with `(srcCoreKey, destCoreKey)`
- `'commit-start'` - fired when the commit begins
- `'verify-committed-start'` - fired with `(destCoreKey)` after the commit completes

#### `const runner = multisig.commitDrive(publicKeys, namespace, srcDrive, request, responses, [options])`

Commit signed data to a multisig drive.

Same parameters and options as `commitCore`, but takes a Hyperdrive instead of a Hypercore.

Call `await runner.done()` to get `{ manifest, core, blobsCore, quorum, result }`.

## Multisig flow

1. Each signer uses [hypercore-sign](https://github.com/holepunchto/hypercore-sign) to generate a key pair:

   ```sh
   hypercore-sign generate-keys
   ```

2. Collect all public keys and create a multisig core or drive with `createCore` or `createDrive`.

3. Generate a signing request with `requestCore` or `requestDrive`.

4. Each signer signs the request using [hypercore-sign](https://github.com/holepunchto/hypercore-sign):

   ```sh
   hypercore-sign <signingRequest>
   ```

5. Collect all signatures and commit with `commitCore` or `commitDrive`.

## License

Apache-2.0
