# agentvault-mls-rs-uniffi

AgentVault's patched UniFFI Python bindings for [mls-rs] (RFC 9420 Messaging Layer Security).

[mls-rs]: https://github.com/awslabs/mls-rs

## What's in this fork

This is a fork of upstream `awslabs/mls-rs` published as a Python wheel. It adds three additive UniFFI exports needed for wire-format interop with [`ts-mls`](https://github.com/LukasMasuch/ts-mls):

- `Group.export_secret(label, context, len)` — RFC 9420 §8.5
- `Message.to_bytes()` — serialize to wire bytes
- `Message.from_bytes(bytes)` — deserialize from wire bytes

The patches are additive (no breaking changes) and are intended to be upstreamed to `awslabs/mls-rs`. Once upstreamed and a release is cut, this package will be deprecated in favor of the upstream wheel.

## Install

```bash
pip install agentvault-mls-rs-uniffi
```

Wheels are published for:

- Linux x86_64 (manylinux2014)
- macOS universal2 (x86_64 + arm64)
- Windows x86_64
- Python 3.10, 3.11, 3.12, 3.13

## Usage

```python
from mls_rs_uniffi import Client, ClientConfig, generate_signature_keypair, CipherSuite

config = ClientConfig()
keypair = generate_signature_keypair(CipherSuite.CURVE25519_AES128)
client = Client(name=b"alice", signature_keypair=keypair, client_config=config)
key_package = client.generate_key_package_message()
```

See the upstream [mls-rs-uniffi tests](https://github.com/motiveflowllc/mls-rs/tree/main/mls-rs-uniffi/tests) for more examples.

## Why a fork

Phase 0 of AgentVault's Hermes plugin validated wire-format interop between Python (mls-rs-uniffi) and Node (ts-mls), but `ts-mls` requires access to the message wire bytes and the group's exported secret — neither of which is exposed by upstream `mls-rs-uniffi` as of `v0.13.0`. The fork adds these as additive UniFFI methods. See [the patch](https://github.com/motiveflowllc/mls-rs/blob/agentvault/uniffi-export-secret-and-message-bytes/mls-rs-uniffi/src/lib.rs) for full diff.

## License

Apache-2.0 OR MIT (matching upstream).
