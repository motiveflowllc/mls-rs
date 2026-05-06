"""Verify Group.export_secret produces identical bytes for all members at the
same epoch, and different bytes after the epoch advances.

This test exercises the agentvault-hermes patch that adds export_secret to the
mls-rs-uniffi Python binding. It mirrors the AgentVault sub-protocol-key
derivation use case (e.g., per-session ratchet keys).
"""
from mls_rs_uniffi import (
    CipherSuite,
    Client,
    client_config_default,
    generate_signature_keypair,
)

config = client_config_default()
alice = Client(b"alice", generate_signature_keypair(CipherSuite.CURVE25519_AES128), config)
bob = Client(b"bob", generate_signature_keypair(CipherSuite.CURVE25519_AES128), config)

alice_group = alice.create_group(None)
bob_kp = bob.generate_key_package_message()

commit = alice_group.add_members([bob_kp])
alice_group.process_incoming_message(commit.commit_message)
bob_group = bob.join_group(None, commit.welcome_message).group

# 1) Same (label, context, len) at the same epoch → identical bytes.
label = b"agentvault.session.derivation"
context = b"v1"
length = 32

a1 = alice_group.export_secret(label, context, length)
b1 = bob_group.export_secret(label, context, length)
assert len(a1) == length, f"export_secret returned {len(a1)} bytes, expected {length}"
assert a1 == b1, "exporter secret diverged between alice and bob at epoch 1"
assert a1 != b"\x00" * length, "exporter secret is all-zeros — likely a bug"

# 2) Different label → different output for the same group + epoch.
a1_other = alice_group.export_secret(b"different.label", context, length)
assert a1_other != a1, "different label produced identical secret"

# 3) Different context → different output.
a1_ctx = alice_group.export_secret(label, b"v2", length)
assert a1_ctx != a1, "different context produced identical secret"

# 4) Advance the epoch (empty commit). New epoch → different exporter secret.
empty_commit = alice_group.commit()
alice_group.process_incoming_message(empty_commit.commit_message)
bob_group.process_incoming_message(empty_commit.commit_message)

a2 = alice_group.export_secret(label, context, length)
b2 = bob_group.export_secret(label, context, length)
assert a2 == b2, "exporter secret diverged between alice and bob at epoch 2"
assert a2 != a1, "exporter secret did not change after epoch advance — forward secrecy broken"

print("export_secret: epoch 1 a==b ✓, epoch 2 a==b ✓, label/context/epoch differentiation ✓")
