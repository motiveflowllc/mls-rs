"""AgentVault #1800: the sender of an application message, read from the tree
of the epoch that verified it.

`ReceivedMessage.APPLICATION_MESSAGE.sender` is looked up in the CURRENT tree
by leaf index. A frame from an earlier epoch can therefore be attributed to
whoever holds that index now. `sender_leaf` is the binding-safe field: it is
read from the tree the frame was verified against, and it is `None` when that
cannot be established.

Every group here is real mls-rs (no mocked crypto). Identities are
device-UUID-shaped, as Hermes uses them.
"""
import uuid

from mls_rs_uniffi import (
    CipherSuite,
    Client,
    client_config_default,
    generate_signature_keypair,
)


def device(name):
    device_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, name + ".agentvault.test")).encode()
    client = Client(
        device_id,
        generate_signature_keypair(CipherSuite.CURVE25519_AES128),
        client_config_default(),
    )
    return device_id, client


def join(client, output):
    return client.join_group(None, output.welcome_message).group


def assert_sender_leaf(received, leaf_index, identity):
    leaf = received.sender_leaf
    assert leaf is not None, "sender_leaf is None for a frame whose verifying leaf is known"
    assert leaf.leaf_index == leaf_index, (leaf.leaf_index, leaf_index)
    assert leaf.signing_identity.basic_identity() == identity, (
        leaf.signing_identity.basic_identity(),
        identity,
    )
    assert leaf.identity_leaf_count == 1, leaf.identity_leaf_count


# --- SigningIdentity.basic_identity -----------------------------------------
a_id, a = device("alice")
assert a.signing_identity().basic_identity() == a_id

# --- 1. Current epoch: {A, B, C}; B's frame names B, once ---------------------
b_id, b = device("bob")
c_id, c = device("carla")
a_group = a.create_group(None)
out = a_group.add_members([b.generate_key_package_message(), c.generate_key_package_message()])
a_group.process_incoming_message(out.commit_message)
b_group = join(b, out)
c_group = join(c, out)

received = c_group.process_incoming_message(b_group.encrypt_application_message(b"hi from bob"))
assert received.data == b"hi from bob"
assert_sender_leaf(received, 1, b_id)

received = b_group.process_incoming_message(a_group.encrypt_application_message(b"hi from alice"))
assert_sender_leaf(received, 0, a_id)

# --- 2. Past epoch, sender's leaf untouched: still B ---------------------------
# B encrypts at epoch N; A adds D (epoch N+1, B's leaf unchanged); C reads
# B's frame after processing that commit. The leaf at B's index still carries
# the key that verified the frame, so the sender is B.
old_from_b = b_group.encrypt_application_message(b"sent before the add")
d_id, d = device("dave")
out = a_group.add_members([d.generate_key_package_message()])
a_group.process_incoming_message(out.commit_message)
b_group.process_incoming_message(out.commit_message)
c_group.process_incoming_message(out.commit_message)
received = c_group.process_incoming_message(old_from_b)
assert received.data == b"sent before the add"
assert_sender_leaf(received, 1, b_id)

# --- 3. Past epoch, sender committed its own UpdatePath since: still B ---------
old_from_b = b_group.encrypt_application_message(b"sent before my own commit")
out = b_group.commit()
b_group.process_incoming_message(out.commit_message)
c_group.process_incoming_message(out.commit_message)
received = c_group.process_incoming_message(old_from_b)
assert_sender_leaf(received, 1, b_id)

# --- 4. Escalation direction: X's old frame, X's index now held by O ----------
# X sends at epoch N. A removes X (N+1) and adds O (N+2); mls-rs puts O in
# X's blanked leaf. The legacy `sender` field now names O for X's frame, which
# is exactly the relabel #1800 closes. `sender_leaf` must not name O.
e_id, e = device("erin")
x_id, x = device("xavier")
o_id, o = device("owner")
e_group = e.create_group(None)
out = e_group.add_members([x.generate_key_package_message(), c.generate_key_package_message()])
e_group.process_incoming_message(out.commit_message)
x_group = join(x, out)
c2_group = join(c, out)

from_x = x_group.encrypt_application_message(b"x, before removal")

out = e_group.remove_members([x.signing_identity()])
e_group.process_incoming_message(out.commit_message)
c2_group.process_incoming_message(out.commit_message)
out = e_group.add_members([o.generate_key_package_message()])
e_group.process_incoming_message(out.commit_message)
c2_group.process_incoming_message(out.commit_message)

received = c2_group.process_incoming_message(from_x)
assert received.data == b"x, before removal"
# The fixture really did hand X's index to O: the legacy field proves it.
assert received.sender.basic_identity() == o_id, received.sender.basic_identity()
assert received.sender_leaf is None, (
    "an earlier-epoch frame was attributed to the leaf's CURRENT holder",
    received.sender_leaf.signing_identity.basic_identity(),
)

# --- 5. Harmless direction: B's old frame, B's index now held by D -------------
# The same shape with an honest sender. mls-rs keeps only signature keys for
# prior epochs, not credentials, so B's identity at that epoch cannot be read
# back: the result is None (fail closed), never D.
f_id, f = device("frank")
g_id, g = device("grace")
h_id, h = device("heidi")
f_group = f.create_group(None)
out = f_group.add_members([g.generate_key_package_message(), h.generate_key_package_message()])
f_group.process_incoming_message(out.commit_message)
g_group = join(g, out)
h_group = join(h, out)
from_g = g_group.encrypt_application_message(b"g, before removal")
out = f_group.remove_members([g.signing_identity()])
f_group.process_incoming_message(out.commit_message)
h_group.process_incoming_message(out.commit_message)
i_id, i = device("ivan")
out = f_group.add_members([i.generate_key_package_message()])
f_group.process_incoming_message(out.commit_message)
h_group.process_incoming_message(out.commit_message)
received = h_group.process_incoming_message(from_g)
assert received.sender.basic_identity() == i_id
assert received.sender_leaf is None
