//! AgentVault #1800: the basic-credential identity rules a Hermes client
//! enforces, proven against hostile commits on real mls-rs groups.
//!
//! The VICTIM is always a [`crate::Client`] built exactly as Hermes builds one
//! (`Client::new(device_id, keypair, client_config_default())`: the
//! `BasicIdentityProvider`, `DefaultMlsRules`, the ratchet tree extension). The
//! ATTACKER is a real mls-rs member whose own identity provider accepts
//! anything, so it can build the commits an honest client refuses to build.
//! Nothing is mocked: every message is real MLS, signed and encrypted.
//!
//! These mirror the three rules of the TypeScript patch
//! `ts-mls+1.6.2+004+identity-rules.patch` in agentvault-gen2:
//!   (a) an Update or UpdatePath never changes a leaf's basic identity;
//!   (b) after a commit's removes and adds, no identity it added sits on two
//!       leaves (a remove + re-add of one device in one commit still passes);
//!   (c) a Welcome never joins a tree holding one identity on two leaves.
//!
//! Each refusal also has a positive control built from the same fixture, so a
//! test cannot pass because the pipeline is broken for an unrelated reason.

use std::sync::Arc;

use mls_rs::client_builder::MlsConfig;
use mls_rs::error::MlsError;
use mls_rs::identity::{CredentialType, SigningIdentity as CoreSigningIdentity};
use mls_rs::mls_rules::{CommitOptions, DefaultMlsRules};
use mls_rs::time::MlsTime;
use mls_rs::{CipherSuiteProvider, CryptoProvider, ExtensionList, MlsMessage};
use mls_rs_core::identity::{BasicCredential, IdentityProvider, MemberValidationContext};
use mls_rs_core::mls_rs_codec::MlsEncode;
use mls_rs_crypto_openssl::OpensslCryptoProvider;

use crate::config::ClientConfig;
use crate::{
    generate_signature_keypair, CipherSuite, Client, Error, Group, Message, ReceivedMessage,
};

const CS: mls_rs::CipherSuite = mls_rs::CipherSuite::CURVE25519_AES128;

// --- The attacker's identity provider ----------------------------------------

#[derive(Debug)]
struct NeverFails;

impl std::fmt::Display for NeverFails {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("never fails")
    }
}

impl std::error::Error for NeverFails {}

impl mls_rs::error::IntoAnyError for NeverFails {
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(self.into())
    }
}

/// Accepts every credential and every successor. Its `identity` is the whole
/// encoded signing identity (credential + key), so its own tree index never
/// sees two leaves as one identity: it will happily build duplicates.
#[derive(Clone, Debug)]
struct Permissive;

impl IdentityProvider for Permissive {
    type Error = NeverFails;

    fn validate_member(
        &self,
        _: &CoreSigningIdentity,
        _: Option<MlsTime>,
        _: MemberValidationContext<'_>,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn validate_external_sender(
        &self,
        _: &CoreSigningIdentity,
        _: Option<MlsTime>,
        _: Option<&ExtensionList>,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn identity(
        &self,
        id: &CoreSigningIdentity,
        _: &ExtensionList,
    ) -> Result<Vec<u8>, Self::Error> {
        Ok(id.mls_encode_to_vec().expect("encode signing identity"))
    }

    fn valid_successor(
        &self,
        _: &CoreSigningIdentity,
        _: &CoreSigningIdentity,
        _: &ExtensionList,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    fn supported_types(&self) -> Vec<CredentialType> {
        vec![CredentialType::BASIC]
    }
}

// --- Fixture helpers ---------------------------------------------------------

fn uuid_identity(n: u8) -> Vec<u8> {
    // Device-UUID-shaped, canonical lowercase, as Hermes and the plugin use.
    format!("{n:02x}000000-0000-4000-8000-0000000000{n:02x}").into_bytes()
}

fn fresh_key() -> (
    mls_rs::crypto::SignatureSecretKey,
    mls_rs::crypto::SignaturePublicKey,
) {
    OpensslCryptoProvider::new()
        .cipher_suite_provider(CS)
        .unwrap()
        .signature_key_generate()
        .unwrap()
}

fn basic(identity: Vec<u8>, public: mls_rs::crypto::SignaturePublicKey) -> CoreSigningIdentity {
    CoreSigningIdentity::new(BasicCredential::new(identity).into_credential(), public)
}

/// A hostile member: real mls-rs, permissive identity rules.
fn attacker_client(identity: Vec<u8>) -> mls_rs::Client<impl MlsConfig> {
    let (secret, public) = fresh_key();
    let rules = DefaultMlsRules::new().with_commit_options(
        CommitOptions::default()
            .with_ratchet_tree_extension(true)
            .with_single_welcome_message(true),
    );
    mls_rs::Client::builder()
        .crypto_provider(OpensslCryptoProvider::new())
        .identity_provider(Permissive)
        .mls_rules(rules)
        .signing_identity(basic(identity, public), secret, CS)
        .build()
}

/// A client built exactly as Hermes builds one (`MlsGroupState.__init__`).
fn hermes_client(identity: Vec<u8>) -> Client {
    let keypair = generate_signature_keypair(CipherSuite::Curve25519Aes128).unwrap();
    Client::new(identity, keypair, ClientConfig::default())
}

fn kp(client: &Client) -> MlsMessage {
    client.generate_key_package_message().unwrap().inner
}

fn msg(inner: MlsMessage) -> Arc<Message> {
    Arc::new(Message { inner })
}

fn victim_processes(victim: &Group, m: &MlsMessage) -> Result<ReceivedMessage, Error> {
    victim.process_incoming_message(msg(m.clone()))
}

fn mls_error(result: Result<impl std::fmt::Debug, Error>) -> MlsError {
    match result {
        Err(Error::MlsError { inner }) => inner,
        other => panic!("expected an mls-rs refusal, got {other:?}"),
    }
}

struct Room<C: MlsConfig> {
    attacker: mls_rs::Group<C>,
    victim: Arc<Group>,
    owner_id: Vec<u8>,
    carol: Client,
}

/// Attacker A (leaf 0) creates a group and adds, in one honest commit, the
/// Hermes victim V (leaf 1), the owner O (leaf 2) and Carol (leaf 3).
fn room() -> Room<impl MlsConfig> {
    let attacker = attacker_client(uuid_identity(0xa0));
    let owner_id = uuid_identity(0x01);
    let victim_client = hermes_client(uuid_identity(0x0f));
    let owner = hermes_client(owner_id.clone());
    let carol = hermes_client(uuid_identity(0x0c));

    let mut group = attacker
        .create_group(ExtensionList::new(), Default::default(), None)
        .unwrap();
    let out = group
        .commit_builder()
        .add_member(kp(&victim_client))
        .unwrap()
        .add_member(kp(&owner))
        .unwrap()
        .add_member(kp(&carol))
        .unwrap()
        .build()
        .unwrap();
    group.apply_pending_commit().unwrap();
    let victim = victim_client
        .join_group(
            None,
            &Message {
                inner: out.welcome_messages[0].clone(),
            },
        )
        .unwrap()
        .group;

    // Positive control: the victim reads the attacker's frames.
    let hello = group
        .encrypt_application_message(b"hello", Vec::new())
        .unwrap();
    match victim_processes(&victim, &hello).unwrap() {
        ReceivedMessage::ApplicationMessage { data, .. } => assert_eq!(data, b"hello"),
        other => panic!("expected an application message, got {other:?}"),
    }

    Room {
        attacker: group,
        victim,
        owner_id,
        carol,
    }
}

fn leaves_holding(victim: &Group, identity: &[u8]) -> usize {
    let group = victim.inner();
    group
        .roster()
        .members_iter()
        .filter(|m| {
            m.signing_identity
                .credential
                .as_basic()
                .map(|b| b.identifier.as_slice())
                == Some(identity)
        })
        .count()
}

/// A KeyPackage claiming `identity`, signed with a key the attacker controls.
fn forged_kp(identity: Vec<u8>) -> MlsMessage {
    attacker_client(identity)
        .generate_key_package_message(Default::default(), Default::default(), None)
        .unwrap()
}

// --- (a) An Update or UpdatePath never changes a leaf's basic identity -------

#[test]
fn rule_a_update_path_renaming_own_leaf_is_refused() {
    let mut r = room();
    let (secret, public) = fresh_key();
    let renamed = basic(uuid_identity(0x77), public);
    let commit = r
        .attacker
        .commit_builder()
        .set_new_signing_identity(secret, renamed)
        .build()
        .unwrap()
        .commit_message;

    assert!(matches!(
        mls_error(victim_processes(&r.victim, &commit)),
        MlsError::InvalidSuccessor
    ));
}

#[test]
fn rule_a_update_path_renaming_own_leaf_to_the_owner_is_refused() {
    let mut r = room();
    let (secret, public) = fresh_key();
    let as_owner = basic(r.owner_id.clone(), public);
    let commit = r
        .attacker
        .commit_builder()
        .set_new_signing_identity(secret, as_owner)
        .build()
        .unwrap()
        .commit_message;

    let err = mls_error(victim_processes(&r.victim, &commit));
    assert!(
        matches!(err, MlsError::InvalidSuccessor),
        "expected InvalidSuccessor, got {err:?}"
    );
    assert_eq!(leaves_holding(&r.victim, &r.owner_id), 1);
}

#[test]
fn rule_a_control_update_path_keeping_identity_with_a_new_key_is_accepted() {
    // Same fixture and builder call; only the identity is kept. This is the
    // honest key rotation the rule must not block.
    let mut r = room();
    let (secret, public) = fresh_key();
    let same = basic(uuid_identity(0xa0), public);
    let commit = r
        .attacker
        .commit_builder()
        .set_new_signing_identity(secret, same)
        .build()
        .unwrap()
        .commit_message;

    assert!(matches!(
        victim_processes(&r.victim, &commit).unwrap(),
        ReceivedMessage::Commit { .. }
    ));
}

#[test]
fn rule_a_update_proposal_renaming_own_leaf_is_refused() {
    // The attacker proposes an identity-changing Update by reference; a second
    // hostile member commits it. RFC 9420 forbids committing your own Update.
    let mut r = room();
    let accomplice = attacker_client(uuid_identity(0xa1));
    let out = r
        .attacker
        .commit_builder()
        .add_member(
            accomplice
                .generate_key_package_message(Default::default(), Default::default(), None)
                .unwrap(),
        )
        .unwrap()
        .build()
        .unwrap();
    r.attacker.apply_pending_commit().unwrap();
    victim_processes(&r.victim, &out.commit_message).unwrap();
    let (mut accomplice_group, _) = accomplice
        .join_group(None, &out.welcome_messages[0], None)
        .unwrap();

    let (secret, public) = fresh_key();
    let proposal = r
        .attacker
        .propose_update_with_identity(secret, basic(r.owner_id.clone(), public), Vec::new())
        .unwrap();
    accomplice_group
        .process_incoming_message(proposal.clone())
        .unwrap();
    let commit = accomplice_group.commit(Vec::new()).unwrap().commit_message;

    // Whichever step refuses it, the renamed leaf must never be applied.
    match victim_processes(&r.victim, &proposal) {
        Err(e) => panic!("victim refused the proposal itself (record this): {e:?}"),
        Ok(_) => {
            let err = mls_error(victim_processes(&r.victim, &commit));
            assert!(
                matches!(err, MlsError::InvalidSuccessor),
                "expected InvalidSuccessor, got {err:?}"
            );
        }
    }
    assert_eq!(leaves_holding(&r.victim, &r.owner_id), 1);
}

// --- (b) No identity a commit adds may sit on two leaves after it --------------

#[test]
fn rule_b_add_of_an_identity_already_present_is_refused() {
    let mut r = room();
    let commit = r
        .attacker
        .commit_builder()
        .add_member(forged_kp(r.owner_id.clone()))
        .unwrap()
        .build()
        .unwrap()
        .commit_message;

    assert!(matches!(
        mls_error(victim_processes(&r.victim, &commit)),
        MlsError::DuplicateLeafData(_)
    ));
    assert_eq!(leaves_holding(&r.victim, &r.owner_id), 1);
}

#[test]
fn rule_b_remove_of_someone_else_plus_add_of_a_present_identity_is_refused() {
    // The duplicate check runs after the removes, but a remove of a DIFFERENT
    // leaf (Carol, leaf 3) must not make room for a second owner leaf.
    let mut r = room();
    let carol_id = r
        .carol
        .signing_identity()
        .unwrap()
        .basic_identity()
        .unwrap();
    let carol_index = r
        .attacker
        .roster()
        .members_iter()
        .find(|m| m.signing_identity.credential.as_basic().unwrap().identifier == carol_id)
        .unwrap()
        .index;
    let commit = r
        .attacker
        .commit_builder()
        .remove_member(carol_index)
        .unwrap()
        .add_member(forged_kp(r.owner_id.clone()))
        .unwrap()
        .build()
        .unwrap()
        .commit_message;

    assert!(matches!(
        mls_error(victim_processes(&r.victim, &commit)),
        MlsError::DuplicateLeafData(_)
    ));
}

#[test]
fn rule_b_control_remove_and_re_add_of_one_identity_in_one_commit_is_accepted() {
    // The honest re-admit shape: the owner's stale leaf removed and a fresh
    // owner KeyPackage added in ONE commit. Must pass (#1170).
    let mut r = room();
    let owner_index = 2;
    let fresh_owner = hermes_client(r.owner_id.clone());
    let commit = r
        .attacker
        .commit_builder()
        .remove_member(owner_index)
        .unwrap()
        .add_member(kp(&fresh_owner))
        .unwrap()
        .build()
        .unwrap()
        .commit_message;

    assert!(matches!(
        victim_processes(&r.victim, &commit).unwrap(),
        ReceivedMessage::Commit { .. }
    ));
    assert_eq!(leaves_holding(&r.victim, &r.owner_id), 1);
}

#[test]
fn rule_b_add_proposal_by_reference_of_a_present_identity_is_refused() {
    let mut r = room();
    let proposal = r
        .attacker
        .propose_add(forged_kp(r.owner_id.clone()), Vec::new())
        .unwrap();
    let proposal_result = victim_processes(&r.victim, &proposal);
    if let Err(e) = &proposal_result {
        panic!("victim refused the add proposal itself (record this): {e:?}");
    }
    let commit = r.attacker.commit(Vec::new()).unwrap().commit_message;

    assert!(matches!(
        mls_error(victim_processes(&r.victim, &commit)),
        MlsError::DuplicateLeafData(_)
    ));
    assert_eq!(leaves_holding(&r.victim, &r.owner_id), 1);
}

#[test]
fn rule_b_external_commit_joining_as_a_present_identity_is_refused() {
    let r = room();
    let group_info = r
        .attacker
        .group_info_message_allowing_ext_commit(true)
        .unwrap();
    let (_, commit) = attacker_client(r.owner_id.clone())
        .external_commit_builder()
        .unwrap()
        .build(group_info.clone())
        .unwrap();

    assert!(matches!(
        mls_error(victim_processes(&r.victim, &commit)),
        MlsError::DuplicateLeafData(_)
    ));

    // Control: the same external commit under a fresh identity is accepted.
    let (_, commit) = attacker_client(uuid_identity(0x55))
        .external_commit_builder()
        .unwrap()
        .build(group_info)
        .unwrap();
    assert!(matches!(
        victim_processes(&r.victim, &commit).unwrap(),
        ReceivedMessage::Commit { .. }
    ));
}

// --- (c) A Welcome never joins a tree holding one identity on two leaves ------

fn welcome_into(duplicate_owner: bool) -> Result<(), Error> {
    let attacker = attacker_client(uuid_identity(0xa0));
    let owner_id = uuid_identity(0x01);
    let owner = hermes_client(owner_id.clone());
    let victim = hermes_client(uuid_identity(0x0f));

    let mut group = attacker
        .create_group(ExtensionList::new(), Default::default(), None)
        .unwrap();
    let mut builder = group.commit_builder().add_member(kp(&owner)).unwrap();
    builder = if duplicate_owner {
        builder.add_member(forged_kp(owner_id.clone())).unwrap()
    } else {
        builder.add_member(forged_kp(uuid_identity(0x02))).unwrap()
    };
    builder.build().unwrap();
    group.apply_pending_commit().unwrap();

    let owner_leaves = group
        .roster()
        .members_iter()
        .filter(|m| m.signing_identity.credential.as_basic().unwrap().identifier == owner_id)
        .count();
    assert_eq!(owner_leaves, if duplicate_owner { 2 } else { 1 });

    let out = group
        .commit_builder()
        .add_member(kp(&victim))
        .unwrap()
        .build()
        .unwrap();
    group.apply_pending_commit().unwrap();
    victim
        .join_group(
            None,
            &Message {
                inner: out.welcome_messages[0].clone(),
            },
        )
        .map(|_| ())
}

#[test]
fn rule_c_welcome_into_a_tree_with_a_duplicate_identity_is_refused() {
    assert!(matches!(
        mls_error(welcome_into(true)),
        MlsError::DuplicateLeafData(_)
    ));
}

#[test]
fn rule_c_control_welcome_into_a_clean_tree_is_accepted() {
    welcome_into(false).unwrap();
}
