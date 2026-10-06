use super::*;
use std::collections::BTreeMap;

use commonware_cryptography::sha256::Digest;
use commonware_storage::{
    mmr,
    qmdb::{any::value::VariableEncoding, current::ordered::proof::constant::ExclusionProof},
};
use vera_modules::{
    acp::{
        AcpModule, keys,
        read_capture::{ReadCapture, ReadLimits, RecordRead},
        record_store::RecordStore,
        types::{AccessRequest, Actor, Object, Operation, PolicyCmd, PolicyMarshalingType},
        zanzibar_store::evaluate_access_request,
    },
    kv_store::ModuleKvStore,
};
use zanzibar::{
    Relationship, Subject,
    error::{Error, Result},
};

type Absent = ExclusionProof<mmr::Family, Vec<u8>, VariableEncoding<Bytes>, Digest, 32>;
type Entries = Vec<(Vec<u8>, Vec<u8>)>;

#[derive(Clone)]
enum Witness {
    Present(proof::Entry),
    Absent(Absent),
    Prefix(proof::PrefixProof),
}

type Reads = Vec<(RecordRead, Witness)>;

async fn prove_reads(db: &Store, reads: Vec<RecordRead>) -> Reads {
    let mut witnesses = Vec::new();
    for read in reads {
        let witness = match &read {
            RecordRead::Key(key) => match db.get(key).await.unwrap() {
                Some(value) => Witness::Present(proof::Entry {
                    key: key.clone(),
                    value,
                    proof: db.key_value_proof(key.clone()).await.unwrap(),
                }),
                None => Witness::Absent(db.exclusion_proof(key).await.unwrap()),
            },
            RecordRead::Prefix(prefix) => Witness::Prefix(proof::prove(db, prefix).await.unwrap()),
        };
        witnesses.push((read, witness));
    }
    witnesses
}

#[derive(Default)]
struct VerifiedReads {
    points: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
    prefixes: BTreeMap<Vec<u8>, Entries>,
}

impl VerifiedReads {
    fn verify(reads: &Reads, root: &Digest) -> std::result::Result<Self, &'static str> {
        let mut records = Self::default();
        for (read, witness) in reads {
            match (read, witness) {
                (RecordRead::Key(key), Witness::Present(entry)) => {
                    if key != &entry.key
                        || !entry
                            .proof
                            .verify::<Sha256, _>(key.clone(), entry.value.clone(), root)
                    {
                        return Err("invalid point proof");
                    }
                    records
                        .points
                        .insert(key.clone(), Some(entry.value.to_vec()));
                }
                (RecordRead::Key(key), Witness::Absent(proof)) => {
                    if !proof.verify::<Sha256>(key, root) {
                        return Err("invalid absence proof");
                    }
                    records.points.insert(key.clone(), None);
                }
                (RecordRead::Prefix(prefix), Witness::Prefix(proof)) => {
                    if !proof.verify(prefix, root) {
                        return Err("invalid complete-prefix proof");
                    }
                    records.prefixes.insert(
                        prefix.clone(),
                        proof
                            .entries
                            .iter()
                            .map(|entry| (entry.key.clone(), entry.value.to_vec()))
                            .collect(),
                    );
                }
                _ => return Err("proof does not match the requested read"),
            }
        }
        Ok(records)
    }
}

impl RecordStore for VerifiedReads {
    fn read_record(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.points
            .get(key)
            .cloned()
            .ok_or_else(|| Error::Serialization("missing point coverage".into()))
    }
    fn scan_records(&self, prefix: &[u8]) -> Result<Entries> {
        self.prefixes
            .get(prefix)
            .cloned()
            .ok_or_else(|| Error::Serialization("missing prefix coverage".into()))
    }
}

const POLICY: &str = "\
name: documents
resources:
  - name: document
    relations:
      - name: reader
        types: [actor]
      - name: blocked
    permissions:
      - name: read
        expr: reader - blocked
";

#[test]
fn permission_evaluation_requires_complete_proofs_at_one_root() {
    run(|context| async move {
        let owner = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
            .parse()
            .unwrap();
        let actor = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
            .parse()
            .unwrap();
        let mut module = AcpModule::new();
        let policy_id = module
            .create_policy(&owner, POLICY, PolicyMarshalingType::ShortYaml)
            .unwrap()
            .policy
            .id;
        module
            .direct_policy_cmd(
                &owner,
                &policy_id,
                PolicyCmd::RegisterObject(Object {
                    resource: "document".into(),
                    id: "report".into(),
                }),
            )
            .unwrap();
        let blocked = Relationship::new(
            "document",
            "report",
            "blocked",
            Subject::typed_wildcard("document"),
        );
        for relationship in [
            Relationship::with_entity("document", "report", "reader", actor),
            blocked.clone(),
        ] {
            module
                .direct_policy_cmd(&owner, &policy_id, PolicyCmd::SetRelationship(relationship))
                .unwrap();
        }
        let request = AccessRequest {
            actor: Actor(
                "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
                    .parse()
                    .unwrap(),
            ),
            operations: vec![Operation {
                object: Object {
                    resource: "document".into(),
                    id: "report".into(),
                },
                permission: "read".into(),
            }],
        };
        let cfg = config(&context);
        let mut db = Store::init(context, cfg, None).await.unwrap();
        db = tests::write(
            db,
            module
                .store()
                .prefix_scan(b"")
                .into_iter()
                .map(|(k, v)| (k, Some(Bytes::from(v))))
                .collect(),
        )
        .await;
        let old_root = db.root();
        let capture = ReadCapture::new(
            module.store().clone(),
            ReadLimits {
                reads: 128,
                records: 128,
                bytes: 1 << 20,
            },
        );
        assert!(!evaluate_access_request(capture.clone(), &policy_id, &request).unwrap());
        let reads = prove_reads(&db, capture.requests().unwrap()).await;
        assert!(
            !evaluate_access_request(
                VerifiedReads::verify(&reads, &old_root).unwrap(),
                &policy_id,
                &request
            )
            .unwrap()
        );
        for index in 0..reads.len() {
            let mut incomplete = reads.clone();
            incomplete.remove(index);
            let records = VerifiedReads::verify(&incomplete, &old_root).unwrap();
            assert!(evaluate_access_request(records, &policy_id, &request).is_err());
        }
        let generations = module.query_policy(&policy_id).unwrap().relations;
        let blocked_prefix = keys::relationship_generation_prefix(
            &policy_id,
            generations.pair(&blocked).unwrap(),
            &keys::relation_prefix("document", "report", "blocked", 0),
        );
        let mut incomplete_records = VerifiedReads::verify(&reads, &old_root).unwrap();
        incomplete_records
            .prefixes
            .insert(blocked_prefix.clone(), vec![]);
        assert!(evaluate_access_request(incomplete_records, &policy_id, &request).unwrap());

        let mut omitted = reads.clone();
        let (_, Witness::Prefix(proof)) = omitted
            .iter_mut()
            .find(|(read, _)| read == &RecordRead::Prefix(blocked_prefix.clone()))
            .unwrap()
        else {
            unreachable!()
        };
        assert_eq!(proof.entries.len(), 1);
        proof.entries.clear();
        assert!(VerifiedReads::verify(&omitted, &old_root).is_err());

        let before = module.store().clone();
        module
            .direct_policy_cmd(&owner, &policy_id, PolicyCmd::DeleteRelationship(blocked))
            .unwrap();
        db = tests::write(
            db,
            module
                .store()
                .diff_from(&before)
                .into_iter()
                .map(|(k, v)| (k, v.map(Bytes::from)))
                .collect(),
        )
        .await;
        assert!(VerifiedReads::verify(&reads, &db.root()).is_err());
        let capture = ReadCapture::new(
            module.store().clone(),
            ReadLimits {
                reads: 128,
                records: 128,
                bytes: 1 << 20,
            },
        );
        assert!(evaluate_access_request(capture.clone(), &policy_id, &request).unwrap());
        let current = prove_reads(&db, capture.requests().unwrap()).await;
        assert!(VerifiedReads::verify(&current, &old_root).is_err());
        assert!(
            evaluate_access_request(
                VerifiedReads::verify(&current, &db.root()).unwrap(),
                &policy_id,
                &request
            )
            .unwrap()
        );
    });
}
