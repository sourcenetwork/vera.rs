"""Versioned source schemas must reject optional incarnation records."""
import unittest
from unittest.mock import patch

from protocol import (ACP_POLICY, BLOCK, DISCOVERY, POLICY_ORIGIN, RECEIPTS, SCHEMAS, baseline_incompatible,
                      discovery_section,
                      incompatibility_reason, source_block_encoding, source_discovery_setting,
                      source_receipt_commitment,
                      source_schema, source_storage_version)


class ProtocolTests(unittest.TestCase):
    def schema(self, record, namespace='relationship/v5/'):
        keys = f'pub const RELATIONSHIP_PREFIX: &[u8] = b"{namespace}";\n'
        policy = 'pub struct PolicyRecord {\n    pub relations: RelationGenerations,\n}\n'
        with patch('protocol.subprocess.check_output', side_effect=[keys, policy + record]):
            return source_schema('.', 'recorded-source')

    def test_mandatory_incarnation_with_unrelated_metadata_default_is_recognized(self):
        record = '''#[derive(Serialize, Deserialize)]
pub struct RelationshipRecord {
    /// The target object incarnation.
    pub incarnation: u64,
    #[serde(default)]
    pub supplied_metadata: SuppliedMetadata,
}
'''
        self.assertEqual(self.schema(record), SCHEMAS['relationship/v5/'])

    def test_missing_optional_or_defaulted_incarnation_is_rejected(self):
        bodies = [
            '',
            '    pub incarnation: Option<u64>,\n',
            '    pub incarnation: u32,\n',
            '    #[serde(default)]\n    pub incarnation: u64,\n',
            '    #[serde(default = "initial")]\n    pub incarnation: u64,\n',
            '    #[serde(\n        default,\n    )]\n    pub incarnation: u64,\n',
            '    #[serde(default)]\n\n    // Still attached to the field.\n    pub incarnation: u64,\n',
            '    #[serde(skip_deserializing)]\n    pub incarnation: u64,\n',
            '    #[serde(deserialize_with = "optional")]\n    pub incarnation: u64,\n',
        ]
        for body in bodies:
            with self.subTest(body=body), self.assertRaisesRegex(ValueError, 'incarnation'):
                self.schema('pub struct RelationshipRecord {\n' + body + '}\n')
        with self.assertRaisesRegex(ValueError, 'incarnation'):
            self.schema('''#[derive(Serialize, Deserialize)]
#[serde(default)]
pub struct RelationshipRecord {
    pub incarnation: u64,
}
''')
        with self.assertRaisesRegex(ValueError, 'relationship record'):
            self.schema('')

    def test_policy_origin_is_recognized_and_cannot_compare_with_plain_v5(self):
        relationship = 'pub struct RelationshipRecord {\n    pub incarnation: u64,\n}\n'
        keys = 'pub const RELATIONSHIP_PREFIX: &[u8] = b"relationship/v5/";\n'

        def read(fields):
            policy = ('pub struct PolicyRecord {\n    pub relations: RelationGenerations,\n'
                      + fields + '}\n')
            with patch('protocol.subprocess.check_output', side_effect=[keys, policy + relationship]):
                return source_schema('.', 'recorded-source')

        origin = '    pub nonce: PolicyNonce,\n    pub policy_hash: PolicyHash,\n'
        self.assertEqual(read(origin), POLICY_ORIGIN)
        self.assertEqual(read(''), SCHEMAS['relationship/v5/'])
        with self.assertRaisesRegex(ValueError, 'nonce'):
            read('    pub nonce: PolicyNonce,\n')
        identity = dict(format_version=2, head=dict(proof_schema=dict(POLICY_ORIGIN)),
                        base=dict(proof_schema=dict(SCHEMAS['relationship/v5/'])))
        self.assertTrue(baseline_incompatible(identity))
        self.assertEqual(incompatibility_reason(identity), 'incompatible ACP proof schema')

    def test_acp_policy_record_cannot_compare_with_the_earlier_engine(self):
        relationship = 'pub struct RelationshipRecord {\n    pub incarnation: u64,\n}\n'
        keys = 'pub const RELATIONSHIP_PREFIX: &[u8] = b"relationship/v5/";\n'

        def read(fields):
            policy = ('pub struct PolicyRecord {\n    pub relations: RelationGenerations,\n'
                      + fields + '}\n')
            with patch('protocol.subprocess.check_output', side_effect=[keys, policy + relationship]):
                return source_schema('.', 'recorded-source')

        origin = '    pub nonce: PolicyNonce,\n    pub policy_hash: PolicyHash,\n'
        self.assertEqual(read('    pub policy: ProcessedPolicy,\n' + origin), ACP_POLICY)
        self.assertEqual(read('    pub policy: Policy,\n' + origin), POLICY_ORIGIN)
        with self.assertRaisesRegex(ValueError, 'nonce'):
            read('    pub policy: ProcessedPolicy,\n')
        identity = dict(format_version=2, head=dict(proof_schema=dict(ACP_POLICY)),
                        base=dict(proof_schema=dict(POLICY_ORIGIN)))
        self.assertTrue(baseline_incompatible(identity))
        self.assertEqual(incompatibility_reason(identity), 'incompatible ACP proof schema')

    def test_earlier_proof_schemas_are_unrecognized(self):
        identity = dict(format_version=2, head=dict(proof_schema=dict(SCHEMAS['relationship/v5/'])),
                        base=dict(proof_schema={'relationship_namespace': 'relationship/v4/',
                                                'policy_generations': 'required'}))
        with self.assertRaisesRegex(ValueError, 'base: unrecognized proof schema'):
            baseline_incompatible(identity)
        identity['base']['proof_schema'] = dict(SCHEMAS['relationship/v5/'])
        self.assertFalse(baseline_incompatible(identity))
        identity['head']['proof_schema'].pop('object_incarnation')
        with self.assertRaisesRegex(ValueError, 'unrecognized proof schema'):
            baseline_incompatible(identity)

    def test_discovery_setting_is_read_from_the_recorded_revision(self):
        for listing, expected in ((DISCOVERY + '\n', True), ('', False)):
            with patch('protocol.subprocess.check_output', return_value=listing) as git:
                self.assertIs(source_discovery_setting('.', 'revision'), expected)
            self.assertEqual(git.call_args.args[0], ['git', 'ls-tree', '--name-only', 'revision', '--', DISCOVERY])

    def test_discovery_provenance_is_per_side_and_absent_from_older_comparisons(self):
        identity = dict(head={}, base={})
        self.assertIsNone(discovery_section(identity, 'base'))
        identity['head']['discovery_setting'] = True
        with self.assertRaisesRegex(ValueError, 'incomplete discovery setting'):
            discovery_section(identity, 'base')
        identity['base']['discovery_setting'] = False
        self.assertIs(discovery_section(identity, 'head'), True)
        self.assertIs(discovery_section(identity, 'base'), False)
        identity['base']['discovery_setting'] = 0
        with self.assertRaisesRegex(ValueError, 'incomplete discovery setting'):
            discovery_section(identity, 'head')

    def test_storage_version_provenance_is_required_and_unique(self):
        record = '[[package]]\nname = "commonware-storage"\nversion = "2026.10.0"\n'
        with patch('protocol.subprocess.check_output', return_value=record):
            self.assertEqual(source_storage_version('.', 'revision'), '2026.10.0')
        for invalid in ('', record + record, record.replace('2026.10.0', 'other')):
            with patch('protocol.subprocess.check_output', return_value=invalid):
                with self.assertRaisesRegex(ValueError, 'storage version'):
                    source_storage_version('.', 'revision')

    def test_different_storage_versions_require_separate_baseline_qualification(self):
        schema = dict(SCHEMAS['relationship/v5/'])
        identity = dict(format_version=2,
                        head=dict(proof_schema=schema, storage_version='2026.10.0'),
                        base=dict(proof_schema=schema, storage_version='2026.9.0'))
        self.assertTrue(baseline_incompatible(identity))
        identity['base']['storage_version'] = '2026.10.0'
        self.assertFalse(baseline_incompatible(identity))
        del identity['base']['storage_version']
        with self.assertRaisesRegex(ValueError, 'storage version provenance'):
            baseline_incompatible(identity)


    def test_block_encoding_is_read_from_the_recorded_revision(self):
        block = 'pub struct Block {\n    pub height: u64,\n    pub timestamp: u64,\n%s    pub txs: Vec<Tx>,\n}\n'
        term, root = '    pub term: u64,\n', '    pub state_root: StateRoot,\n'
        for fields, expected in ((term, 3), (term + root, 2), (root, 1), ('', 1)):
            with patch('protocol.subprocess.check_output', return_value=block % fields) as git:
                self.assertEqual(source_block_encoding('.', 'revision'), expected)
            self.assertEqual(git.call_args.args[0], ['git', 'show', f'revision:{BLOCK}'])
        version = 'pub const BLOCK_FORMAT_VERSION: u8 = %s;\n'
        for declared, expected in ((1, 'v1'), (2, 'v2'), (12, 'v12')):
            with patch('protocol.subprocess.check_output', return_value=version % declared + block % term):
                self.assertEqual(source_block_encoding('.', 'revision'), expected)
        for invalid in ('', block % '    pub term: u32,\n', block % (root + root),
                        (block % root) * 2, version % 1 + block % '', version % 1 + block % (term + root),
                        version % 1 + version % 2 + block % term,
                        version % 'CURRENT' + block % term,
                        'const BLOCK_FORMAT_VERSION: u16 = 1;\n' + block % term):
            with patch('protocol.subprocess.check_output', return_value=invalid):
                with self.assertRaisesRegex(ValueError, 'block'):
                    source_block_encoding('.', 'revision')

    def test_different_block_encodings_cannot_share_a_runner(self):
        schema = dict(SCHEMAS['relationship/v5/'])
        identity = dict(format_version=2,
                        head=dict(proof_schema=schema, storage_version='2026.10.0', block_encoding=2),
                        base=dict(proof_schema=schema, storage_version='2026.10.0', block_encoding=1))
        self.assertTrue(baseline_incompatible(identity))
        self.assertIn('block encodings', incompatibility_reason(identity))
        identity['base']['block_encoding'] = 2
        self.assertFalse(baseline_incompatible(identity))
        for head, base, incompatible in (('v1', 3, True), ('v2', 'v1', True), ('v1', 'v1', False)):
            identity['head']['block_encoding'], identity['base']['block_encoding'] = head, base
            self.assertEqual(baseline_incompatible(identity), incompatible)
        del identity['base']['block_encoding']
        with self.assertRaisesRegex(ValueError, 'block encoding provenance'):
            baseline_incompatible(identity)

    def test_receipt_commitment_is_read_from_the_recorded_revision(self):
        source = 'hash.update(b"vera/receipts/v%d");\nassert_eq!(b"vera/receipts/v%d".as_slice(), domain);\n'
        with patch('protocol.subprocess.check_output', return_value=source % (2, 2)) as git:
            self.assertEqual(source_receipt_commitment('.', 'revision'), 'vera/receipts/v2')
        self.assertEqual(git.call_args.args[0], ['git', 'show', f'revision:{RECEIPTS}'])
        for invalid in ('', source % (1, 2)):
            with patch('protocol.subprocess.check_output', return_value=invalid):
                with self.assertRaisesRegex(ValueError, 'receipt commitment'):
                    source_receipt_commitment('.', 'revision')

    def test_different_receipt_commitments_cannot_share_a_runner(self):
        schema = dict(SCHEMAS['relationship/v5/'])
        identity = dict(format_version=2,
                        head=dict(proof_schema=schema, storage_version='2026.10.0',
                                  receipt_commitment='vera/receipts/v2'),
                        base=dict(proof_schema=schema, storage_version='2026.10.0',
                                  receipt_commitment='vera/receipts/v1'))
        self.assertTrue(baseline_incompatible(identity))
        self.assertIn('receipt commitments', incompatibility_reason(identity))
        identity['base']['receipt_commitment'] = 'vera/receipts/v2'
        self.assertFalse(baseline_incompatible(identity))
        del identity['base']['receipt_commitment']
        with self.assertRaisesRegex(ValueError, 'receipt commitment provenance'):
            baseline_incompatible(identity)


if __name__ == '__main__':
    unittest.main()
