"""Versioned source schemas must reject optional incarnation records."""
import unittest
from unittest.mock import patch

from protocol import SCHEMAS, baseline_incompatible, source_schema


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

    def test_v5_cannot_compare_with_either_previous_proof_schema(self):
        for namespace in ('relationship/v3/', 'relationship/v4/'):
            identity = dict(format_version=2, head=dict(proof_schema=dict(SCHEMAS['relationship/v5/'])),
                            base=dict(proof_schema=SCHEMAS[namespace]))
            self.assertTrue(baseline_incompatible(identity))
            identity['base']['proof_schema'] = dict(SCHEMAS['relationship/v5/'])
            self.assertFalse(baseline_incompatible(identity))
        identity['head']['proof_schema'].pop('object_incarnation')
        with self.assertRaisesRegex(ValueError, 'unrecognized proof schema'):
            baseline_incompatible(identity)


if __name__ == '__main__':
    unittest.main()
