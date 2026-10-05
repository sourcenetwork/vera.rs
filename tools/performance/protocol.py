"""Identify supported fresh-state ACP proof schemas from committed node source."""
import json
import re
import subprocess

SCHEMAS = {
    'relationship/v3/': {'relationship_namespace': 'relationship/v3/', 'policy_generations': 'absent'},
    'relationship/v4/': {'relationship_namespace': 'relationship/v4/', 'policy_generations': 'required'},
    'relationship/v5/': {'relationship_namespace': 'relationship/v5/', 'policy_generations': 'required',
                         'object_incarnation': 'required'},
}
KEYS = 'crates/vera-modules/src/acp/keys.rs'
TYPES = 'crates/vera-modules/src/acp/types.rs'


def source_schema(source, revision):
    def read(path):
        return subprocess.check_output(['git', 'show', f'{revision}:{path}'], cwd=source, text=True)
    keys, types = read(KEYS), read(TYPES)
    namespaces = re.findall(r'^pub const RELATIONSHIP_PREFIX:\s*&\[u8\]\s*=\s*b"([^"\n]+)";', keys, re.MULTILINE)
    if len(namespaces) != 1 or namespaces[0] not in SCHEMAS:
        raise ValueError('unrecognized ACP relationship proof namespace')
    records = re.findall(r'^pub struct PolicyRecord\s*\{(.*?)^\}', types, re.MULTILINE | re.DOTALL)
    if len(records) != 1:
        raise ValueError('unrecognized ACP policy record schema')
    fields = re.findall(r'\bpub\s+relations\s*:\s*([^,\n]+)', records[0])
    expected = [] if namespaces[0] == 'relationship/v3/' else ['RelationGenerations']
    if fields != expected:
        raise ValueError('ACP policy record differs from its versioned relationship schema')
    if namespaces[0] == 'relationship/v5/':
        # Match only attached attributes, not defaults on unrelated record fields.
        attached = r'((?:^[ \t]*#\[[^\]]*\][ \t]*\n|^[ \t]*//[^\n]*\n|^[ \t]*\n)*)'
        records = re.findall(attached + r'^pub struct RelationshipRecord\s*\{(.*?)^\}',
                             types, re.MULTILINE | re.DOTALL)
        if len(records) != 1:
            raise ValueError('unrecognized ACP relationship record schema')
        attributes, record = records[0]
        fields = re.findall(attached + r'^[ \t]*pub\s+incarnation\s*:\s*([^,\n]+),',
                            record, re.MULTILINE)
        if len(fields) != 1 or fields[0][1].strip() != 'u64':
            raise ValueError('ACP relationship incarnation must be a required u64')
        if re.search(r'#\[\s*serde\s*\([^\]]*\b(default|skip|skip_deserializing|deserialize_with|with)\b',
                     attributes + fields[0][0]):
            raise ValueError('ACP relationship incarnation must not default or use custom decoding')
    return dict(SCHEMAS[namespaces[0]])


def baseline_incompatible(identity):
    present = ['proof_schema' in identity[side] for side in ('head', 'base')]
    if not any(present):
        return False  # Historical comparisons predate schema provenance.
    if not all(present) or identity.get('format_version') != 2:
        raise ValueError('incomplete proof schema provenance')
    for side in ('head', 'base'):
        schema = identity[side]['proof_schema']
        if not isinstance(schema, dict) or schema not in SCHEMAS.values():
            raise ValueError(f'{side}: unrecognized proof schema provenance')
    return identity['head']['proof_schema'] != identity['base']['proof_schema']


def unavailable(identity, objects):
    return {
        'status': 'not_run', 'reason': 'incompatible ACP proof schema', 'fixed_update_objects': objects,
        'node_source': identity['base']['source'], 'runner_source': identity['head']['source'],
        'node_proof_schema': identity['base']['proof_schema'],
        'runner_proof_schema': identity['head']['proof_schema'],
    }


def validate_unavailable(directory, identity, objects):
    metadata = json.loads((directory / 'unavailable.json').read_text())
    if metadata != unavailable(identity, objects):
        raise ValueError('baseline incompatibility provenance mismatch')
    if (directory / 'manifest.json').exists() or (directory / 'workload.jsonl').exists():
        raise ValueError('baseline marked not run contains workload evidence')
