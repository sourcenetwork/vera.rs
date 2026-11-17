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
DISCOVERY = 'crates/vera-config/src/discovery.rs'
RECEIPTS = 'crates/vera-domain/src/receipt_commitment.rs'


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


def source_storage_version(source, revision):
    lock = subprocess.check_output(['git', 'show', f'{revision}:Cargo.lock'], cwd=source, text=True)
    packages = re.findall(r'^\[\[package\]\]\nname = "commonware-storage"\nversion = "([^"]+)"$',
                          lock, re.MULTILINE)
    if len(packages) != 1 or not re.fullmatch(r'\d{4}\.\d+\.\d+', packages[0]):
        raise ValueError('unrecognized Commonware storage version')
    return packages[0]


def source_receipt_commitment(source, revision):
    """The receipt commitment domain at this revision, such as `vera/receipts/v2`.

    A runner recomputes receipt commitments under its own domain, so it
    cannot verify the receipts of a node that commits under another.
    """
    text = subprocess.check_output(['git', 'show', f'{revision}:{RECEIPTS}'], cwd=source, text=True)
    domains = set(re.findall(r'b"(vera/receipts/v\d+)"', text))
    if len(domains) != 1:
        raise ValueError('unrecognized receipt commitment domain')
    return domains.pop()


def source_discovery_setting(source, revision):
    """Whether node configuration at this revision accepts `[network.discovery]`."""
    listed = subprocess.check_output(['git', 'ls-tree', '--name-only', revision, '--', DISCOVERY],
                                     cwd=source, text=True)
    return listed.splitlines() == [DISCOVERY]


def discovery_section(identity, side):
    """Whether a side's generated node configuration states discovery settings.

    None for comparisons recorded before nodes had the setting.
    """
    present = ['discovery_setting' in identity[revision] for revision in ('head', 'base')]
    if not any(present):
        return None
    if not all(present) or any(type(identity[revision]['discovery_setting']) is not bool
                               for revision in ('head', 'base')):
        raise ValueError('incomplete discovery setting provenance')
    return identity[side]['discovery_setting']


def incompatibility_reason(identity):
    if identity['head']['proof_schema'] != identity['base']['proof_schema']:
        return 'incompatible ACP proof schema'
    if identity['head'].get('receipt_commitment') != identity['base'].get('receipt_commitment'):
        return 'different receipt commitments; the runner cannot verify the baseline'
    return 'different Commonware storage versions; proof compatibility not established'

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
    present = ['storage_version' in identity[side] for side in ('head', 'base')]
    if any(present):
        if not all(present) or any(not isinstance(identity[side]['storage_version'], str) or
                                   not re.fullmatch(r'\d{4}\.\d+\.\d+', identity[side]['storage_version'])
                                   for side in ('head', 'base')):
            raise ValueError('incomplete Commonware storage version provenance')
        if identity['head']['storage_version'] != identity['base']['storage_version']:
            return True
    present = ['receipt_commitment' in identity[side] for side in ('head', 'base')]
    if any(present):
        if not all(present) or any(not isinstance(identity[side]['receipt_commitment'], str) or
                                   not re.fullmatch(r'vera/receipts/v\d+', identity[side]['receipt_commitment'])
                                   for side in ('head', 'base')):
            raise ValueError('incomplete receipt commitment provenance')
        if identity['head']['receipt_commitment'] != identity['base']['receipt_commitment']:
            return True
    return identity['head']['proof_schema'] != identity['base']['proof_schema']


def unavailable(identity, objects):
    return {
        'status': 'not_run', 'reason': incompatibility_reason(identity), 'fixed_update_objects': objects,
        'node_source': identity['base']['source'], 'runner_source': identity['head']['source'],
        'node_proof_schema': identity['base']['proof_schema'],
        'runner_proof_schema': identity['head']['proof_schema'],
        **({'node_storage_version': identity['base']['storage_version'],
            'runner_storage_version': identity['head']['storage_version']}
           if 'storage_version' in identity['base'] else {}),
        **({'node_receipt_commitment': identity['base']['receipt_commitment'],
            'runner_receipt_commitment': identity['head']['receipt_commitment']}
           if 'receipt_commitment' in identity['base'] else {}),
    }


def validate_unavailable(directory, identity, objects):
    metadata = json.loads((directory / 'unavailable.json').read_text())
    if metadata != unavailable(identity, objects):
        raise ValueError('baseline incompatibility provenance mismatch')
    if (directory / 'manifest.json').exists() or (directory / 'workload.jsonl').exists():
        raise ValueError('baseline marked not run contains workload evidence')
