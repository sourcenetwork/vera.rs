#!/usr/bin/env python3
"""Check the publication boundary and emit dependency-ordered manual release inputs."""
import argparse
import json
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[2]


def plan(metadata, config):
    if config.get('schema_version') != 1:
        raise ValueError('unsupported release configuration')
    expected = config['packages']
    if len(expected) != len(set(expected)):
        raise ValueError('duplicate release package')
    members = set(metadata['workspace_members'])
    by_id = {package['id']: package for package in metadata['packages']}
    workspace = {package['name']: package for package in by_id.values() if package['id'] in members}
    blockers = []

    def refuse(code, package, detail):
        item = dict(code=code, package=package, detail=detail)
        if item not in blockers:
            blockers.append(item)

    permitted = set(expected)
    actual = {name for name, package in workspace.items() if package['publish'] != []}
    for name in sorted(actual ^ permitted):
        refuse('publication_boundary', name, 'workspace publication set differs from the release allowlist')

    ordered, visited, visiting = [], set(), set()

    def visit(name):
        if name in visited:
            return
        if name in visiting:
            raise ValueError('cycle in release dependencies at ' + name)
        package = workspace.get(name)
        if package is None:
            raise ValueError('release package is not a workspace member: ' + name)
        visiting.add(name)
        for dep in sorted(package['dependencies'], key=lambda item: item['name']):
            if dep['kind'] == 'dev':
                continue
            if dep['name'] in workspace:
                visit(dep['name'])
                version = workspace[dep['name']]['version']
                if dep['req'] != '=' + version:
                    refuse('internal_version', name, dep['name'] + ' must pin =' + version)
            elif (dep.get('source') or '').startswith('git+'):
                refuse('git_dependency', name, dep['name'] + ' requires a verified registry release')
        visiting.remove(name)
        visited.add(name)
        for field in ('description', 'license', 'repository', 'rust_version'):
            if not package.get(field):
                refuse('package_metadata', name, 'missing ' + field)
        if package['publish'] != ['crates-io']:
            refuse('publication_registry', name, 'release crates must explicitly select crates-io')
        ordered.append(dict(name=name, version=package['version'], manifest_path=package['manifest_path']))

    for root in sorted(config['roots']):
        visit(root)
    for name in sorted(visited ^ permitted):
        refuse('release_closure', name, 'declared allowlist differs from the client/verifier dependency closure')
    versions = {workspace[name]['version'] for name in visited}
    if len(versions) != 1:
        refuse('release_version', 'workspace', 'release packages must have one version')

    resolve = metadata.get('resolve')
    if resolve is None:
        refuse('dependency_resolution', 'workspace', 'full locked dependency metadata is required')
    else:
        nodes = {node['id']: node for node in resolve['nodes']}
        walked = set()

        def inspect(package_id):
            if package_id in walked:
                return
            walked.add(package_id)
            package = by_id[package_id]
            source = package.get('source')
            if package_id not in members and not (source or '').startswith('registry+'):
                refuse('resolved_source', package['name'], 'qualified dependency is not a registry package: ' + str(source))
            for dep in nodes[package_id]['deps']:
                if any(kind['kind'] != 'dev' for kind in dep['dep_kinds']):
                    inspect(dep['pkg'])

        for name in sorted(visited):
            inspect(workspace[name]['id'])

    return dict(schema_version=1, ready=not blockers, publication='manual',
                roots=config['roots'], packages=ordered, blockers=blockers)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('plan', 'check'))
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    metadata = json.loads(subprocess.run(
        ['cargo', 'metadata', '--locked', '--format-version', '1'], cwd=ROOT,
        check=True, capture_output=True, text=True, timeout=120).stdout)
    config = json.loads((ROOT / '.github/release-packages.json').read_text())
    result = plan(metadata, config)
    output = json.dumps(result, sort_keys=True, indent=2) + '\n'
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output)
    else:
        print(output, end='')
    return 1 if args.command == 'check' and not result['ready'] else 0


if __name__ == '__main__':
    raise SystemExit(main())
