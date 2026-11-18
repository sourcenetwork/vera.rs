"""Fail when an integration test target or case is neither run by CI nor excluded with a reason.

A target is a top-level file in one of TEST_DIRECTORIES. CI runs it when the
workflow names it with `--test`, iterates over it with a `crates/<crate>/tests/<glob>.rs`
loop, or runs `cargo test --workspace` without excluding its package. Ignored
cases and cases gated by a Cargo feature are checked individually.
"""

import fnmatch
import pathlib
import re
import sys

WORKFLOW = pathlib.Path('.github/workflows/ci.yml')
TEST_DIRECTORIES = (
    pathlib.Path('crates/vera-e2e/tests'),
    pathlib.Path('crates/vera-node/tests'),
)

EXCLUDED_TARGETS = {
    'native_go_client': (
        'every case is ignored: it needs Trust test binaries built with vera_native '
        '(TRUST_NATIVE_TEST_BINARY, TRUST_NATIVE_GATEWAY_TEST_BINARY) from the separate trust-api repository'
    ),
    'native_pressure': (
        'release-mode overload and network-fault suite with resource evidence; '
        'native-pressure.yml runs it on pull requests that change its paths and on dispatch'
    ),
}

IGNORED_CASES = {
    'native_go_client::native_go_workers_verify_policy_creation': 'needs a Trust native test binary',
    'native_go_client::native_go_gateway_verifies_pipelined_vera': 'needs Trust native test and gateway binaries',
    'native_go_client::native_go_policy_pages': 'needs a Trust native test binary',
    'native_pressure::delayed_validator::pipelined_delayed_validator_crosses_epoch_and_preserves_work': (
        'needs explicitly enabled network fault injection; native-pressure.yml runs it with --include-ignored'
    ),
    'embedded_solo_profile::profile_solo_writes_and_idle_cost': 'measurement, run explicitly in release mode',
    'embedded_backup_profile::profile_backup_catch_up_and_idle_cost': 'measurement, run explicitly in release mode',
    'embedded_backup_busy_profile::profile_backup_catch_up_from_a_busy_active_device': (
        'measurement, run explicitly in release mode'
    ),
}

IGNORE = re.compile(r'#\[ignore\b[^\]]*\]')
FUNCTION = re.compile(r'\bfn\s+(\w+)')
FEATURE_CASE = re.compile(
    r'#\[cfg\(feature\s*=\s*"([^"]+)"\)\]\s*((?:#\[[^\]]*\]\s*)*)(?:async\s+)?fn\s+(\w+)'
)
TEST_ATTRIBUTE = re.compile(r'#\[(?:tokio::)?test\b')


def package(directory):
    return directory.parent.name


def targets(root):
    found = {}
    for directory in TEST_DIRECTORIES:
        for path in sorted((root / directory).glob('*.rs')):
            found[path.stem] = directory / path.name
    return found


def module_path(directory, path):
    parts = list(path.relative_to(directory).with_suffix('').parts)
    if parts[-1] == 'mod':
        parts.pop()
    return '::'.join(parts)


def sources(root):
    for directory in TEST_DIRECTORIES:
        for path in sorted((root / directory).rglob('*.rs')):
            yield module_path(root / directory, path), path.read_text()


def ignored_cases(root):
    cases = set()
    for module, text in sources(root):
        for marker in IGNORE.finditer(text):
            function = FUNCTION.search(text, marker.end())
            if function:
                cases.add(module + '::' + function[1])
    return cases


def feature_cases(root):
    cases = set()
    for module, text in sources(root):
        for match in FEATURE_CASE.finditer(text):
            if TEST_ATTRIBUTE.search(match[2]):
                cases.add((module.split('::')[0], match[3], match[1]))
    return cases


def command_lines(workflow):
    return [line for line in workflow.splitlines() if 'cargo clippy' not in line]


def named_targets(workflow):
    return set(re.findall(r'--test\s+(\w+)', '\n'.join(command_lines(workflow))))


def globbed(workflow, relative):
    for pattern in re.findall(r'(crates/[\w-]+/tests/[\w*?\[\]-]+\.rs)', workflow):
        if fnmatch.fnmatchcase(str(relative), pattern):
            return True
    return False


def workspace_packages_excluded(workflow):
    excluded = []
    for line in command_lines(workflow):
        if 'cargo test' in line and '--workspace' in line:
            excluded.append(set(re.findall(r'--exclude\s+([\w-]+)', line)))
    return excluded


def covered(workflow, relative):
    if pathlib.Path(relative).stem in named_targets(workflow):
        return True
    if globbed(workflow, relative):
        return True
    owner = package(pathlib.Path(relative).parent)
    return any(owner not in excluded for excluded in workspace_packages_excluded(workflow))


def feature_case_run(workflow, target, feature):
    for block in re.split(r'\n\s*- suite:', '\n'.join(command_lines(workflow))):
        if f'--features {feature}' in block and re.search(rf'--test\s+{target}\b', block):
            return True
    return False


def problems(root, workflow):
    found = []
    for name, relative in targets(root).items():
        runs = covered(workflow, relative)
        if name in EXCLUDED_TARGETS and runs:
            found.append(f'{relative} runs in CI; remove its exclusion')
        elif name not in EXCLUDED_TARGETS and not runs:
            found.append(f'{relative} runs in no CI job; add it to a job or to EXCLUDED_TARGETS with a reason')
    for name in sorted(set(EXCLUDED_TARGETS) - set(targets(root))):
        found.append(f'excluded target {name} does not exist')
    ignored = ignored_cases(root)
    for case in sorted(ignored - set(IGNORED_CASES)):
        found.append(f'ignored case {case} is not listed in IGNORED_CASES with a reason')
    for case in sorted(set(IGNORED_CASES) - ignored):
        found.append(f'listed ignored case {case} is no longer ignored')
    for target, case, feature in sorted(feature_cases(root)):
        if not feature_case_run(workflow, target, feature):
            found.append(f'{target}::{case} needs feature {feature}; no CI suite runs {target} with it')
    return found


def main():
    root = pathlib.Path.cwd()
    found = problems(root, (root / WORKFLOW).read_text())
    for problem in found:
        print(problem, file=sys.stderr)
    return 1 if found else 0


if __name__ == '__main__':
    sys.exit(main())
