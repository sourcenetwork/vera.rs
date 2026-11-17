import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('assignment', Path(__file__).with_name('check-test-assignment.py'))
assignment = importlib.util.module_from_spec(spec)
spec.loader.exec_module(assignment)

WORKFLOW = """
jobs:
  build:
    steps:
      - run: cargo test --frozen --workspace --exclude vera-e2e
  e2e:
    steps:
      - name: Lint
        run: cargo clippy --frozen -p vera-e2e --test linted -- -D warnings
      - run: >-
          cargo test --frozen -p vera-e2e
          --test listed
          -- --nocapture
  recovery:
    strategy:
      matrix:
        include:
          - suite: plain
            test-features: ""
            tests: --test gated
          - suite: crash
            test-features: "--features fault-injection"
            tests: --test crashing
"""


class TestAssignment(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        for directory in assignment.TEST_DIRECTORIES:
            (self.root / directory).mkdir(parents=True)
        for name in ('listed', 'gated', 'crashing'):
            self.write('crates/vera-e2e/tests', name, '#[tokio::test]\nasync fn case() {}\n')
        self.write('crates/vera-node/tests', 'embedded', '#[test]\nfn case() {}\n')
        patcher = patch.multiple(assignment, EXCLUDED_TARGETS={}, IGNORED_CASES={})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.directory.cleanup)

    def write(self, directory, name, text):
        path = self.root / directory / f'{name}.rs'
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def problems(self, workflow=WORKFLOW):
        return assignment.problems(self.root, workflow)

    def test_named_and_workspace_targets_are_covered(self):
        self.assertEqual(self.problems(), [])

    def test_unassigned_target_fails(self):
        self.write('crates/vera-e2e/tests', 'forgotten', '')
        self.assertEqual(self.problems(), [
            'crates/vera-e2e/tests/forgotten.rs runs in no CI job; '
            'add it to a job or to EXCLUDED_TARGETS with a reason'])

    def test_lint_step_does_not_count_as_a_run(self):
        self.write('crates/vera-e2e/tests', 'linted', '')
        self.assertEqual(len(self.problems()), 1)

    def test_excluded_target_needs_no_job_but_stale_exclusions_fail(self):
        self.write('crates/vera-e2e/tests', 'external', '')
        with patch.object(assignment, 'EXCLUDED_TARGETS', {'external': 'reason', 'listed': 'reason', 'gone': 'reason'}):
            self.assertEqual(self.problems(), [
                'crates/vera-e2e/tests/listed.rs runs in CI; remove its exclusion',
                'excluded target gone does not exist'])

    def test_excluding_the_package_from_the_workspace_run_uncovers_its_targets(self):
        workflow = WORKFLOW.replace('--exclude vera-e2e', '--exclude vera-e2e --exclude vera-node')
        self.assertEqual(self.problems(workflow), [
            'crates/vera-node/tests/embedded.rs runs in no CI job; '
            'add it to a job or to EXCLUDED_TARGETS with a reason'])

    def test_glob_loop_covers_matching_targets(self):
        workflow = WORKFLOW.replace('--workspace --exclude vera-e2e', '-p vera-app') + (
            '      - run: for file in crates/vera-node/tests/embedded*.rs; do echo; done\n')
        self.assertEqual(self.problems(workflow), [])

    def test_ignored_cases_need_a_listed_reason(self):
        self.write('crates/vera-e2e/tests/listed', 'slow', '#[tokio::test]\n#[ignore = "x"]\nasync fn slow_case() {}\n')
        self.assertEqual(self.problems(), [
            'ignored case listed::slow::slow_case is not listed in IGNORED_CASES with a reason'])
        with patch.object(assignment, 'IGNORED_CASES', {'listed::slow::slow_case': 'reason'}):
            self.assertEqual(self.problems(), [])
        with patch.object(assignment, 'IGNORED_CASES', {'listed::slow::slow_case': 'r', 'listed::old': 'r'}):
            self.assertEqual(self.problems(), ['listed ignored case listed::old is no longer ignored'])

    def test_feature_gated_case_needs_a_suite_with_that_feature(self):
        gated = '#[cfg(feature = "fault-injection")]\n#[tokio::test]\nasync fn crash_case() {}\n'
        self.write('crates/vera-e2e/tests', 'gated', gated)
        self.assertEqual(self.problems(), [
            'gated::crash_case needs feature fault-injection; no CI suite runs gated with it'])
        self.write('crates/vera-e2e/tests', 'crashing', gated)
        self.assertEqual(self.problems(), [
            'gated::crash_case needs feature fault-injection; no CI suite runs gated with it'])

    def test_feature_gated_helper_is_not_a_case(self):
        self.write('crates/vera-e2e/tests', 'gated', '#[cfg(feature = "fault-injection")]\nfn helper() {}\n')
        self.assertEqual(self.problems(), [])


if __name__ == '__main__':
    unittest.main()
