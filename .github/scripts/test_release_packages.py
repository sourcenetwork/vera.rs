import copy
from pathlib import Path
import runpy
import unittest

plan = runpy.run_path(str(Path(__file__).with_name('release-packages.py')))['plan']


def package(name, dependencies=()):
    return dict(id=name, name=name, version='0.1.0', publish=['crates-io'],
                description='Test package', license='MIT', repository='https://example.org/repo',
                rust_version='1.98', manifest_path='/workspace/' + name + '/Cargo.toml',
                dependencies=list(dependencies), source=None)


def dependency(name, **extra):
    return dict(name=name, kind=None, req='=0.1.0', source=None, **extra)


class PublicationPlan(unittest.TestCase):
    def setUp(self):
        self.config = dict(schema_version=1, roots=['sdk'], packages=['sdk', 'types'])
        self.metadata = dict(workspace_members=['sdk', 'types'], packages=[
            package('sdk', [dependency('types')]), package('types')], resolve=dict(nodes=[
                dict(id='sdk', deps=[dict(pkg='types', dep_kinds=[dict(kind=None)])]),
                dict(id='types', deps=[])]))

    def test_orders_dependencies_before_consumer(self):
        result = plan(self.metadata, self.config)
        self.assertTrue(result['ready'], result['blockers'])
        self.assertEqual([p['name'] for p in result['packages']], ['types', 'sdk'])
        self.assertEqual(result['publication'], 'manual')

    def test_path_only_or_wrong_versions_cannot_pass(self):
        for req in ('*', '=0.2.0'):
            with self.subTest(req=req):
                metadata = copy.deepcopy(self.metadata)
                metadata['packages'][0]['dependencies'][0]['req'] = req
                self.assertIn('internal_version', [b['code'] for b in plan(metadata, self.config)['blockers']])

    def test_root_patch_cannot_hide_behind_registry_declaration(self):
        external = package('upstream')
        external['source'] = 'git+https://example.org/upstream?rev=abc#abc'
        self.metadata['packages'].append(external)
        self.metadata['resolve']['nodes'].extend([dict(id='upstream', deps=[])])
        self.metadata['resolve']['nodes'][1]['deps'] = [dict(pkg='upstream', dep_kinds=[dict(kind=None)])]
        result = plan(self.metadata, self.config)
        self.assertFalse(result['ready'])
        self.assertEqual(result['blockers'][0]['code'], 'resolved_source')

    def test_unlisted_publishable_tool_is_rejected(self):
        self.metadata['packages'].append(package('tool'))
        self.metadata['workspace_members'].append('tool')
        result = plan(self.metadata, self.config)
        self.assertIn('publication_boundary', [b['code'] for b in result['blockers']])

    def test_missing_resolution_is_not_ready(self):
        self.metadata['resolve'] = None
        self.assertFalse(plan(self.metadata, self.config)['ready'])

    def test_dependency_cycle_is_rejected(self):
        self.metadata['packages'][1]['dependencies'] = [dependency('sdk')]
        with self.assertRaisesRegex(ValueError, 'cycle'):
            plan(self.metadata, self.config)

    def test_dev_dependency_does_not_expand_release(self):
        dep = dependency('private-test-helper')
        dep['kind'] = 'dev'
        self.metadata['packages'][0]['dependencies'].append(dep)
        self.assertTrue(plan(self.metadata, self.config)['ready'])


if __name__ == '__main__':
    unittest.main()
