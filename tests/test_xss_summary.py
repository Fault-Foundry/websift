import unittest
from scan_pipeline import format_xss_summary


class SummaryTests(unittest.TestCase):
    def test_confirmed_result_keeps_exact_payload_and_collapses_static_duplicates(self):
        dom = {'evidence': 'https://lab.test/page:20:5 - DOM (Source: input, Sink: eval) [script: https://lab.test/game.js]'}
        report = {'browser': {'tested': 1, 'status': 'completed', 'findings': [
            {'url': 'https://lab.test/frame', 'param': 'query', 'form': 0, 'payload': '<svg onload=alert(1)>'}]},
            'dom_candidates': [dom] * 9, 'artifacts': '/tmp/report'}
        text = '\n'.join(format_xss_summary(report))
        self.assertIn('Подтверждено в браузере: 1', text)
        self.assertIn('<svg onload=alert(1)>', text)
        self.assertIn('1 участков JS (9 записей', text)
        self.assertIn('/tmp/report/xss_report.txt', text)
        self.assertLess(len(text), 800)

    def test_unconfirmed_not_reported_as_confirmed(self):
        text = '\n'.join(format_xss_summary({'browser': {'tested': 2, 'status': 'completed', 'findings': []}}))
        self.assertIn('не подтверждено', text)
        self.assertIn('попыток — 2', text)
