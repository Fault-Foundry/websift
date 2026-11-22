import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from SQLi.options import SQLiOptions
from SQLi.profile import build_profile
from SQLi.sqli_scanner import scan_target, ReconTarget
from SQLi.waf_detect import WafDetectionResult
from shared_recon import Session, ReconService
from scan_pipeline import run_pipeline


class DetectionOptionsTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        env = patch.dict(os.environ, {}, clear=True)
        env.start()
        self.addCleanup(env.stop)

    async def test_default_pipeline_target_restores_full_techniques(self):
        engine = AsyncMock()
        engine.scan.return_value = ([], False)
        with patch('SQLi.sqli_scanner.detect_waf', AsyncMock(return_value=WafDetectionResult(False))):
            await scan_target(ReconTarget('https://lab.test/?q=1'), engine)
        target = engine.scan.call_args.args[0]
        self.assertEqual((target.level, target.risk), (3, 2))
        self.assertEqual(target.techniques, 'BEUSTQ')
        self.assertEqual(target.time_sec, 5)
        self.assertEqual(target.delay, 1)

    async def test_custom_coverage_is_independent_from_throttle(self):
        with patch.dict(os.environ, {'SQLI_LEVEL': '5', 'SQLI_RISK': '3',
                                     'SQLI_TECHNIQUES': 'BT', 'SQLI_TIME_SEC': '7',
                                     'SCAN_REQUEST_INTERVAL': '4'}):
            engine = AsyncMock()
            engine.scan.return_value = ([], False)
            with patch('SQLi.sqli_scanner.detect_waf', AsyncMock(return_value=WafDetectionResult(True))):
                await scan_target(ReconTarget('https://lab.test/?q=1'), engine)
        target = engine.scan.call_args.args[0]
        self.assertEqual((target.level, target.risk, target.techniques, target.time_sec, target.delay),
                         (5, 3, 'BT', 7, 4))

    async def test_default_xss_pipeline_runs_browser_probe(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = AsyncMock()
            run.project = Path(tmp)
            run.report = lambda: {}
            browser = AsyncMock(return_value={'status': 'completed', 'tested': 1, 'findings': [], 'errors': []})
            with patch('scan_pipeline.authenticate', AsyncMock(return_value=Session('A'))), \
                 patch('scan_pipeline.XSSRun', return_value=run), \
                 patch('browser_xss.check_forms', browser):
                result = await run_pipeline('https://lab.test/', 'xss', [('', '')], None, single=True)
            browser.assert_awaited_once()
            self.assertEqual(result['xss']['browser']['tested'], 1)

    def test_invalid_detection_settings_are_rejected(self):
        for key, values in {'SQLI_LEVEL': ['0', '6', 'bad'], 'SQLI_RISK': ['0', '4'],
                            'SQLI_TECHNIQUES': ['', 'XYZ', 'B,T'], 'SQLI_TIME_SEC': ['0', 'nan']}.items():
            for value in values:
                with self.subTest(key=key, value=value), patch.dict(os.environ, {key: value}):
                    with self.assertRaises(ValueError):
                        SQLiOptions.load()

    def test_caller_caps_and_explicit_quick_depth_still_apply(self):
        with patch.dict(os.environ, {'SQLI_LEVEL': '5', 'SQLI_RISK': '3', 'RECON_MAX_DEPTH': '8'}):
            profile = build_profile(WafDetectionResult(False), max_level=2, max_risk=1)
            self.assertEqual((profile.level, profile.risk), (2, 1))
            self.assertEqual(ReconService('https://lab.test/').max_depth, 8)
            self.assertEqual(ReconService('https://lab.test/', max_depth=0).max_depth, 0)
