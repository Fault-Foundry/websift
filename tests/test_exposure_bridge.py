import unittest
from unittest.mock import AsyncMock, patch

from exposure_bridge import run_exposure
from scan_pipeline import run_pipeline, format_results


class ExposureTests(unittest.IsolatedAsyncioTestCase):
    async def test_standalone_skips_recon(self):
        report = {'status': 'completed', 'findings': [], 'errors': []}
        with patch('exposure_bridge.run_exposure', AsyncMock(return_value=report)), patch('scan_pipeline.ReconService') as recon:
            result = await run_pipeline('https://example.test/path', 'exposure', [], None)
        recon.assert_not_called()
        self.assertEqual(result, {'exposure': report})
        self.assertIn('EXPOSURE', format_results('https://example.test', result))

    async def test_credentials_rejected(self):
        with self.assertRaises(ValueError):
            await run_exposure('https://user:password@example.test')
