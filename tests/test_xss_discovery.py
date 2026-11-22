import unittest
import tempfile
from pathlib import Path
from bs4 import BeautifulSoup
from SQLi.recon import Crawler
from SQLi.sqli_scanner import ReconTarget
from shared_recon import Inventory, Session
from xss_bridge import XSSRun


class DiscoveryTests(unittest.IsolatedAsyncioTestCase):
    def test_same_origin_frames_enter_crawl(self):
        crawler = Crawler('https://lab.test/level2')
        html = BeautifulSoup('''<iframe src="/level2/frame"></iframe>
            <iframe src="https://other.test/frame"></iframe>
            <iframe src="javascript:alert(1)"></iframe>
            <iframe src="/logout"></iframe><a href="/next">next</a>''', 'html.parser')
        self.assertEqual(crawler._extract_internal_links(html, 'https://lab.test/level2'),
                         ['https://lab.test/level2/frame', 'https://lab.test/next'])

    async def test_form_inputs_imported_and_external_urls_filtered(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = XSSRun('https://lab.test/', Path(__file__).resolve().parents[1] / 'xss-orchestrator/run.sh', tmp)
            await run.import_inventory(Inventory(Session('A'), ['https://lab.test/'], [
                ReconTarget('https://lab.test/search', params={'q': 'test value'}),
                ReconTarget('https://external.test/search', params={'q': 'test'}),
                ReconTarget('https://lab.test/post', 'POST', data={'text': 'test'})]))
            self.assertIn('https://lab.test/search?q=test+value', run.urls())
            self.assertFalse(any('external.test' in url for url in run.urls()))
            self.assertNotIn('https://lab.test/post', run.urls())
