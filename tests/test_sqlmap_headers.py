import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

import httpx
from SQLi.sqlmap_client import SqlmapClient, SqlmapTarget, SqlmapAPIError


class HeaderTests(unittest.IsolatedAsyncioTestCase):
    async def options(self, headers):
        captured = {}
        def handler(request):
            captured.update(json.loads(request.content))
            return httpx.Response(200, json={'success': True})
        client = SqlmapClient(sqlmap_dir='/unused')
        async with httpx.AsyncClient(base_url='https://api.test', transport=httpx.MockTransport(handler)) as http:
            client._http = http
            await client.start_scan('task', SqlmapTarget('http://lab.test/?q=a', headers=headers))
        return captured

    async def test_single_and_multiple_headers_through_installed_sqlmap(self):
        root = os.environ.get('SQLMAP_DIR', '/usr/share/sqlmap')
        if not (Path(root) / 'sqlmap.py').is_file():
            self.skipTest('installed sqlmap required for config round-trip')
        script = r'''
import json, sys, tempfile
sys.path.insert(0, sys.argv[1])
from lib.core.common import saveConfig
from lib.core.data import conf
from lib.parse.configfile import configFileParser
from lib.core.option import _setHTTPExtraHeaders
options = json.load(sys.stdin)
with tempfile.NamedTemporaryFile() as f:
    saveConfig(options, f.name)
    configFileParser(f.name)
    conf.httpHeaders = []
    _setHTTPExtraHeaders()
    print(json.dumps(conf.httpHeaders))
'''
        for headers in ({'Authorization': 'Bearer test-token'},
                        {'Authorization': 'Bearer test-token', 'X-Test': 'example'}):
            options = await self.options(headers)
            result = subprocess.run([sys.executable, '-c', script, root], input=json.dumps(options),
                                    text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(dict(json.loads(result.stdout)), headers)

    async def test_no_headers_and_injection_rejection(self):
        self.assertNotIn('headers', await self.options({}))
        with self.assertRaises(SqlmapAPIError):
            await self.options({'Authorization': 'Bearer test\r\nX-Injected: value'})
