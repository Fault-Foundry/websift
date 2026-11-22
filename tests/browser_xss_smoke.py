import asyncio
from unittest.mock import patch
from shared_recon import Session
from browser_xss import check_forms


async def main():
    for vulnerable, override_alert in ((True, False), (True, True), (False, False), (False, True)):
        async def context(browser, url, *args):
            ctx = await browser.new_context()
            assignment = 'innerHTML' if vulnerable else 'textContent'
            html = '<form onsubmit="event.preventDefault(); document.getElementById(\'out\').' + assignment + '=this.elements.comment.value"><textarea name="comment"></textarea><button>Post</button></form><div id="out"></div>'
            if override_alert:
                html = '<script>window.alert = function() {};</script>' + html
            await ctx.route('**/*', lambda route: route.fulfill(status=200, content_type='text/html', body=html) if route.request.resource_type == 'document' else route.abort())
            return ctx
        with patch('browser_xss.scoped_context', context):
            result = await check_forms('http://lab.test/', Session('A'))
        assert not result['errors'], result['errors']
        assert result['tested'] == (1 if vulnerable else 2), result
        assert bool(result['findings']) == vulnerable, result
    print('Real browser: vulnerable form confirmed; escaped form not confirmed')


if __name__ == '__main__':
    asyncio.run(main())
