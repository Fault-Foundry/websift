import asyncio
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
from browser_auth import browser_login, browser_discover, BrowserAuthError

HTML = '''<!doctype html><html><body><main></main><script>
const store = location.search.includes('session') ? sessionStorage : localStorage;
async function render() {
 const main = document.querySelector('main');
 const token = store.getItem('token');
 if(token) {
   const r = await fetch('/api/me', {headers:{Authorization:'Bearer '+token}});
   if(r.ok) {main.innerHTML='<a href="/#/account">Account</a><p>Signed in</p>'; return;}
 }
 main.innerHTML='<form><input type="email" autocomplete="username"><input type="password"><button type="submit">Login</button></form>';
 main.querySelector('form').onsubmit=async (e)=>{
   e.preventDefault();
   const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:main.querySelector('[type=email]').value,password:main.querySelector('[type=password]').value})});
   if(r.ok){store.setItem('token',(await r.json()).token);await render();}
 };
}
render();
</script></body></html>'''


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, status, body, kind='application/json'):
        raw = body.encode()
        self.send_response(status)
        self.send_header('Content-Type', kind)
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.path == '/api/me':
            token = self.headers.get('Authorization', '')
            if token in ('Bearer a@example.test', 'Bearer b@example.test'):
                self.reply(200, json.dumps({'user':{'email': token.split(' ', 1)[1]}}))
            else:
                self.reply(401, '{}')
        else:
            self.reply(200, HTML, 'text/html')

    def do_POST(self):
        data = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        if self.path == '/api/login' and data.get('password') == 'correct':
            self.reply(200, json.dumps({'token': data['email']}))
        else:
            self.reply(401, '{}')


async def check(url):
    for suffix in ('', '?session'):
        sessions = [await browser_login(url+suffix, label, email, 'correct')
                    for label,email in [('A','a@example.test'), ('B','b@example.test')]]
        assert sessions[0].headers != sessions[1].headers
        for session in sessions:
            found = await browser_discover(url+suffix, session, max_pages=3)
            assert url + 'api/me' in found
    try:
        await browser_login(url, 'A', 'a@example.test', 'wrong')
    except BrowserAuthError:
        pass
    else:
        raise AssertionError('Wrong password was accepted')
    print('Browser SPA smoke: localStorage, sessionStorage, two accounts, discovery, wrong password OK')


if __name__ == '__main__':
    import playwright.async_api
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        asyncio.run(check(f'http://127.0.0.1:{server.server_port}/'))
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
