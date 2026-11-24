from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED

ROOT = Path(__file__).resolve().parents[1]
TOP = ['README.md', 'INTEGRATION.md', '.env.example', '.gitignore',
       'requirements.txt', 'requirements-cli.txt', 'requirements-browser.txt', 'websift', 'websift.py', 'cli.py', 'scan_runner.py', 'bot.py', 'browser_auth.py',
       'browser_xss.py', 'durable_queue.py', 'scan_safety.py', 'cookie_session.py', 'shared_recon.py', 'scan_pipeline.py', 'xss_bridge.py']
PATTERNS = ['SQLi/*.py', 'IDOR/*.py', 'tests/*.py', 'scripts/*.py', 'deploy/*.service',
            'xss-orchestrator/*.py', 'xss-orchestrator/*.sh', 'xss-orchestrator/*.md',
            'xss-orchestrator/example/*.txt']


def main():
    files = {ROOT / name for name in TOP}
    for pattern in PATTERNS:
        files.update(ROOT.glob(pattern))
    dest = ROOT / 'dist' / 'web_vuln_scan.zip'
    dest.parent.mkdir(exist_ok=True)
    with ZipFile(dest, 'w', ZIP_DEFLATED) as archive:
        for file in sorted(files):
            if file.is_symlink() or not file.is_file():
                raise ValueError(f'Missing file or unexpected symlink: {file.relative_to(ROOT)}')
            archive.write(file, 'web_vuln_scan/' + file.relative_to(ROOT).as_posix())
    print(f'{dest} ({len(files)} files)')


if __name__ == '__main__':
    main()
