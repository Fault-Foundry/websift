"""Application orchestration; discovery happens once per selected identity."""
import os
from pathlib import Path
from urllib.parse import urlsplit, parse_qsl, urlunsplit
from shared_recon import ReconService, authenticate
from SQLi.sqli_scanner import scan_target, _build_get_url, _serialize_data
from cookie_session import cookie_key
from scan_safety import scan_session, check_safety, Limits, SafetyStop
from IDOR.idor_detector import scan_inventories
from xss_bridge import XSSRun

BASE = Path(__file__).resolve().parent


async def _run_pipeline(url, mode, credentials, sqlmap_client, *, single=False):
    modes = ['sqli', 'idor', 'xss', 'exposure'] if mode == 'all' else [mode]
    exposure = {}
    if 'exposure' in modes:
        from exposure_bridge import run_exposure
        try:
            exposure['exposure'] = await run_exposure(url)
        except Exception as exc:
            exposure['exposure'] = {'status': 'error', 'findings': [], 'errors': [str(exc)]}
        modes.remove('exposure')
        if not modes:
            return exposure
    service = None if single else ReconService(url, os.environ.get('RECON_MODE', 'http'))
    inventories, errors = {}, {}
    labels = ['A', 'B'] if 'idor' in modes else ['A']
    for label, (username, password) in zip(labels, credentials):
        try:
            session = await authenticate(url, label, username, password)
            if single:
                from shared_recon import Inventory
                inventories[label] = Inventory(session, [url])
            else:
                inventories[label] = await service.discover(session)
        except Exception as exc:
            errors[label] = str(exc)
    results = dict(exposure)
    for tool in modes:
        check_safety()
        inventory = inventories.get('A')
        if inventory is None:
            results[tool] = {'status': 'error', 'errors': [errors.get('A', 'Missing session A')], 'findings': []}
            continue
        result = {'status': inventory.status, 'errors': list(inventory.errors), 'findings': []}
        try:
            if tool == 'sqli':
                if sqlmap_client is None:
                    raise RuntimeError('SQLmap is unavailable')
                exclude = os.environ.get('SQLI_EXCLUDE_PATHS', 'logout,signout,delete,destroy,reset,setup,security').split(',')
                coverage = result['coverage'] = new_sqli_coverage(inventory.sources, inventory.session.authenticated)
                count = 0
                seen = set()
                for target in inventory.targets:
                    if urlsplit(target.url).path.rstrip('/').lower() == '/socket.io':
                        coverage['service'] += 1
                        continue
                    key = sqli_target_key(target)
                    if key in seen:
                        coverage['duplicates'] += 1
                        continue
                    seen.add(key)
                    if any(x and x.lower() in urlsplit(target.url).path.lower() for x in exclude):
                        coverage['excluded'] += 1
                        continue
                    if not (urlsplit(target.url).query or target.params or target.data):
                        coverage['no_inputs'] += 1
                        continue
                    fields = set((target.params or {})) | set((target.data or {}))
                    if any('pass' in x.lower() or 'pwd' in x.lower() for x in fields):
                        coverage['login_forms'] += 1
                        continue
                    if Limits.load().targets and count >= Limits.load().targets:
                        result['status'] = 'incomplete'
                        result['errors'].append('Достигнут SCAN_MAX_TARGETS; часть SQLi-точек не проверена.')
                        break
                    count += 1
                    entry = record_sqli_target(coverage, target)
                    before_errors = len(result['errors'])
                    try:
                        findings = await scan_target(target, sqlmap_client, is_trusted_target=False, diagnostics=result["errors"])
                        result['findings'].extend(serialize_sqli_finding(f) for f in findings)
                        entry['status'] = 'неполная' if len(result['errors']) > before_errors else 'завершена'
                    except TimeoutError as exc:
                        entry['status'] = 'таймаут'
                        result['status'] = 'incomplete'
                        result['errors'].append(str(exc))
                    except Exception as exc:
                        result['status'] = 'incomplete'
                        result['errors'].append(str(exc))
                if not count and result['status'] == 'completed':
                    result['status'] = 'skipped'
                    result['errors'].append('No eligible SQLi inputs discovered')
            elif tool == 'idor':
                if 'B' not in inventories:
                    raise RuntimeError(errors.get('B', 'Missing session B'))
                if single:
                    from IDOR.idor_detector import scan_single_url
                    result = await scan_single_url(url, [inventory.session, inventories['B'].session])
                else:
                    result = await scan_inventories([inventory, inventories['B']])
                for item in (inventory, inventories['B']):
                    if item.status != 'completed':
                        result['status'] = 'incomplete'
                        result['errors'].extend(item.errors)
            elif tool == 'xss':
                run = XSSRun(url, os.environ.get('XSS_ORCHESTRATOR_PATH', str(BASE / 'xss-orchestrator/run.sh')),
                             os.environ.get('SCAN_OUTPUT_DIR', str(BASE / 'scan_output')))
                from browser_xss import check_forms
                result['browser'] = (await check_forms(url, inventory.session, single=single)
                                     if Limits.load().browser_forms else
                                     {'status': 'skipped', 'tested': 0, 'findings': [],
                                      'errors': [], 'note': 'Отправка форм выключена (SCAN_BROWSER_FORMS=0).'})
                import json
                (run.project / 'browser.json').write_text(json.dumps(result['browser'], ensure_ascii=False, indent=2))
                if result['browser']['status'] == 'incomplete':
                    result['status'] = 'incomplete'
                result['artifacts'] = str(run.project)
                if result['browser'].get('blocked_reason'):
                    result['errors'].append(result['browser']['blocked_reason'])
                    results[tool] = result
                    continue
                check_safety()
                await run.import_inventory(inventory)
                if single:
                    run.restrict_to_page(url)
                try:
                    await run.execute('scan', 3600)
                except Exception as exc:
                    result['status'] = 'incomplete'
                    result['errors'].append(str(exc))
                try:
                    result.update(run.report())
                    (run.project / 'xss_report.txt').write_text('\n'.join(format_xss_details(result)))
                except (OSError, ValueError):
                    if result['status'] == 'completed':
                        raise RuntimeError('Missing XSS report')
                finally:
                    (run.project / 'session.http').unlink(missing_ok=True)
                    (run.project / 'session.config.json').unlink(missing_ok=True)
        except Exception as exc:
            result['status'] = 'error'
            result['errors'].append(str(exc))
        if result.get('errors') and result['status'] == 'completed':
            result['status'] = 'incomplete'
        results[tool] = result
    return results


def sqli_target_key(target):
    # Only identical effective requests are duplicates; different values,
    # bodies and identities may reach different application code paths.
    return (target.method.upper(), _build_get_url(target.url, target.params),
            _serialize_data(target.data), cookie_key(target.cookies or {}),
            tuple(sorted((k.lower(), v) for k, v in (target.headers or {}).items())))


def new_sqli_coverage(sources, authenticated):
    return {'sources': list(sources), 'authenticated': authenticated,
            'targets': [], 'excluded': 0, 'no_inputs': 0, 'login_forms': 0, 'duplicates': 0, 'service': 0}


def record_sqli_target(coverage, target):
    parts = urlsplit(target.url)
    # Show input names, never query values, cookies or request bodies.
    fields = sorted(set(dict(parse_qsl(parts.query, keep_blank_values=True))) |
                    set(target.params or {}) | set(target.data or {}))
    entry = {'method': target.method, 'url': urlunsplit((parts.scheme, parts.netloc, parts.path, '', '')),
             'fields': fields, 'status': 'ошибка'}
    coverage['targets'].append(entry)
    return entry


def format_sqli_coverage(coverage):
    targets = coverage['targets']
    lines = [f"Сессия: {'с авторизацией' if coverage['authenticated'] else 'анонимная'}. "
             f"Разведка: {', '.join(coverage['sources']) or 'явно заданная точка'}.",
             f"Передано в sqlmap: {len(targets)} точек; завершено без ошибок обёртки: "
             f"{sum(t['status'] == 'завершена' for t in targets)}."]
    for entry in targets[:15]:
        lines.append(f"  {entry['method']} {entry['url']} | параметры: {', '.join(entry['fields']) or 'нет'} | {entry['status']}")
    if len(targets) > 15:
        lines.append(f"  Ещё {len(targets) - 15} точек не показаны.")
    lines.append(f"Пропущено: без параметров — {coverage['no_inputs']}, формы с паролем — "
                 f"{coverage['login_forms']}, исключённые пути — {coverage['excluded']}, "
                 f"дубли — {coverage['duplicates']}, служебный Socket.IO — {coverage['service']}.")
    lines.append('Охват ограничен обнаруженными запросами. Автоматический ввод в поиск SPA и проверка JSON POST пока не реализованы.')
    return lines


def serialize_sqli_finding(finding):
    return {'severity': finding.severity.value, 'vuln_type': finding.description,
            'confidence': finding.confidence.value, 'param': finding.parameter,
            'url': finding.url, 'evidence': finding.evidence,
            'remediation': finding.remediation, 'dbms': finding.extra.get('dbms')}


def format_detection_details(tool, report):
    findings = report.get('findings', [])
    if not findings:
        if report['status'] == 'completed':
            return ['На проверенных точках находок нет. Это не гарантирует отсутствие уязвимостей.']
        if report['status'] == 'skipped':
            return ['Проверка не выполнена: нет подходящих точек или данных для сравнения.']
        return ['Находок в полученных результатах нет; из-за неполной проверки вывод о безопасности сделать нельзя.']
    labels = {'low': 'низкая', 'medium': 'средняя', 'high': 'высокая', 'critical': 'критическая'}
    lines = [f'{"Кандидатов IDOR" if tool == "idor" else "Находок SQLi по данным sqlmap"}: {len(findings)}']
    for index, finding in enumerate(findings, 1):
        name = 'Возможный доступ к одному объекту из разных аккаунтов' if tool == 'idor' else finding.get('vuln_type', 'SQL-инъекция')
        lines.extend([f'\n{index}. {name}', f'   URL: {finding.get("url", "не указан")}',
                      f'   Параметр: {finding.get("param", "не указан")}',
                      f'   Опасность по оценке движка: {labels.get(str(finding.get("severity", "")).lower(), "не указана")}'])
        confidence = finding.get('confidence')
        # Numerical IDOR scores are heuristics, not calibrated probabilities.
        if isinstance(confidence, str) and confidence.lower() in labels:
            lines.append(f'   Уверенность движка: {labels[confidence.lower()]}')
        if tool == 'sqli' and finding.get('dbms'):
            lines.append(f'   СУБД по данным sqlmap: {finding["dbms"]}')
        if finding.get('evidence'):
            evidence = str(finding['evidence'])
            lines.append(f'   {"Тестовый ввод sqlmap" if tool == "sqli" else "Основание"}: {evidence[:1200]}' + (' … [сокращено]' if len(evidence) > 1200 else ''))
        else:
            lines.append('   Подробное доказательство движок не передал.')
    if tool == 'idor':
        lines.append('\nЭто кандидаты, не подтверждённые нарушения прав. Проверьте владельца объекта и разрешён ли совместный доступ; одинаковые ответы сами по себе не доказывают IDOR.')
    else:
        lines.append('\nРезультат основан на проверке sqlmap. Рекомендация: параметризованные запросы вместо сборки SQL из пользовательского ввода.')
    return lines


def format_xss_details(report):
    """Present engine evidence as candidates, never as browser-confirmed XSS."""
    import re
    strong = len(report.get('strong_candidates', []))
    dom = len(report.get('dom_candidates', []))
    reflections = len(report.get('reflections', []))
    other = len(report.get('other', []))
    browser = report.get('browser')
    confirmed = browser.get('findings', []) if browser else []
    if browser and browser.get('blocked_reason'):
        return ['Итог: XSS-проверка игры не выполнена — в текущей сессии уровень недоступен.']
    if confirmed:
        verdict = f'Итог: выполнение тестового JavaScript подтверждено в браузере: {len(confirmed)}.'
    elif strong:
        verdict = f'Итог: найдены XSS-кандидаты — {strong}. Выполнение JavaScript не подтверждено.'
    elif dom:
        verdict = f'Итог: XSS не подтверждена. Подозрительных участков JavaScript: {dom}; готового воспроизведения нет.'
    elif report.get('status') in ('error', 'incomplete', 'skipped'):
        verdict = 'Итог: результат проверки XSS неопределён — проверка не завершена полностью.'
    elif reflections or other:
        verdict = 'Итог: XSS-кандидатов не найдено; есть только отражения или другие сигналы.'
    else:
        verdict = 'Итог: сканер не обнаружил XSS в этой проверке.'
    lines = [verdict]
    if browser:
        lines.append(f"Браузер: попыток — {browser['tested']}; статус — {browser['status']}.")
        if browser.get('note'):
            lines.append(browser['note'])
        lines.extend(browser.get('errors', []))
        if not browser['tested']:
            lines.append('Доступных для автоматического теста форм не найдено или тест не выполнен. Проверьте, что сессия открывает саму игру, а не страницу ограничения доступа.')
        for finding in confirmed:
            lines.extend([f"URL формы: {finding['url']}", f"Поле: {finding['param']}; форма № {finding['form'] + 1}",
                          f"Введите в поле и отправьте форму: {finding['payload']}", f"Доказательство: {finding['evidence']}"])
    coverage = report.get('coverage', {})
    if coverage:
        lines.append(f"Передано адресов в XSS-движок: {coverage['supplied_urls']}; GET-целей из форм: {coverage['get_form_targets']}.")
        if coverage.get('post_targets_not_imported'):
            lines.append(f"Ограничение: POST-целей из разведки не передано: {coverage['post_targets_not_imported']}. Их проверка этим запуском не установлена.")
    if report.get('single_page'):
        lines.append('Режим: одна страница. Скрипты по другим путям исключены; анализ DOM XSS ограничен. Для более полного анализа используйте /xss <url>.')
    metadata = report.get('metadata', {})
    for key, label in (('reflected', 'Проверка ввода'), ('dom', 'Анализ DOM')):
        meta = metadata.get(key, {}) if isinstance(metadata, dict) else {}
        if isinstance(meta, dict) and 'total_requests' in meta:
            lines.append(f'{label}: запросов {meta["total_requests"]}, ошибок запросов {meta.get("failed_requests", "не указано")}.')
    confidence_labels = {'low': 'низкая', 'medium': 'средняя', 'high': 'высокая'}
    categories = [('strong_candidates', 'Сильные XSS-кандидаты'),
                  ('dom_candidates', 'Участки JavaScript для проверки'),
                  ('reflections', 'Отражения ввода без доказательства XSS'),
                  ('other', 'Прочие сигналы')]
    count = sum(len(report.get(key, [])) for key, _ in categories)
    if not count:
        lines.append('В полученных результатах кандидатов нет. Это не доказывает отсутствие XSS.')
    for key, title in categories:
        entries = report.get(key, [])
        if not entries:
            continue
        lines.append(f'\n{title}: {len(entries)}')
        for number, finding in enumerate(entries[:10], 1):
            if not isinstance(finding, dict):
                lines.append(f'{number}. Запись нестандартного формата — см. файл отчёта.')
                continue
            confidence = confidence_labels.get(str(finding.get('confidence', '')).lower(), 'не указана')
            evidence = str(finding.get('evidence') or '')
            flow = re.search(r'\(Source: (.*?), Sink: (.*?)\)', evidence)
            description = f'{flow[1]} → {flow[2]}' if flow else str(finding.get('message_str') or finding.get('inject_type') or 'Кандидат XSS')
            lines.append(f'{number}. {description[:350]}')
            if key == 'dom_candidates':
                target = finding.get('data') or finding.get('url')
                if isinstance(target, str) and target.startswith(('http://', 'https://')):
                    lines.append(f'   Страница анализа: {target}')
                script = re.search(r'\[script: (.*?)\]', evidence)
                location = re.search(r':(\d+):(\d+) - ', evidence)
                lines.append(f"   Скрипт: {script[1] if script else 'движок не указал'}")
                if location:
                    lines.append(f'   Строка: {location[1]}, столбец: {location[2]} (по отчёту движка)')
                source = flow[1] if flow else finding.get('param')
                if source:
                    lines.append(f'   Источник в коде: {source}')
                lines.append('   Точка ввода на странице: не установлена; источник в коде не является именем поля формы или GET-параметра.')
                payload = finding.get('payload')
                lines.append(f'   Шаблон JavaScript от движка: {payload}' if payload else '   Шаблон JavaScript: движок не предоставил.')
                lines.append('   Payload для воспроизведения через сайт: не установлен.')
                lines.append(f'   Уверенность движка: {confidence}. Контроль источника пользователем и выполнение не проверены.')
                lines.append('   Проверка: проследить путь от ввода пользователя до указанной операции в скрипте. Вставка шаблона в консоль XSS не подтверждает.')
                continue

            severity = {'low': 'низкая', 'medium': 'средняя', 'high': 'высокая', 'critical': 'критическая'}.get(str(finding.get('severity', '')).lower(), 'не указана')
            lines.append(f'   Опасность: {severity} | Уверенность движка: {confidence}')
            target = finding.get('data') or finding.get('url')
            if isinstance(target, str) and target.startswith(('http://', 'https://')):
                lines.append(f'   URL: {target}')
            if finding.get('method'):
                lines.append(f'   Метод: {finding["method"]}')
            if finding.get('param'):
                label = 'Источник в JS' if key == 'dom_candidates' else 'Параметр'
                lines.append(f'   {label}: {finding["param"]}')
            payload = finding.get('payload')
            if payload:
                label = 'Payload движка (выполнение не проверено)' if key == 'dom_candidates' else 'Тестовый ввод Dalfox'
                lines.append(f'   {label}: {payload}')
            else:
                lines.append('   Payload: движок не предоставил.')
            script = re.search(r'\[script: (.*?)\]', evidence)
            if script:
                lines.append(f'   Скрипт: {script[1][:500]}')
            location = re.search(r':(\d+):(\d+) - ', evidence)
            if location:
                lines.append(f'   Позиция по отчёту движка: {location[1]}:{location[2]}')
            reason = finding.get('confidence_reason')
            if reason == 'source needs an attacker-controlled page to set up':
                reason = 'Нужно подтвердить возможность управлять источником через страницу атакующего.'
            if reason:
                lines.append(f'   Ограничение: {str(reason)[:400]}')
        if len(entries) > 10:
            lines.append(f'Ещё {len(entries) - 10} записей — в полном отчёте.')
    if count:
        lines.append('\nDOM-записи выше не подтверждены браузером; шаблоны AST не являются готовым воспроизведением.' if browser else '\nБраузерное подтверждение не проводилось. Payload из AST-анализа — не готовое доказательство XSS.')
    if report.get('artifacts'):
        lines.append(f'Файлы отчёта на компьютере бота: {report["artifacts"]}')
    return lines


def format_xss_summary(report):
    import re
    browser = report.get('browser', {})
    findings = browser.get('findings', [])
    if browser.get('blocked_reason'):
        return ['XSS-проверка не выполнена: ' + browser['blocked_reason']]
    lines = [f'Подтверждено в браузере: {len(findings)}.' if findings else
             'Выполнение XSS не подтверждено. Это не доказывает отсутствие уязвимостей.']
    for i, f in enumerate(findings[:5], 1):
        lines.extend([f"\n{i}. {f['url']}", f"Поле: {f['param']}; форма № {f['form'] + 1}",
                      f"Введите и отправьте: {f['payload']}"])
    if len(findings) > 5:
        lines.append(f'Ещё подтверждений: {len(findings) - 5}; см. полный отчёт.')
    strong = report.get('strong_candidates', [])
    confirmed_keys = {(urlsplit(f['url']).path, f['param']) for f in findings}
    remaining = [f for f in strong if (urlsplit(f.get('data') or f.get('url') or '').path, f.get('param')) not in confirmed_keys]
    if remaining:
        lines.append(f'Кандидатов Dalfox без браузерного подтверждения: {len(remaining)}.')
        for f in remaining[:3]:
            lines.extend([f"URL: {f.get('data') or f.get('url') or 'не указан'}; параметр: {f.get('param', 'не указан')}",
                          f"Тестовый ввод: {f.get('payload') or 'не предоставлен'}"])
    dom = report.get('dom_candidates', [])
    keys = set()
    for index, f in enumerate(dom):
        evidence = str(f.get('evidence', ''))
        script = re.search(r'\[script: (.*?)\]', evidence)
        location = re.search(r':(\d+):(\d+) - ', evidence)
        flow = re.search(r'\(Source: (.*?), Sink: (.*?)\)', evidence)
        keys.add((script[1], location.groups(), flow.groups()) if script and location and flow else ('unresolved', index))
    if dom:
        lines.append(f'Статический анализ: {len(keys)} участков JS ({len(dom)} записей с повторами); детали в файле отчёта. Это не подтверждённые XSS.')
    if browser:
        lines.append(f"Браузер: попыток — {browser.get('tested', 0)}, статус — {browser.get('status')}.")
        if browser.get('note'):
            lines.append(browser['note'])
        lines.extend(browser.get('errors', []))
    if report.get('single_page'):
        lines.append('Быстрая проверка: один путь; покрытие ограничено.')
    coverage = report.get('coverage', {})
    if coverage.get('post_targets_not_imported'):
        lines.append(f"POST-целей не передано в Dalfox: {coverage['post_targets_not_imported']}.")
    if report.get('artifacts'):
        lines.append(f"Полный отчёт: {report['artifacts']}/xss_report.txt")
    return lines


def format_results(url, results):
    lines = [f'Результаты: {url}']
    for tool, report in results.items():
        status = {'completed': 'проверка завершена', 'incomplete': 'проверка неполная',
                  'error': 'ошибка проверки', 'skipped': 'проверка пропущена'}.get(report['status'], report['status'])
        lines.append(f'[{tool.upper()}] {status}')
        lines.extend('  ' + message for message in report.get('errors', []))
        lines.extend('  ' + message for message in report.get('notes', []))
        if tool == 'exposure':
            from exposure_bridge import format_exposure
            lines.extend(format_exposure(report))
        if tool == 'sqli' and 'coverage' in report:
            lines.extend(format_sqli_coverage(report['coverage']))
        if tool in ('sqli', 'idor'):
            lines.extend(format_detection_details(tool, report))
        if tool == 'xss':
            lines.extend(format_xss_summary(report) if report.get('browser') or report.get('artifacts') else format_xss_details(report))
    return '\n'.join(lines)


async def _run_single(url, body, credentials, sqlmap_client):
    from urllib.parse import parse_qsl
    from SQLi.sqli_scanner import ReconTarget
    result = {'status': 'completed', 'findings': [], 'errors': []}
    try:
        if sqlmap_client is None:
            raise RuntimeError('SQLmap is unavailable')
        session = await authenticate(url, 'A', *credentials)
        coverage = result['coverage'] = new_sqli_coverage([], session.authenticated)
        if body or urlsplit(url).query:
            targets = [ReconTarget(url, 'POST' if body else 'GET',
                                   data=dict(parse_qsl(body, keep_blank_values=True)) if body else None,
                                   cookies=session.cookies, headers=session.headers)]
        else:
            inventory = await ReconService(url, 'http', max_pages=1, max_depth=0).discover(session)
            targets = [t for t in inventory.targets if t.params or t.data or urlsplit(t.url).query]
            result.update(status=inventory.status, errors=inventory.errors)
            coverage['sources'] = inventory.sources
            coverage['no_inputs'] = len(inventory.targets) - len(targets)
        if Limits.load().targets and len(targets) > Limits.load().targets:
            result['status'] = 'incomplete'
            result['errors'].append('Достигнут SCAN_MAX_TARGETS; часть SQLi-точек не проверена.')
        if not targets and result['status'] == 'completed':
            result['status'] = 'skipped'
        for target in targets[:Limits.load().targets or None]:
            entry = record_sqli_target(coverage, target)
            before_errors = len(result['errors'])
            findings = await scan_target(target, sqlmap_client, is_trusted_target=False, diagnostics=result["errors"])
            result['findings'].extend(serialize_sqli_finding(f) for f in findings)
            entry['status'] = 'неполная' if len(result['errors']) > before_errors else 'завершена'
    except Exception as exc:
        result['status'] = 'error'
        result['errors'].append(str(exc))
    if result.get('errors') and result['status'] == 'completed':
        result['status'] = 'incomplete'
    return result


async def run_pipeline(url, mode, credentials, sqlmap_client, *, single=False):
    try:
        async with scan_session():
            return await _run_pipeline(url, mode, credentials, sqlmap_client, single=single)
    except (SafetyStop, TimeoutError) as exc:
        message = str(exc) or 'Остановка: истёк общий SCAN_TIMEOUT.'
        modes = ['sqli', 'idor', 'xss', 'exposure'] if mode == 'all' else [mode]
        return {tool: {'status': 'incomplete', 'findings': [], 'errors': [message], 'retryable': getattr(exc, 'retryable', False)} for tool in modes}


async def run_single(url, body, credentials, sqlmap_client):
    try:
        async with scan_session():
            return await _run_single(url, body, credentials, sqlmap_client)
    except (SafetyStop, TimeoutError) as exc:
        return {'status': 'incomplete', 'findings': [],
                'errors': [str(exc) or 'Остановка: истёк общий SCAN_TIMEOUT.'],
                'retryable': getattr(exc, 'retryable', False)}
