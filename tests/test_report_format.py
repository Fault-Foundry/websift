import unittest
from scan_pipeline import format_results


class ReportTests(unittest.TestCase):
    def test_dom_evidence_is_candidate_with_confidence_and_source(self):
        finding = {'confidence':'low', 'data':'https://lab.test/level2',
                   'evidence':'https://lab.test/level2:20:5 - DOM (Source: XMLHttpRequest.responseText, Sink: eval) [script: https://lab.test/static/game.js]',
                   'confidence_reason':'source needs an attacker-controlled page to set up'}
        text = format_results('https://lab.test/level2', {'xss': {'status':'completed','dom_candidates':[finding]}})
        for expected in ('проверка завершена', 'не проводилось', 'XMLHttpRequest.responseText → eval',
                         'Уверенность движка: низкая', 'https://lab.test/static/game.js', 'Строка: 20, столбец: 5', 'Участки JavaScript для проверки'):
            self.assertIn(expected, text)
        self.assertNotIn('dom_candidates', text)

    def test_empty_incomplete_not_clean(self):
        text = format_results('https://lab.test', {'xss':{'status':'incomplete','errors':['timeout']}})
        self.assertIn('проверка неполная', text)
        self.assertIn('timeout', text)
        self.assertIn('не доказывает отсутствие', text)

    def test_reflections_not_called_confirmed(self):
        text = format_results('https://lab.test', {'xss':{'status':'completed','reflections':[{}]}})
        self.assertIn('Отражения ввода без доказательства XSS: 1', text)
        self.assertNotIn('Сильные XSS-кандидаты', text)

    def test_large_report_has_explicit_truncation(self):
        text = format_results('https://lab.test', {'xss':{'status':'completed','dom_candidates':[{}]*12}})
        self.assertIn('Ещё 2 записей', text)

    def test_sqli_evidence_survives_serialization(self):
        from scan_pipeline import serialize_sqli_finding
        from SQLi.finding import Finding, VulnType, Severity, Confidence
        finding = Finding(VulnType.SQLI, 'https://lab.test/?id=1', 'id', Severity.HIGH,
                          Confidence.HIGH, 'SQL Injection (boolean-based)', evidence='id=1 AND 1=1', extra={'dbms':'SQLite'})
        text = format_results(finding.url, {'sqli':{'status':'completed','findings':[serialize_sqli_finding(finding)]}})
        for expected in ('boolean-based', 'Параметр: id', 'высокая', 'SQLite', 'id=1 AND 1=1'):
            self.assertIn(expected, text)

    def test_idor_evidence_and_limitations(self):
        text = format_results('https://lab.test', {'idor':{'status':'completed','findings':[
            {'url':'https://lab.test/object/1','param':'path:2','severity':'medium','confidence':0.5,
             'evidence':'Аккаунты A и B: HTTP A=200, B=200, гость=403.'}]}})
        self.assertIn('гость=403', text)
        self.assertIn('не подтверждённые нарушения', text)
        self.assertNotIn('50%', text)

    def test_empty_statuses_are_distinct(self):
        for tool in ('sqli','idor'):
            completed = format_results('https://lab.test',{tool:{'status':'completed'}})
            skipped = format_results('https://lab.test',{tool:{'status':'skipped'}})
            error = format_results('https://lab.test',{tool:{'status':'error','errors':['engine failed']}})
            self.assertIn('На проверенных точках находок нет', completed)
            self.assertIn('Проверка не выполнена', skipped)
            self.assertIn('вывод о безопасности сделать нельзя', error)
            self.assertIn('engine failed', error)

    def test_xss_empty_quick_verdict_and_coverage(self):
        text = format_results('https://lab.test/page', {'xss':{'status':'completed','single_page':True,
                              'metadata':{'dom':{'total_requests':2,'failed_requests':0}}}})
        self.assertIn('Итог: сканер не обнаружил XSS в этой проверке.', text)
        self.assertIn('Скрипты по другим путям исключены', text)
        self.assertIn('Анализ DOM: запросов 2', text)

    def test_xss_verdict_distinguishes_candidates_and_unknown(self):
        candidate = format_results('https://lab.test', {'xss':{'status':'completed','dom_candidates':[{}]}})
        self.assertIn('Подозрительных участков JavaScript: 1', candidate)
        self.assertIn('готового воспроизведения нет', candidate)
        unknown = format_results('https://lab.test', {'xss':{'status':'incomplete'}})
        self.assertIn('результат проверки XSS неопределён', unknown)
        self.assertNotIn('Итог: сканер не обнаружил', unknown)

    def test_dom_payload_is_exact_and_not_claimed_executed(self):
        payload = 'data:text/javascript,alert(1)/*marker*/'
        text = format_results('https://lab.test', {'xss':{'status':'completed','dom_candidates':[
            {'param':'fn_param_1','payload':payload,'confidence':'low','severity':'Medium','method':'GET','data':'https://lab.test'}]}})
        self.assertIn('Источник в коде: fn_param_1', text)
        self.assertIn('Шаблон JavaScript от движка: '+payload, text)
        self.assertIn('Точка ввода на странице: не установлена', text)
        self.assertIn('Payload для воспроизведения через сайт: не установлен', text)
        self.assertNotIn('Метод: GET', text)
        self.assertNotIn('Опасность: средняя', text)

    def test_reflected_payload_and_parameter_visible(self):
        text = format_results('https://lab.test', {'xss':{'status':'completed','strong_candidates':[
            {'param':'search','payload':'<svg onload=alert(1)>','method':'GET','confidence':'high'}]}})
        self.assertIn('Параметр: search', text)
        self.assertIn('Тестовый ввод Dalfox: <svg onload=alert(1)>', text)
        self.assertIn('Выполнение JavaScript не подтверждено', text)

    def test_missing_payload_not_fabricated(self):
        text = format_results('https://lab.test', {'xss':{'status':'completed','dom_candidates':[{}]}})
        self.assertIn('Шаблон JavaScript: движок не предоставил.', text)
        self.assertNotIn('alert(1)', text)
