# Validation

Проверено 2026-11-08.

- Bash syntax: `run.sh`, `install.sh` — OK.
- Python compilation: `glue.py` — OK.
- Offline scope: lookalike host, userinfo, другой scheme/port, статические расширения, encoded excluded path — отсекаются.
- Query preservation: duplicate keys, empty values, разные значения одного параметра и hash routes — сохраняются.
- Reports: AST отделяется от сильных reflected-кандидатов даже при типе V; ошибки/неполные сканы помечаются INCOMPLETE.
- **Реальный Dalfox 3.2.4**, локальная контролируемая HTTP-страница с неэкранированным отражением: тип V, метод reflection.
- Тот же движок, экранированное отражение: V не найден.
- Тот же движок, `location.hash → innerHTML`: тип A, метод ast, с пометкой needs runtime confirmation.
- Bash integration: crawler stub + настоящий Dalfox. Полный цикл разбор/фильтр/два прохода/классификация завершился с кодом 0; strong_candidates=1, dom_candidates=1; off-scope URL от stub отсеян.

Полный запуск с Katana и gau и установка всех трёх бинарников не проверены. В интеграционном тесте использовалась заглушка краулера. Выполнение JavaScript в браузере этот тест не проверяет.
