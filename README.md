# WebSift

WebSift is a Python CLI for web application security testing. It brings together SQL injection, cross-site scripting, and access control findings in one report per URL. Each report shows what each engine found, the evidence behind the finding, and which findings warrant manual review.

## Read a report from the CLI

List recent batches, then export the results for a completed batch. Replace `BATCH_ID` with the ID shown by the first command.

```sh
./websift queue
./websift report BATCH_ID
```

You can also run the CLI as `python3 websift.py`. The previous `python3 cli.py` entry point remains available for existing scripts.

The CLI prints the report and writes a text file and a JSON file for each completed job under `reports/<batch-id>/` in the CLI queue directory.

This excerpt shows how a timeout appears in a JSON report:

```json
{
  "url": "https://lab.test",
  "results": {
    "xss": {
      "status": "incomplete",
      "errors": ["timeout"]
    }
  }
}
```

Here the XSS check timed out. Other checks have their own statuses and can still have findings for the same URL.

## What WebSift records

| Check | Evidence in the report |
| --- | --- |
| SQL injection (SQLi) | The request parameter, the injection type, and the evidence sqlmap used to identify the vulnerability. |
| Cross-site scripting (XSS) | Dalfox findings and instances where the page reflects user input. For potential DOM-based XSS, the report includes the data source and, when available, the relevant JavaScript for review. |
| Insecure direct object references (IDOR) | Responses from requests for the same object using two different user sessions. Reviewers can compare the observed behavior with the application's access rules. |

For example, if two accounts can open the same record, the responses alone cannot establish who should have access. WebSift flags the observation as a potential IDOR. The reviewer checks it against the application's access rules to determine whether access was unauthorized.

## Telegram bot

The Telegram bot uses the same scan engine and sends the plain-text report to the chat. The CLI also exports structured JSON. In the bot, only the explicit choice `defaults` selects the configured accounts. Entering one account leaves the second account empty. The bot and CLI each keep a separate queue on disk. Both support pausing and resuming batches. After an interruption, the worker resumes at the URL it was processing.

For details on how the engines work, see the [integration notes](INTEGRATION.md). The [report tests](tests/test_report_format.py) show how WebSift presents findings, skipped checks, and errors.
