"""Ask the questions of genie/eval.yaml to a Genie Agent and print the pass rate.

    uv run --frozen python tools/genie_eval.py --profile some-profile --space-id <id> [--mode agent|chat]
        [--only 1,5] [--strict] [--workers 4] [--out results.json]

Agent mode (default) uses the Agent mode API (Beta, Server-Sent Events from
/api/2.0/genie/agents/<space>/responses). If the workspace does not allow it, the tool uses the
Conversation API (Chat mode) instead. A question passes when the answer contains every `expect` item
(case-insensitive); an item that is a list passes when one of its strings is there. By default the
answer is the final text and the result tables of the queries Genie ran; --strict checks the text only.
Exit code 1 when the pass rate is below --target (default 0.9).
"""
from __future__ import annotations

import argparse
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

import requests
import yaml
from databricks.sdk import WorkspaceClient

EVAL = Path(__file__).resolve().parents[1] / "genie" / "eval.yaml"


@dataclass
class Answer:
    text: str = ""
    tables: list[str] = field(default_factory=list)
    sql: list[str] = field(default_factory=list)
    error: str = ""


class AgentModeUnavailable(Exception):
    pass


def ask_agent(w: WorkspaceClient, space_id: str, question: str, timeout: int = 900) -> Answer:
    url = f"{w.config.host.rstrip('/')}/api/2.0/genie/agents/{space_id}/responses"
    headers = {**w.config.authenticate(), "Content-Type": "application/json", "Accept": "text/event-stream"}
    body = {"model": "genie-agent", "stream": True,
            "input": [{"type": "message", "role": "user",
                       "content": [{"type": "input_text", "text": question}]}]}
    r = requests.post(url, headers=headers, json=body, stream=True, timeout=timeout)
    if r.status_code in (400, 403, 404, 501):
        raise AgentModeUnavailable(f"{r.status_code}: {r.text[:300]}")
    r.raise_for_status()
    out = Answer()
    for line in r.iter_lines(decode_unicode=True):
        if not line or not line.startswith("data:"):
            continue
        try:
            event = json.loads(line[5:])
        except json.JSONDecodeError:
            continue
        kind = event.get("type")
        if kind == "response.failed":
            out.error = json.dumps(event.get("response", {}).get("error"))[:500]
        if kind != "response.output_item.done":
            continue
        item = event.get("item") or {}
        if item.get("type") == "message":
            out.text += "".join(c.get("text", "") for c in item.get("content", [])) + "\n"
        elif item.get("type") == "function_call_output":
            out.tables.append(str(item.get("output", "")))
        elif item.get("type") == "function_call":
            try:
                out.sql.append(json.loads(item.get("arguments") or "{}").get("sql", ""))
            except json.JSONDecodeError:
                pass
    return out


def ask_chat(w: WorkspaceClient, space_id: str, question: str) -> Answer:
    msg = w.genie.start_conversation_and_wait(space_id, question)
    out = Answer(error=str(msg.error.error) if msg.error else "")
    for a in msg.attachments or []:
        if a.text and a.text.content:
            out.text += a.text.content + "\n"
        if a.query:
            out.text += (a.query.description or "") + "\n"
            out.sql.append(a.query.query or "")
            res = w.genie.get_message_attachment_query_result(space_id, msg.conversation_id, msg.id,
                                                              a.attachment_id)
            rows = (res.statement_response.result.data_array or []) if res.statement_response.result else []
            out.tables.append("\n".join(" | ".join(str(v) for v in row) for row in rows[:200]))
    return out


def missing(expect: list, haystack: str) -> list:
    text = haystack.lower()
    return [e for e in expect
            if not any(alt.lower() in text for alt in ([e] if isinstance(e, str) else e))]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--profile", required=True)
    ap.add_argument("--space-id", required=True)
    ap.add_argument("--eval", type=Path, default=EVAL)
    ap.add_argument("--mode", choices=["agent", "chat"], default="agent")
    ap.add_argument("--only", help="comma-separated 1-based question numbers")
    ap.add_argument("--strict", action="store_true", help="check the answer text only, not the result tables")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--target", type=float, default=0.9)
    ap.add_argument("--out", type=Path, help="write the answers as JSON")
    args = ap.parse_args(argv)

    items = yaml.safe_load(args.eval.read_text())["questions"]
    numbers = [int(n) for n in args.only.split(",")] if args.only else list(range(1, len(items) + 1))
    w = WorkspaceClient(profile=args.profile)
    mode = args.mode

    def ask(n: int) -> tuple[int, Answer]:
        q = items[n - 1]["question"]
        try:
            if mode == "agent":
                return n, ask_agent(w, args.space_id, q)
            return n, ask_chat(w, args.space_id, q)
        except AgentModeUnavailable:
            raise
        except Exception as e:  # one failed question must not stop the run
            return n, Answer(error=f"{type(e).__name__}: {e}")

    if mode == "agent":
        try:
            first = [ask(numbers[0])]
        except AgentModeUnavailable as e:
            print(f"Agent mode API not available ({e}); using Chat mode", file=sys.stderr)
            mode = "chat"
            first = [ask(numbers[0])]
    else:
        first = [ask(numbers[0])]
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        answers = dict(first + list(pool.map(ask, numbers[1:])))

    passed, report = 0, []
    for n in numbers:
        item, a = items[n - 1], answers[n]
        haystack = a.text if args.strict else a.text + "\n" + "\n".join(a.tables)
        miss = missing(item["expect"], haystack)
        in_text = not missing(item["expect"], a.text)
        ok = not miss and not a.error
        passed += ok
        status = "PASS" if ok else "FAIL"
        note = "" if ok and in_text else (" (rows only)" if ok else f"  missing {miss}" + (f" error {a.error}" if a.error else ""))
        print(f"{status} {n:2}. {item['question']}{note}")
        report.append({"n": n, "question": item["question"], "pass": ok, "missing": miss, "in_text": in_text,
                       "text": a.text, "sql": a.sql, "error": a.error})
    rate = passed / len(numbers)
    print(f"mode {mode}: {passed}/{len(numbers)} passed ({rate:.0%})")
    if args.out:
        args.out.write_text(json.dumps(report, indent=1))
    return 0 if rate >= args.target else 1


if __name__ == "__main__":
    sys.exit(main())
