"""An evidence pack a victim can hand to an exchange and to the police.

Built from `drain.check` on the victim's own address: what was taken, when, by
which transactions, where the money went, and — the part that gets results — the
exchange deposit and its memo, with a precise request: freeze that account and
preserve its records. Everything is a fact read from the chain with a link to
check it; nothing about the victim is invented — name, contact and signature are
left blank to fill in.

English for exchanges' compliance teams, Russian for a police report.
"""
import datetime as dt
import html
import json
from pathlib import Path
from typing import Dict, List, Optional

from crypttrace import __version__, chains, drain
from crypttrace.labels import labels

# law-enforcement request portals, only where checked against the exchange's own site
LE_PORTALS = {"KuCoin": "https://www.kucoin.com/legal/requests"}
SOURCES = {"ton": "toncenter.com (transactions), tonapi.io (account names)",
           "tron": "TronGrid", "btc": "mempool.space", "sol": "Solana JSON-RPC"}


def _utc(ts) -> str:
    return dt.datetime.fromtimestamp(int(ts or 0), dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _link_hop(src: str, dst: str, chain: str) -> Optional[dict]:
    """The largest transfer src → dst: the link between two hops of the path."""
    rows = [r for r in chains.transfers(src, chain) if r.get("from") == src and r.get("to") == dst]
    if not rows:
        return None
    r = max(rows, key=lambda r: r.get("value", 0) or 0)
    return {"from": src, "to": dst, "value": r.get("value", 0), "symbol": r.get("symbol", ""),
            "timestamp": r.get("timestamp", 0), "hash": r.get("hash", "")}


def build(address: str, chain: str) -> Dict:
    """Facts for the pack. `verdict` other than drained/suspicious means there is nothing to report."""
    res = drain.check(address, chain)
    doc = {"generated": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
           "tool": f"crypttrace {__version__}", "chain": chain, "check": res, "path": [], "deposits": []}
    if res["verdict"] == "no_drain":
        return doc
    dest = res["to"]
    for d in res.get("next", []):
        if not d.get("memo"):
            continue
        hops = []
        if d["from"] != dest:
            link = _link_hop(dest, d["from"], chain)
            if link:
                hops.append(link)
        company = labels.company(d["exchange"])
        doc["deposits"].append({**d, "company": company, "portal": LE_PORTALS.get(company),
                                "via": hops})
    return doc


# ------------------------------------------------------------------ text
T = {
    "en": {
        "title": "Theft of cryptocurrency — evidence summary",
        "victim": "Victim (to be completed)", "name": "Name", "contact": "Contact (e-mail / phone)",
        "wallet": "Wallet", "discovered": "Date the theft was discovered",
        "summary": "Summary",
        "summary_text": ("On {start}, {n} transfer(s) moved {taken} out of the wallet {victim} to {to}{to_label}, "
                         "within {mins} minute(s). The wallet was left empty."),
        "mass": ("The same receiving address collected funds from {k} other wallets within one hour of this "
                 "theft — a mass theft using leaked private keys, not an individual transaction made by the owner."),
        "resweep": ("Money that arrived in the wallet after the theft was taken as well ({n} later transfer(s)): "
                    "the attacker still holds the wallet's key."),
        "chronology": "Transfers out of the victim's wallet",
        "cols": ["Time (UTC)", "Amount", "Transaction"],
        "path": "Where the funds went",
        "deposit": ("The funds collected by the receiving address (from this and other victims) were moved on: "
                    "{amount} was deposited on {time} to the hot wallet of {company} ({hot}) with the deposit "
                    "memo {memo}. The memo identifies one customer account at {company}."),
        "via": "Path: {chain_text}",
        "requests": "Requests",
        "req_exchange": ("To {company}: please freeze the account identified by deposit memo {memo} (deposits to {hot}), "
                         "and preserve its KYC records, login IP addresses and withdrawal history. A police report "
                         "is being filed; law enforcement will request the data through your official channel."),
        "req_police": ("To the police: please request from {company} the identity, login records and withdrawal "
                       "destinations of the account behind deposit memo {memo}{portal}."),
        "portal": " — law-enforcement portal: {url}",
        "none": "No deposit with a memo was found on the path yet; the receiving address above is the lead.",
        "method": "How this was established",
        "method_text": ("Read directly from the public {chain} blockchain ({sources}) with {tool} on {generated}. "
                        "Every transaction above links to a public block explorer and can be checked by anyone. "
                        "Exchange names are explorer tags; the account behind a memo can be confirmed only by the "
                        "exchange. To reproduce: {cmd}"),
        "sign": "Signature / date", "nothing": "No drain was found for this wallet in the history read.",
    },
    "ru": {
        "title": "Хищение криптовалюты — сводка доказательств",
        "victim": "Потерпевший (заполнить)", "name": "ФИО", "contact": "Контакты (e-mail / телефон)",
        "wallet": "Кошелёк", "discovered": "Дата обнаружения хищения",
        "summary": "Кратко",
        "summary_text": ("{start} с кошелька {victim} на адрес {to}{to_label} было выполнено {n} перевод(а/ов) "
                         "за {mins} мин.: {taken}. После этого кошелёк остался пустым."),
        "mass": ("Тот же адрес-получатель в течение часа собрал средства ещё с {k} кошельков — это массовое хищение "
                 "с использованием утёкших ключей, а не перевод, сделанный владельцем."),
        "resweep": ("Средства, поступившие на кошелёк после хищения, также были выведены ({n} перевод(а/ов)): "
                    "ключ от кошелька до сих пор у злоумышленника."),
        "chronology": "Переводы с кошелька потерпевшего",
        "cols": ["Время (UTC)", "Сумма", "Транзакция"],
        "path": "Куда ушли средства",
        "deposit": ("Средства, собранные адресом-получателем (в том числе с других потерпевших), выведены "
                    "дальше: {amount} зачислено {time} на горячий кошелёк биржи {company} ({hot}) с депозитным "
                    "memo {memo}. Memo однозначно указывает на один клиентский аккаунт на {company}."),
        "via": "Путь: {chain_text}",
        "requests": "Просьбы",
        "req_exchange": ("Бирже {company}: заморозить аккаунт, определяемый депозитным memo {memo} (депозиты на {hot}), "
                         "и сохранить его данные KYC, IP-адреса входов и историю выводов. Подаётся заявление в "
                         "полицию; правоохранительные органы запросят данные через официальный канал биржи."),
        "req_police": ("Полиции: запросить у {company} данные владельца, журнал входов и адреса выводов аккаунта "
                       "с депозитным memo {memo}{portal}."),
        "portal": " — портал для правоохранительных органов: {url}",
        "none": "Депозит на биржу с memo пока не найден; зацепкой остаётся адрес-получатель, указанный выше.",
        "method": "Как это установлено",
        "method_text": ("Данные получены напрямую из публичного блокчейна {chain} ({sources}) инструментом {tool}, "
                        "{generated}. Каждая транзакция выше снабжена ссылкой на публичный обозреватель и может быть "
                        "проверена любым лицом. Названия бирж — метки обозревателей; владельца аккаунта по memo "
                        "может подтвердить только биржа. Проверка: {cmd}"),
        "sign": "Подпись / дата", "nothing": "Для этого кошелька хищение в прочитанной истории не обнаружено.",
    },
}


def _facts(doc: Dict, lang: str) -> Dict:
    t, res, chain = T[lang], doc["check"], doc["chain"]
    taken = ", ".join(f"{v:,.4f} {k}" for k, v in res.get("assets", {}).items())
    if res.get("nfts"):
        taken += f"{', ' if taken else ''}{res['nfts']} NFT"
    lab = res.get("to_label")
    paras = [t["summary_text"].format(start=_utc(res["start"]), n=res["transfers"], taken=taken or "—",
                                      victim=res["address"], to=res["to"], to_label=f" ({lab})" if lab else "",
                                      mins=max(1, (res["end"] - res["start"]) // 60))]
    if (res.get("other_wallets_same_hour") or 0) >= drain.MASS_SENDERS:
        paras.append(t["mass"].format(k=res["other_wallets_same_hour"]))
    if res.get("resweeps"):
        paras.append(t["resweep"].format(n=res["resweeps"]))
    rows = [(_utc(x["timestamp"]), f"{x['value']:,.4f} {x['symbol']}", x["hash"]) for x in res.get("drain_txs", [])]
    deps = []
    for d in doc["deposits"]:
        hops = [res["address"], res["to"]] + [h["to"] for h in d["via"]] + [d["exchange_address"]]
        deps.append({
            "text": t["deposit"].format(amount=f"{d['value']:,.4f} {d['symbol']}", time=_utc(d["last_ts"]),
                                        exchange=d["exchange"], hot=d["exchange_address"], memo=d["memo"],
                                        company=d["company"]),
            "via": t["via"].format(chain_text=" → ".join(hops)),
            "links": [h["hash"] for h in d["via"]] + [d["hash"]],
            "req_exchange": t["req_exchange"].format(company=d["company"], memo=d["memo"], hot=d["exchange_address"]),
            "req_police": t["req_police"].format(company=d["company"], memo=d["memo"],
                                                 portal=t["portal"].format(url=d["portal"]) if d.get("portal") else ""),
        })
    method = t["method_text"].format(chain=chain.upper(), sources=SOURCES.get(chain, "public node APIs"),
                                     tool=doc["tool"], generated=doc["generated"],
                                     cmd=f"crypttrace check {res['address']} --chain {chain}")
    return {"paras": paras, "rows": rows, "deps": deps, "method": method}


def render_markdown(doc: Dict, lang: str = "en") -> str:
    t, res = T[lang], doc["check"]
    if res["verdict"] == "no_drain":
        return f"# {t['title']}\n\n{t['nothing']}\n"
    f = _facts(doc, lang)
    tx = lambda h: f"[{h[:16]}…]({chains.tx_url(h, doc['chain'])})"
    L = [f"# {t['title']}\n", f"## {t['victim']}\n",
         f"- {t['name']}: ____________________\n", f"- {t['contact']}: ____________________\n",
         f"- {t['wallet']}: `{res['address']}` ({doc['chain'].upper()})\n", f"- {t['discovered']}: __________\n",
         f"\n## {t['summary']}\n"] + [p + "\n\n" for p in f["paras"]]
    L += [f"## {t['chronology']}\n", f"| {' | '.join(t['cols'])} |\n|---|---|---|\n"]
    L += [f"| {a} | {b} | {tx(h)} |\n" for a, b, h in f["rows"]]
    L += [f"\n## {t['path']}\n"]
    if f["deps"]:
        for d in f["deps"]:
            L += [d["text"] + "\n\n", d["via"] + "\n\n", " · ".join(tx(h) for h in d["links"] if h) + "\n\n"]
        L += [f"## {t['requests']}\n"] + [f"- {d['req_exchange']}\n- {d['req_police']}\n" for d in f["deps"]]
    else:
        L.append(t["none"] + "\n")
    L += [f"\n## {t['method']}\n", f["method"] + "\n", f"\n{t['sign']}: ____________________\n"]
    return "".join(L)


def render_html(doc: Dict, lang: str = "en") -> str:
    t, res, e = T[lang], doc["check"], html.escape
    head = (f"<!doctype html><html lang='{lang}'><head><meta charset='utf-8'><title>{e(t['title'])}</title>"
            "<style>body{font:15px/1.55 Georgia,'Times New Roman',serif;max-width:860px;margin:32px auto;padding:0 20px;"
            "color:#111}h1{font-size:24px}h2{font-size:18px;margin-top:28px;border-bottom:1px solid #999}"
            "table{border-collapse:collapse;width:100%}td,th{border:1px solid #bbb;padding:5px 8px;font-size:13px;"
            "text-align:left;vertical-align:top}code,.mono{font-family:Consolas,monospace;font-size:12.5px;"
            "word-break:break-all}.box{border:2px solid #111;padding:10px 14px;margin:10px 0}.blank{display:inline-block;"
            "min-width:280px;border-bottom:1px solid #111}@media print{a{color:#111}}</style></head><body>")
    if res["verdict"] == "no_drain":
        return head + f"<h1>{e(t['title'])}</h1><p>{e(t['nothing'])}</p></body></html>"
    f = _facts(doc, lang)
    a = lambda h: f"<a class='mono' href='{e(chains.tx_url(h, doc['chain']))}'>{e(h)}</a>"
    P = [head, f"<h1>{e(t['title'])}</h1>", f"<h2>{e(t['victim'])}</h2><table>"]
    for k, v in ((t["name"], ""), (t["contact"], ""), (t["wallet"], f"<span class='mono'>{e(res['address'])}</span> "
                                                                   f"({e(doc['chain'].upper())})"),
                 (t["discovered"], "")):
        P.append(f"<tr><th style='width:34%'>{e(k)}</th><td>{v or '<span class=blank>&nbsp;</span>'}</td></tr>")
    P.append("</table>")
    P.append(f"<h2>{e(t['summary'])}</h2>" + "".join(f"<p>{e(p)}</p>" for p in f["paras"]))
    P.append(f"<h2>{e(t['chronology'])}</h2><table><tr>" + "".join(f"<th>{e(c)}</th>" for c in t["cols"]) + "</tr>")
    P += [f"<tr><td>{e(x)}</td><td>{e(y)}</td><td>{a(h)}</td></tr>" for x, y, h in f["rows"]]
    P.append(f"</table><h2>{e(t['path'])}</h2>")
    if f["deps"]:
        for d in f["deps"]:
            P.append(f"<div class='box'><p><b>{e(d['text'])}</b></p><p class='mono'>{e(d['via'])}</p>"
                     + "".join(f"<div>{a(h)}</div>" for h in d["links"] if h) + "</div>")
        P.append(f"<h2>{e(t['requests'])}</h2><ol>"
                 + "".join(f"<li>{e(d['req_exchange'])}</li><li>{e(d['req_police'])}</li>" for d in f["deps"]) + "</ol>")
    else:
        P.append(f"<p>{e(t['none'])}</p>")
    P.append(f"<h2>{e(t['method'])}</h2><p>{e(f['method'])}</p>")
    P.append(f"<p style='margin-top:40px'>{e(t['sign'])}: <span class='blank'>&nbsp;</span></p></body></html>")
    return "".join(P)


def write(doc: Dict, out_dir: Path, lang: str = "en") -> List[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = f"evidence_{doc['chain']}_{doc['check']['address'][:12]}_{lang}"
    paths = [out_dir / f"{stem}.html", out_dir / f"{stem}.md", out_dir / f"{stem}.json"]
    paths[0].write_text(render_html(doc, lang), encoding="utf-8")
    paths[1].write_text(render_markdown(doc, lang), encoding="utf-8")
    paths[2].write_text(json.dumps(doc, ensure_ascii=False, indent=1, default=str), encoding="utf-8")
    return paths
