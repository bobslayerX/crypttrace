"""Local web UI for crypttrace.

A small Flask app that wraps the same modules the CLI uses and serves a
single-page frontend (an interactive fund-flow graph + address profile). Runs
entirely on the user's machine — no data leaves except the Etherscan/CoinGecko
calls the CLI already makes.

Launch with:  crypttrace serve   (then open http://127.0.0.1:8000)
"""
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory

from crypttrace.fetchers import etherscan
from crypttrace.labels import labels
from crypttrace import trace as trace_mod, funder as funder_mod, offramp as offramp_mod
from crypttrace import assets, prices, config, chains

_WEB_DIR = Path(__file__).parent / "web"

# Errors that mean "bad input / upstream said no", not "the app crashed".
_KNOWN_ERRORS = (chains.ChainError, etherscan.EtherscanError, ValueError)


def validate(address: str, chain: str):
    """Return a helpful message if the address obviously doesn't fit the chain."""
    a = (address or "").strip()
    if not a:
        return "Enter an address."
    if len(a) == 64 and all(c in "0123456789abcdefABCDEF" for c in a):
        return ("That looks like a transaction ID, not an address. "
                "Paste the wallet address instead.")
    if chains.is_evm(chain):
        if not (a.startswith("0x") and len(a) == 42):
            return f"'{a[:14]}…' is not an {chain} address (expected 0x…, 42 chars)."
    elif chain == "btc":
        if not (a.startswith(("1", "3", "bc1", "tb1")) and 25 <= len(a) <= 62):
            return f"'{a[:14]}…' is not a Bitcoin address (expected 1…, 3… or bc1…)."
    elif chain == "tron":
        if not (a.startswith("T") and len(a) == 34):
            return f"'{a[:14]}…' is not a Tron address (expected T…, 34 chars)."
    return None


def create_app() -> Flask:
    app = Flask(__name__, static_folder=None)

    # Always answer the API in JSON — an HTML error page would break the frontend.
    @app.errorhandler(Exception)
    def _json_errors(e):
        code = getattr(e, "code", 500)
        return jsonify({"error": getattr(e, "description", None) or str(e)}), code

    @app.route("/")
    def index():
        return send_from_directory(_WEB_DIR, "index.html")

    @app.route("/api/assets")
    def api_assets():
        """Which assets can be traced on a given chain (drives the UI dropdown)."""
        chain = request.args.get("chain", "eth")
        native = chains.symbol(chain)
        opts = [{"value": "native", "label": f"{native} (native)"}]
        for sym, meta in assets.tokens_for(chain).items():
            opts.append({"value": sym, "label": meta["symbol"]})
        return jsonify({"chain": chain, "assets": opts,
                        "tokens_supported": chain != "btc"})

    @app.route("/api/label")
    def api_label():
        addr = request.args.get("address", "")
        hit = labels.lookup(addr)
        return jsonify({
            "address": addr,
            "label": hit["name"] if hit else None,
            "type": labels.type_of(addr),
            "risk": labels.risk_score(addr),
        })

    @app.route("/api/profile")
    def api_profile():
        addr = request.args.get("address", "")
        chain = request.args.get("chain", "eth")
        bad = validate(addr, chain)
        if bad:
            return jsonify({"error": bad}), 400
        try:
            bal = chains.balance(addr, chain)
            rows = chains.transfers(addr, chain, limit=1000)
        except _KNOWN_ERRORS as e:
            return jsonify({"error": str(e)}), 400
        price = prices.native_price(chain)
        hit = labels.lookup(addr)
        return jsonify({
            "address": addr, "chain": chain,
            "balance": round(bal, 8),
            "balance_usd": prices.usd(bal, price),
            "symbol": chains.symbol(chain),
            "txs": len(rows),
            "first_seen": rows[-1]["timestamp"] if rows else None,
            "last_seen": rows[0]["timestamp"] if rows else None,
            "label": hit["name"] if hit else None,
            "type": labels.type_of(addr),
            "risk": labels.risk_score(addr),
            "explorer": chains.explorer_url(addr, chain),
        })

    @app.route("/api/trace")
    def api_trace():
        addr = request.args.get("address", "")
        chain = request.args.get("chain", "eth")
        depth = int(request.args.get("depth", 3))
        branching = int(request.args.get("branching", 3))
        asset_arg = request.args.get("asset", "eth")
        direction = request.args.get("direction", "out")
        if direction not in ("out", "in"):
            direction = "out"
        bad = validate(addr, chain)
        if bad:
            return jsonify({"error": bad}), 400
        try:
            asset = assets.resolve_asset(asset_arg, chain)
            graph = trace_mod.build_graph(addr, chain, depth, branching, asset, direction)
        except _KNOWN_ERRORS as e:
            return jsonify({"error": str(e)}), 400
        return jsonify(graph)

    @app.route("/api/funder")
    def api_funder():
        addr = request.args.get("address", "")
        chain = request.args.get("chain", "eth")
        if validate(addr, chain):
            return jsonify({"hops": []})
        try:
            hops = funder_mod.funding_chain(addr, chain, 6)
        except _KNOWN_ERRORS as e:
            return jsonify({"error": str(e)}), 400
        return jsonify({"hops": hops})

    @app.route("/api/offramp")
    def api_offramp():
        addr = request.args.get("address", "")
        chain = request.args.get("chain", "eth")
        # off-ramp heuristic relies on exchange labels, which are EVM-only today
        if not chains.is_evm(chain) or validate(addr, chain):
            return jsonify({"offramp": None})
        try:
            hit = offramp_mod.detect(addr, chain)
        except _KNOWN_ERRORS as e:
            return jsonify({"error": str(e)}), 400
        return jsonify({"offramp": hit})

    return app


def serve(host: str = "127.0.0.1", port: int = 8000, debug: bool = False) -> None:
    create_app().run(host=host, port=port, debug=debug)
