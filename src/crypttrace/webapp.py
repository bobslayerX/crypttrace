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
from crypttrace import assets, prices, config

_WEB_DIR = Path(__file__).parent / "web"


def create_app() -> Flask:
    app = Flask(__name__, static_folder=None)

    @app.route("/")
    def index():
        return send_from_directory(_WEB_DIR, "index.html")

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
        from crypttrace import chains
        addr = request.args.get("address", "")
        chain = request.args.get("chain", "eth")
        try:
            bal = chains.balance(addr, chain)
            rows = chains.transfers(addr, chain, limit=1000)
        except (chains.ChainError, etherscan.EtherscanError) as e:
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
        try:
            asset = assets.resolve_asset(asset_arg)
            graph = trace_mod.build_graph(addr, chain, depth, branching, asset)
        except (etherscan.EtherscanError, ValueError) as e:
            return jsonify({"error": str(e)}), 400
        return jsonify(graph)

    @app.route("/api/funder")
    def api_funder():
        addr = request.args.get("address", "")
        chain = request.args.get("chain", "eth")
        try:
            hops = funder_mod.funding_chain(addr, chain, 6)
        except etherscan.EtherscanError as e:
            return jsonify({"error": str(e)}), 400
        return jsonify({"hops": hops})

    @app.route("/api/offramp")
    def api_offramp():
        addr = request.args.get("address", "")
        chain = request.args.get("chain", "eth")
        try:
            hit = offramp_mod.detect(addr, chain)
        except etherscan.EtherscanError as e:
            return jsonify({"error": str(e)}), 400
        return jsonify({"offramp": hit})

    return app


def serve(host: str = "127.0.0.1", port: int = 8000, debug: bool = False) -> None:
    create_app().run(host=host, port=port, debug=debug)
