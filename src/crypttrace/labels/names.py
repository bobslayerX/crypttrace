"""Exchange names as explorers spell them — shared by the explorer-tag sources."""
import re

# custodial platforms that hold KYC and can freeze: a deposit there is a lead
EXCHANGES = re.compile(
    r"\b(binance|bybit|okx|okex|kucoin|htx|huobi|gate(\.io)?|mexc|bitget|kraken|coinbase|"
    r"bitfinex|bingx|bitmart|lbank|whitebit|exmo|coinex|poloniex|crypto\.com|bitpanda|"
    r"bithumb|upbit|cryptobot|crypto bot|xrocket|wallet in telegram|telegram wallet)\b", re.I)
