import yfinance as yf
import pandas as pd
import numpy as np
import scipy.stats as si
from datetime import datetime, timedelta
import time as _time

# Module-level caches (per-process, safe for gunicorn workers)
_ticker_cache = {}      # symbol -> yf.Ticker
_price_cache = {}       # symbol -> (price, timestamp)
_history_cache = {}     # symbol -> (history_list, timestamp)
_chain_cache = {}       # (symbol, date) -> (chain, timestamp)
_iv_cache = {}          # (symbol, exp, type, strike) -> (iv, timestamp)

_PRICE_TTL = 30         # seconds
_CHAIN_TTL = 120        # seconds
_IV_TTL = 120           # seconds


def _get_ticker(symbol):
    """Return a cached yf.Ticker object."""
    if symbol not in _ticker_cache:
        _ticker_cache[symbol] = yf.Ticker(symbol)
    return _ticker_cache[symbol]


def _is_fresh(timestamp, ttl):
    return (_time.time() - timestamp) < ttl


def get_batch_prices(tickers):
    """Fetch prices for multiple tickers, using cache where possible.
    Returns dict of {ticker: {price, prices}}."""
    results = {}
    uncached = []

    for t in tickers:
        if t in _price_cache and _is_fresh(_price_cache[t][1], _PRICE_TTL):
            price = _price_cache[t][0]
            history = _history_cache.get(t, ([], 0))[0]
            results[t] = {'price': round(price, 2), 'prices': [round(p, 2) for p in history]}
        else:
            uncached.append(t)

    for t in uncached:
        try:
            stock = _get_ticker(t)
            hist = stock.history(period="5d")['Close']
            current_price = float(hist.iloc[-1])
            history_list = hist.tolist()
            now = _time.time()
            _price_cache[t] = (current_price, now)
            _history_cache[t] = (history_list, now)
            results[t] = {'price': round(current_price, 2), 'prices': [round(p, 2) for p in history_list]}
        except Exception as e:
            print(f"get_batch_prices error for {t}: {e}")
            results[t] = {'price': None, 'prices': []}

    return results


class OptionsManager:

    def __init__(self):
        self.ticker_data = None

    def black_scholes(self, S, K, T, r, sigma, option_type='call'):
        if T <= 0:
            if option_type == 'call':
                return max(0, S - K)
            else:
                return max(0, K - S)

        d1 = (np.log(S / K) + (r + 0.5 * sigma ** 2) * T) / (sigma * np.sqrt(T))
        d2 = d1 - sigma * np.sqrt(T)

        if option_type == 'call':
            price = (S * si.norm.cdf(d1, 0.0, 1.0) - K * np.exp(-r * T) * si.norm.cdf(d2, 0.0, 1.0))
        else:
            price = (K * np.exp(-r * T) * si.norm.cdf(-d2, 0.0, 1.0) - S * si.norm.cdf(-d1, 0.0, 1.0))

        return price

    def getChainData(self, ticker, date=None):
        self.ticker_data = _get_ticker(ticker)
        cache_key = (ticker, date)
        if cache_key in _chain_cache and _is_fresh(_chain_cache[cache_key][1], _CHAIN_TTL):
            return _chain_cache[cache_key][0]
        chain_data = self.ticker_data.option_chain(date)
        _chain_cache[cache_key] = (chain_data, _time.time())
        return chain_data

    def getCallsData(self, ticker, date=None):
        return self.getChainData(ticker, date).calls

    def getPutData(self, ticker, date=None):
        return self.getChainData(ticker, date).puts

    def callPutDataToExcel(self, ticker, call_put_data):
        call_put_data.to_excel(f'OptionsData_{ticker}.xlsx', index=False)

    def getStockPrice(self, ticker):
        if ticker in _price_cache and _is_fresh(_price_cache[ticker][1], _PRICE_TTL):
            return _price_cache[ticker][0]
        self.ticker_data = _get_ticker(ticker)
        hist = self.ticker_data.history(period="1d")['Close']
        stock_price = float(hist.iloc[-1])
        _price_cache[ticker] = (stock_price, _time.time())
        return stock_price

    def get_implied_volatility(self, ticker, expiration_date, option_type, strike_price):
        try:
            if isinstance(expiration_date, datetime):
                exp = expiration_date.date().isoformat()
            else:
                exp = pd.to_datetime(expiration_date).date().isoformat()

            iv_key = (ticker, exp, option_type, float(strike_price))
            if iv_key in _iv_cache and _is_fresh(_iv_cache[iv_key][1], _IV_TTL):
                return _iv_cache[iv_key][0]

            stock = _get_ticker(ticker)

            available = stock.options or []
            if exp not in available:
                return None

            cache_key = (ticker, exp)
            if cache_key in _chain_cache and _is_fresh(_chain_cache[cache_key][1], _CHAIN_TTL):
                chain = _chain_cache[cache_key][0]
            else:
                chain = stock.option_chain(exp)
                _chain_cache[cache_key] = (chain, _time.time())

            options = chain.calls if option_type == "call" else chain.puts

            row = options[options["strike"] == float(strike_price)]
            if row.empty:
                return None

            iv = row["impliedVolatility"].values[0]
            if iv is None or (isinstance(iv, float) and np.isnan(iv)):
                _iv_cache[iv_key] = (None, _time.time())
                return None
            iv = float(iv)
            _iv_cache[iv_key] = (iv, _time.time())
            return iv

        except Exception as e:
            print(f"IV fetch failed for {ticker} {expiration_date} {option_type} {strike_price}: {e}")
            return None


    def calculateOptionPrice(self, ticker, strike_price, expiration_date, option_type, r):
        S = float(self.getStockPrice(ticker))
        K = float(strike_price)

        now = pd.Timestamp.utcnow()
        exp = pd.to_datetime(expiration_date, utc=True, errors="coerce")
        if pd.isna(exp):
            return None
        T = (exp - now).total_seconds() / (365.0 * 24 * 3600)

        if T <= 0:
            return self.black_scholes(S, K, 0, r, 0.3, option_type)

        iv = self.get_implied_volatility(ticker, expiration_date, option_type, K)

        sigma = float(iv) if iv is not None else 0.30

        return float(self.black_scholes(S, K, T, float(r), sigma, option_type))
