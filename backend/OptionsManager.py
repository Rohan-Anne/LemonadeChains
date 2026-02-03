import yfinance as yf
import pandas as pd
import numpy as np
import scipy.stats as si
from datetime import datetime, timedelta

class OptionsManager:
    
    def __init__(self):
        self.ticker_data = None  # Variable to store yfinance Ticker object]
    
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
    
    def getChainData(self, ticker, date = None):
        self.ticker_data = yf.Ticker(ticker)
        chain_data = self.ticker_data.option_chain(date)
        return chain_data
    
    def getCallsData(self, ticker, date = None):
        self.ticker_data = yf.Ticker(ticker)
        call_data = self.ticker_data.option_chain(date).calls
        return call_data
    
    def getPutData(self, ticker, date = None):
        self.ticker_data = yf.Ticker(ticker)
        put_data = self.ticker_data.option_chain(date).puts
        return put_data
    
    def callPutDataToExcel(self, ticker, call_put_data):
        call_put_data.to_excel(f'OptionsData_{ticker}.xlsx', index=False)

    def getStockPrice(self, ticker):
        self.ticker_data = yf.Ticker(ticker)
        stock_price = self.ticker_data.history(period="1d")['Close'].iloc[-1]
        return stock_price
    
    def get_implied_volatility(self, ticker, expiration_date, option_type, strike_price):
        try:
            # normalize expiration_date to YYYY-MM-DD string
            if isinstance(expiration_date, datetime):
                exp = expiration_date.date().isoformat()
            else:
                exp = pd.to_datetime(expiration_date).date().isoformat()

            stock = yf.Ticker(ticker)

            # FAST FAIL: if expiration isn't available, do not call option_chain
            available = stock.options or []
            if exp not in available:
                # This is the exact error you are seeing in logs — but we won't crash now
                return None

            chain = stock.option_chain(exp)
            options = chain.calls if option_type == "call" else chain.puts

            row = options[options["strike"] == float(strike_price)]
            if row.empty:
                return None

            iv = row["impliedVolatility"].values[0]
            if iv is None or (isinstance(iv, float) and np.isnan(iv)):
                return None
            return float(iv)

        except Exception as e:
            print(f"IV fetch failed for {ticker} {expiration_date} {option_type} {strike_price}: {e}")
            return None


    def calculateOptionPrice(self, ticker, strike_price, expiration_date, option_type, r):
        S = float(self.getStockPrice(ticker))
        K = float(strike_price)

        # robust time-to-expiry using seconds, not .days floor
        now = pd.Timestamp.utcnow()
        exp = pd.to_datetime(expiration_date, utc=True, errors="coerce")
        if pd.isna(exp):
            return None
        T = (exp - now).total_seconds() / (365.0 * 24 * 3600)

        # expired options -> intrinsic value
        if T <= 0:
            return self.black_scholes(S, K, 0, r, 0.3, option_type)

        iv = self.get_implied_volatility(ticker, expiration_date, option_type, K)

        # fallback volatility to avoid crashing / timeouts
        sigma = float(iv) if iv is not None else 0.30

        return float(self.black_scholes(S, K, T, float(r), sigma, option_type))




    
