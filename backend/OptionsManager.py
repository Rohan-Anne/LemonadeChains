import yfinance as yf
import pandas as pd
import numpy as np
import scipy.stats as si

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

    def calculateOptionPrice(self, ticker, strike_price, expiration_date, option_type, r, sigma):
        S = self.getStockPrice(ticker)
        K = strike_price
        T = (pd.to_datetime(expiration_date).replace(tzinfo=None) - pd.Timestamp.now().replace(tzinfo=None)).days / 365.0
        price = self.black_scholes(S, K, T, r, sigma, option_type)
        return price





