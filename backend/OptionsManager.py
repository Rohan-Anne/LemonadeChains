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
            new_expiration = None
            # Check if expiration_date is a datetime object
            if isinstance(expiration_date, datetime):
                # If the time part is 23:59:59, move to the next day
                if expiration_date.time() == datetime.strptime("23:59:59", "%H:%M:%S").time():
                    expiration_date += timedelta(days=1)  # Move to the next day

                # Convert to string in the desired format (YYYY-MM-DD)
                expiration_date = expiration_date.strftime("%Y-%m-%d")
                new_expiration = expiration_date
            else:
                # If it's already a string, attempt to parse it
                try:
                    expiration_dt = datetime.strptime(expiration_date, "%Y-%m-%d %H:%M:%S")
                    if expiration_dt.time() == datetime.strptime("23:59:59", "%H:%M:%S").time():
                        expiration_dt += timedelta(days=1)  # Move to the next day
                    expiration_date = expiration_dt.strftime("%Y-%m-%d")  # Convert to string in YYYY-MM-DD format
                    new_expiration = expiration_date
                except ValueError:
                    # If the format is already just a date, keep it as is
                    expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d").strftime("%Y-%m-%d")
                    new_expiration = expiration_date

            # Fetch the stock option chain for the expiration date
            stock = yf.Ticker(ticker)
            option_chain = stock.option_chain(new_expiration)
            
            # Select the correct option type (calls or puts)
            options = option_chain.calls if option_type == 'call' else option_chain.puts
            
            # Find the specific contract by strike price and return its implied volatility
            option_row = options[options['strike'] == strike_price]
            if option_row.empty:
                raise ValueError(f"Contract with strike price {strike_price} not found.")
            
            implied_vol = option_row['impliedVolatility'].values[0]
            
            return implied_vol

        except Exception as e:
            print(f"Error fetching implied volatility for {ticker} with strike price {strike_price} and expiration {expiration_date}: {e}")
            return None

    def calculateOptionPrice(self, ticker, strike_price, expiration_date, option_type, r):

        S = self.getStockPrice(ticker)
        K = strike_price
        T = (pd.to_datetime(expiration_date).replace(tzinfo=None) - pd.Timestamp.now().replace(tzinfo=None)).days / 365.0
        volatility = self.get_implied_volatility(ticker, expiration_date, option_type, K)
        price = self.black_scholes(S, K, T, r, volatility, option_type)
        return price



    