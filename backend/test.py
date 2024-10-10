import yfinance as yf
from datetime import datetime

def get_implied_volatility(ticker, expiration_date, option_type, strike_price):
    """
    Fetches the implied volatility for a given options contract based on ticker, expiration date, option type, and strike price.
    
    Parameters:
    - ticker (str): The stock ticker (e.g., 'AAPL').
    - expiration_date (str): The expiration date in 'YYYY-MM-DD' format.
    - option_type (str): The option type, either 'call' or 'put'.
    - strike_price (float): The strike price of the option.
    
    Returns:
    - implied_volatility (float): Implied volatility as a percentage.
    """
    try:
        # Fetch the stock option chain for the expiration date
        stock = yf.Ticker(ticker)
        option_chain = stock.option_chain(expiration_date)
        
        # Select the correct option type (calls or puts)
        options = option_chain.calls if option_type == 'call' else option_chain.puts
        
        # Find the specific contract by strike price and return its implied volatility
        option_row = options[options['strike'] == strike_price]
        if option_row.empty:
            raise ValueError(f"Contract with strike price {strike_price} not found.")
        
        implied_vol = option_row['impliedVolatility'].values[0]
        
        # Return the implied volatility as a percentage
        return implied_vol
    
    except Exception as e:
        print(f"Error fetching implied volatility for {ticker} with strike price {strike_price} and expiration {expiration_date}: {e}")
        return None

# Example Usage
ticker = 'AAPL'
expiration_date = '2024-10-11'  # Expiration date in 'YYYY-MM-DD'
option_type = 'call'  # 'call' or 'put'
strike_price = 100  # Strike price

implied_volatility = get_implied_volatility(ticker, expiration_date, option_type, strike_price)
print(implied_volatility)


