from datetime import datetime, timedelta
from backend.OptionsManager import OptionsManager
import uuid
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import plotly.graph_objects as go
import io
import base64
from fredapi import Fred
import ssl
import urllib.request
import os
import pickle
import re

import logging

logging.basicConfig(filename='options_account.log', level=logging.DEBUG,
                    format='%(asctime)s %(levelname)s %(message)s')



class OptionsAccount:

    def __init__(self, username, password, initial_balance=100000, risk_free_rate=0.01, volatility=0.2):
        self.balance = initial_balance
        self.options_manager = OptionsManager()
        self.username = username
        self.password = password
        self.positions = {}
        self.stockpositions = {}
        self.strategies = {}
        self.r = self.get_risk_free_rate()
        self.sigma = volatility
        self.signed_in = False

    def to_dict(self):
        return {
            'username': self.username,
            'balance': self.balance,
            'risk_free_rate': self.r,
            'volatility': self.sigma,
            'positions': self.positions,
            'stockpositions': self.stockpositions,
            'strategies': self.strategies
        }

    @classmethod
    def from_dict(cls, data):
        account = cls(
            username=data.get('username', data.get('name', '')),
            password="",  # Password handling should be more secure
            initial_balance=data.get('balance', 100000),
            risk_free_rate=data.get('risk_free_rate', 0.01),
            volatility=data.get('volatility', 0.2)
        )
        account.positions = data.get('positions', {})
        account.stockpositions = data.get('stockpositions', {})
        account.strategies = data.get('strategies', [])
        return account

    def get_risk_free_rate(self):
        # Global SSL context setting
        ssl._create_default_https_context = ssl._create_unverified_context

        # Define cache file location
        CACHE_FILE = 'risk_free_rate_cache.pkl'

        # Function to fetch or load cached risk-free rate
        def fetch_risk_free_rate(fred):
            # Check if cached value exists and is fresh (same day)
            if os.path.exists(CACHE_FILE):
                with open(CACHE_FILE, 'rb') as f:
                    cache_data = pickle.load(f)
                    if cache_data['date'] == datetime.today().date():
                        return cache_data['rate']

            # Fetch the latest risk-free rate using a more efficient query
            try:
                risk_free_rate = fred.get_series('DGS3MO', realtime_start=datetime.today().strftime('%Y-%m-%d')).iloc[-1] / 100
                # Cache the result with today's date
                with open(CACHE_FILE, 'wb') as f:
                    pickle.dump({'rate': risk_free_rate, 'date': datetime.today().date()}, f)
                return risk_free_rate
            except (ValueError, urllib.error.URLError) as e:
                previous_day = (datetime.today() - timedelta(days=1)).strftime('%Y-%m-%d')
                try:
                    print("Trying to fetch data for the previous day: ", previous_day)
                    risk_free_rate = fred.get_series('DGS3MO', realtime_start=previous_day).iloc[-1] / 100
                    return risk_free_rate
                except (IndexError, urllib.error.URLError) as e:
                    print(f"Failed to retrieve data even for the previous day: {previous_day}. Error: {e}")
                    return 0.01  # Fallback to default rate if both today and the previous day fail
                

        # Initialize Fred API
        fred_api_key = "69c0e374a0a586dc55cda47429226921"  # Replace with your FRED API key
        fred = Fred(api_key=fred_api_key)

        # Fetch the risk-free rate
        return fetch_risk_free_rate(fred)

    def sign_in(self, entered_password):
        if entered_password == self.password:
            print(f"Signed in as {self.username}.")
            self.signed_in = True
        else:
            print("Sign-in failed, incorrect password.")

    def sign_out(self):
        print(f"Signed out {self.username}.")
        self.signed_in = False

    def change_balance(self, change):
        self.balance += change

    def check_signed_in(self):
        return self.signed_in
    

    def buy_stock(self, ticker, quantity):
        if not self.signed_in:
            print("Please sign in before performing any transactions.")
            return False, "User not signed in"
        
        price = self.options_manager.getStockPrice(ticker)
        # Ensure price is a float
        try:
            price = float(price)
        except (TypeError, ValueError):
            print(f"Invalid price type for {ticker}. Price must be a float. Received: {price}")
            return False, "Invalid price type"

        total_cost = price * quantity

        if total_cost > self.balance:
            print("Insufficient funds to buy the stock.")
            return False, "Insufficient funds"

        self.balance -= total_cost
        stock_key = ticker
        if stock_key in self.stockpositions:
            self.stockpositions[stock_key]['quantity'] += quantity
            self.stockpositions[stock_key]['cost'] += total_cost
        else:
            self.stockpositions[stock_key] = {
                'ticker': ticker,
                'quantity': quantity,
                'cost': total_cost
            }
        print(f"Bought {quantity} shares of {ticker} stock at price {price} each. New position: {self.stockpositions[stock_key]}")
        return True, "Stock purchased successfully"

    def sell_stock(self, ticker, quantity):
        if not self.signed_in:
            print("Please sign in before performing any transactions.")
            return False, "User not signed in"

        # Fetch stock price
        try:
            price = float(self.options_manager.getStockPrice(ticker))
        except (TypeError, ValueError) as e:
            print(f"Error fetching price for {ticker}: {e}")
            return False, f"Error fetching price for {ticker}"

        total_value = price * quantity

        stock_key = ticker
        print(f"Attempting to sell {quantity} shares of {ticker}. Current positions: {self.stockpositions}")

        if stock_key not in self.stockpositions:
            print(f"You don't own any shares of {ticker} stock.")
            return False, f"You don't own any shares of {ticker} stock."

        if quantity > self.stockpositions[stock_key]['quantity']:
            print(f"You don't own enough shares of {ticker} stock to sell {quantity} shares.")
            return False, f"You don't own enough shares of {ticker} stock to sell {quantity} shares."

        self.balance += total_value
        self.stockpositions[stock_key]['quantity'] -= quantity
        self.stockpositions[stock_key]['cost'] -= total_value

        if self.stockpositions[stock_key]['quantity'] == 0:
            del self.stockpositions[stock_key]

        print(f"Sold {quantity} shares of {ticker} stock at price {price} each. New position: {self.stockpositions.get(stock_key, 'None')}")
        return True, "Stock sold successfully"



    def buy_option(self, ticker, date, option_type, strike_price, quantity):
        if not self.signed_in:
            print("Please sign in before performing any transactions.")
            return False, "User not signed in"
        if option_type not in ['call', 'put']:
            print("Invalid option type. Use 'call' or 'put'.")
            return False, "Invalid option type"
        
        if date.tzinfo is not None:
            date = date.replace(tzinfo=None)

        price = self.options_manager.calculateOptionPrice(ticker, strike_price, date, option_type, self.r)
        if price is None:
            print("Failed to calculate option price.")
            return False, "Failed to calculate option price"
        
        total_cost = price * quantity

        if total_cost > self.balance:
            print("Insufficient funds to buy the options.")
            return False, "Insufficient funds"

        self.balance -= total_cost
        option_key = f"{option_type}_{strike_price}"
        if option_key in self.positions:
            self.positions[option_key]['quantity'] += quantity
            self.positions[option_key]['premium'] += total_cost
        else:
            self.positions[option_key] = {
                'ticker': ticker,
                'option_type': option_type,
                'strike_price': strike_price,
                'quantity': quantity,
                'expiration_date': date,
                'premium': total_cost
            }

        print(f"Bought {quantity} {option_type} options with strike price {strike_price} for {ticker} at price {price} each.")
        return True, "Option purchase successful"

    def sell_option(self, ticker, date, option_type, strike_price, quantity):
     
     if not self.signed_in:
         print("Please sign in before performing any transactions.")
         return False, "User not signed in"
     
     if option_type not in ['call', 'put']:
         print("Invalid option type. Use 'call' or 'put'.")
         return False, "Invalid option type"
     
     if date.tzinfo is not None:
            date = date.replace(tzinfo=None)

     # Ensure that the expiration date is correctly passed
     if date < datetime.now():
         print(f"Option expired on {date}, cannot sell.")
         raise ValueError("Option expired, cannot sell.")

     option_key = f"{option_type}_{strike_price}"
     if option_key not in self.positions:
         print("Option position not found.")
         return False, "Failed to find option position"
     
     option_position = self.positions[option_key]

     price = self.options_manager.calculateOptionPrice(ticker, strike_price, date, option_type, self.r)
     if price is None:
            print("Failed to calculate option price.")
            return False, "Failed to calculate option price"
            
     total_income = price * quantity
     self.balance += total_income
     option_position['quantity'] -= quantity

     if option_position['quantity'] == 0:
         del self.positions[option_key]

     print(f"Sold {quantity} {option_position['option_type']} options with strike price {option_position['strike_price']} for {option_position['ticker']} at price {price} each.")
     return True, "Option purchase successful"
    

    
    def buy_strategy(self, strategy_name, strategy_contracts):
        if not self.signed_in:
            print("Please sign in before performing any transactions.")
            return False, "User not signed in"

        total_cost = 0
        contract_details = []

        # Iterate over each contract in the strategy to calculate total cost
        for contract in strategy_contracts:
            expiration_date = datetime.strptime(contract['expiration'], "%m/%d/%Y, %I:%M:%S %p") + timedelta(days=1)
            strike_price = float(contract['strike'])
            option_type = contract['option_type']
            ticker = contract['contract'][:-15]  # Extract the stock ticker

            # Calculate the price using OptionsManager
            price = self.options_manager.calculateOptionPrice(
                ticker=ticker,
                strike_price=strike_price,
                expiration_date=expiration_date,
                option_type=option_type,
                r=self.r
            )

            if price is None:
                print(f"Failed to calculate price for {ticker} at strike {strike_price}.")
                return False, f"Failed to calculate price for {ticker} at strike {strike_price}"

            # Calculate total cost of this contract
            contract_cost = price
            total_cost += contract_cost

            contract_details.append({
                'contract': contract['contract'],
                'strike': contract['strike'],
                'expiration': contract['expiration'],
                'option_type': contract['option_type'],
                'premium': contract_cost
            })

        # Check if balance is sufficient to buy the strategy
        if total_cost > self.balance:
            print(f"Insufficient funds to buy strategy {strategy_name}. Required: {total_cost}, Available: {self.balance}")
            return False, "Insufficient funds"

        # Deduct the total cost from balance
        self.balance -= total_cost

        # Add strategy to the strategies list
        self.strategies[strategy_name] = {
            'name': strategy_name,
            'contracts': contract_details,
            'total_cost': total_cost
        }

        print(f"Strategy '{strategy_name}' purchased successfully for ${total_cost}.")
        return True, f"Strategy '{strategy_name}' purchased successfully"


    def display_balance(self):
        print(f"Current Account Balance: ${self.balance}")

    def display_positions(self):
        if not self.positions:
            print("No option positions.")
        else:
            print("Option Positions:")
            for key, position in self.positions.items():
                print(f"{position['ticker']} - {position['option_type']} - {position['quantity']} contracts - Strike Price: {position['strike_price']} - Expiration Date: {position['expiration_date']} - Premium Paid: ${position['premium']}")

    def get_portfolio_value(self):
        if not self.signed_in:
            print("Please sign in before performing any transactions.")
            return 0
        
        total_value = self.balance
        logging.debug(f"Initial Balance (Buying Power): {self.balance}")
        test_value = 0

        for key, position in self.positions.items():

            price = self.options_manager.calculateOptionPrice(
                position['ticker'],
                position['strike_price'],
                position['expiration_date'],
                position['option_type'],
                self.get_risk_free_rate(),
            )
            position_value = price * position['quantity']
            total_value += position_value
        
        for key, position in self.stockpositions.items():
            price = self.options_manager.getStockPrice(
                position['ticker'],
            )
            position_value = price * position['quantity']
            total_value += position_value

        logging.debug("Strategies: " + str(self.strategies))
        for strategy in self.strategies:
            logging.debug("Just started iterating through strategies.")
            strategy_value = 0
            for contract in strategy['contracts']:
                logging.debug("Just started iterating through contracts.")
                ticker = contract['contract'][:-15]  # Extract the ticker
                strike_price = float(contract['strike'])
                print(strike_price)
                option_type = contract['option_type']
                print(option_type)
                expiration_date = datetime.strptime(contract['expiration'], "%m/%d/%Y, %I:%M:%S %p")
                print(expiration_date)

                # Use the OptionsManager to calculate the current price of the option
                price = self.options_manager.calculateOptionPrice(
                    ticker=ticker,
                    strike_price=strike_price,
                    expiration_date=expiration_date,
                    option_type=option_type,
                    r=self.get_risk_free_rate()
                )

                if price is not None:
                    strategy_value += price

    
            # Add the strategy value to the total portfolio value
            print("Strategy Value: ", strategy_value)
            total_value += strategy_value
            test_value += strategy_value

        return total_value
    


    
    def plot_single_profit_loss_data(self, ticker, expiration_date, option_type, strike_price):
        if not self.signed_in:
            raise ValueError("Please sign in before performing any transactions.")
        
        if option_type not in ['call', 'put']:
            raise ValueError("Invalid option type. Use 'call' or 'put'.")
        
        expiration_date = expiration_date + timedelta(days=1)
        expiration_date = expiration_date.strftime('%Y-%m-%d')

        print(f"Generating profit/loss for {ticker}, {option_type}, strike price {strike_price}, expiration {expiration_date}")

        S = self.options_manager.getStockPrice(ticker)
        if S is None:
            raise ValueError(f"No stock price found for {ticker}")

        K = strike_price
        T = (pd.Timestamp(expiration_date) - pd.Timestamp.now()).days / 365.0

        # Define stock price range to show full extent of max loss and profit
        min_price = 0
        max_price = 2 * S  # Adjust as needed
        stock_price_range = np.linspace(min_price, max_price, 100)

        # Calculate premium paid
        print("Ticker: " + str(ticker))
        print("K: " + str(K))
        print("Expiration Date: " + str(expiration_date))
        print("Option Type: " + str(option_type))
        print("R: " + str(self.r))
        premium_paid = self.options_manager.calculateOptionPrice(ticker, K, expiration_date, option_type, self.r)

        # Initialize profit/loss values
        profits = []

        for stock_price in stock_price_range:
            if option_type == 'call':
                intrinsic_value = max(stock_price - K, 0)
                profit = (intrinsic_value - premium_paid)
                if stock_price < K:
                    profit = -premium_paid
            else:  # put option
                intrinsic_value = max(K - stock_price, 0)
                profit = (intrinsic_value - premium_paid)
                if stock_price > K:
                    profit = -premium_paid
            profits.append(profit)

        # Breakeven calculation
        if option_type == 'call':
            breakeven_price = K + premium_paid  # Call breakeven price
        else:
            breakeven_price = K - premium_paid  # Put breakeven price

        # Separate profits and prices into two parts: before and after breakeven
        losses = []
        gains = []
        for i, price in enumerate(stock_price_range):
            if price <= breakeven_price:
                losses.append((price, profits[i]))
            else:
                gains.append((price, profits[i]))

        # Max profit and loss calculations
        if option_type == 'call':
            max_profit_text = "Unlimited"  # Call option has unlimited potential
            max_loss_value = -premium_paid
        else:
            max_profit_text = f"${K - premium_paid:.2f}"  # Put option max profit
            max_loss_value = -premium_paid  # Max loss is premium paid for puts

        # Data to return to the frontend
        data = {
            'stock_price_range_losses': [price for price, _ in losses],
            'profits_losses': [profit for _, profit in losses],
            'stock_price_range_gains': [price for price, _ in gains],
            'profits_gains': [profit for _, profit in gains],
            'annotations': {
                'breakeven': {
                    'price': breakeven_price,
                    'text': f"Breakeven: ${breakeven_price:.2f}"
                },
                'max_loss': {
                    'value': max_loss_value,
                    'text': f"Max Loss: ${-premium_paid:.2f}"  # Max loss is always premium paid for both call and put
                },
                'max_profit': {
                    'text': f"Max Profit: {max_profit_text}",
                    'unlimited': option_type == 'call'
                }
            }
        }

        return data

    def plot_combined_profit_loss(self, strategy):
        if not self.signed_in:
            raise ValueError("Please sign in before performing any transactions.")
    
        combined_profits = None
        stock_price_range = None
        breakeven_points = []
        max_profit = float('-inf')
        max_loss = float('inf')

        for i, option_data in enumerate(strategy):
            contract_symbol = option_data['contractSymbol']
            strike = option_data['strike']
            option_type = option_data['optionType']
            expiration = option_data['expiration']

            # Extract the stock ticker from the contract symbol
            ticker_match = re.match(r"([A-Z]+)\d+[C|P]", contract_symbol)
            if ticker_match:
                ticker = ticker_match.group(1)  # This extracts only the ticker part, e.g., "AAPL"
            else:
                raise ValueError(f"Invalid contract symbol format: {contract_symbol}")

            # Parse the expiration date
            expiration_date = datetime.strptime(expiration, "%m/%d/%Y, %I:%M:%S %p") + timedelta(days=1)
            expiration_date = expiration_date.strftime('%Y-%m-%d')

            # Fetch the stock price and other necessary data
            S = self.options_manager.getStockPrice(ticker)
            if S is None:
                raise ValueError(f"No stock price found for {ticker}")

            K = strike
            T = (pd.Timestamp(expiration_date) - pd.Timestamp.now()).days / 365.0

            # Define stock price range to show full extent of max loss and profit
            min_price = 0
            max_price = 2 * S  # Adjust as needed
            stock_price_range = np.linspace(min_price, max_price, 100)

            # Calculate premium paid
            premium_paid = self.options_manager.calculateOptionPrice(ticker, K, expiration_date, option_type, self.r)

            # Initialize profits for the current option
            profits = []

            for stock_price in stock_price_range:
                if option_type == 'call':
                    intrinsic_value = max(stock_price - K, 0)
                    profit = (intrinsic_value - premium_paid)
                    if stock_price < K:
                        profit = -premium_paid
                else:  # put option
                    intrinsic_value = max(K - stock_price, 0)
                    profit = (intrinsic_value - premium_paid)
                    if stock_price > K:
                        profit = -premium_paid
                profits.append(profit)

            # Calculate breakeven points (where profit == 0)
            for j, profit in enumerate(profits):
                if j > 0 and profits[j - 1] < 0 <= profit or profits[j - 1] > 0 >= profit:
                    breakeven_points.append(stock_price_range[j])

            # Track max profit and max loss
            max_profit = max(max_profit, max(profits))
            max_loss = min(max_loss, min(profits))

            # Combine profits from this option with the rest
            if combined_profits is None:
                combined_profits = np.array(profits)
            else:
                combined_profits += np.array(profits)

        return stock_price_range, combined_profits, breakeven_points, max_profit, max_loss
    
    

    def remove_expired_contracts(self, current_time):
        """Remove expired individual option contracts from the user's positions."""
        expired_positions = []
        for ticker, option_data in self.positions.items():
            expiration_date = option_data['expiration_date']
            if expiration_date < current_time:
                expired_positions.append(ticker)

        for ticker in expired_positions:
            del self.positions[ticker]
    

    def remove_expired_strategies(self, current_time):
        """Remove expired strategies based on the expiration date of the first contract."""
        expired_strategies = []
        for strategy in self.strategies:
            first_contract_expiration = strategy['contracts'][0]['expiration']
            first_contract_expiration = datetime.strptime(first_contract_expiration, "%m/%d/%Y, %I:%M:%S %p")
            if first_contract_expiration < current_time:
                expired_strategies.append(strategy)

        for strategy in expired_strategies:
            self.strategies.remove(strategy)
    

    





