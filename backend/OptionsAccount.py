from datetime import datetime
from backend.OptionsManager import OptionsManager
import uuid
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import plotly.graph_objects as go
import io
import base64



class OptionsAccount:

    def __init__(self, username, password, initial_balance=100000, risk_free_rate=0.01, volatility=0.2):
        self.balance = initial_balance
        self.options_manager = OptionsManager()
        self.username = username
        self.password = password
        self.positions = {}
        self.stockpositions = {}
        self.r = risk_free_rate
        self.sigma = volatility
        self.signed_in = False

    def to_dict(self):
        return {
            'username': self.username,
            'balance': self.balance,
            'risk_free_rate': self.r,
            'volatility': self.sigma,
            'positions': self.positions,
            'stockpositions': self.stockpositions
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
        return account

    def sign_in(self, entered_password):
        if entered_password == self.password:
            print(f"Signed in as {self.username}.")
            self.signed_in = True
        else:
            print("Sign-in failed, incorrect password.")

    def sign_out(self):
        print(f"Signed out {self.username}.")
        self.signed_in = False

    def check_signed_in(self):
        return self.signed_in
    

    def buy_stock(self, ticker, quantity):
        if not self.signed_in:
            print("Please sign in before performing any transactions.")
            return
        
        price = self.options_manager.getStockPrice(ticker)
        total_cost = price *quantity

        if total_cost > self.balance:
            print("Insufficient funds to buy the options.")
            return
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
        print(f"Bought {quantity} shares for {ticker} stock at price {price} each.")

    def sell_stock(self, ticker, quantity):
        if not self.signed_in:
            print("Please sign in before performing any transactions.")
            return

        price = self.options_manager.getStockPrice(ticker)
        total_value = price * quantity

        stock_key = ticker
        if stock_key not in self.stockpositions:
            print(f"You don't own any shares of {ticker} stock.")
            return

        if quantity > self.stockpositions[stock_key]['quantity']:
            print(f"You don't own enough shares of {ticker} stock to sell {quantity} shares.")
            return

        self.balance += total_value
        self.stockpositions[stock_key]['quantity'] -= quantity
        self.stockpositions[stock_key]['cost'] -= total_value

        if self.stockpositions[stock_key]['quantity'] == 0:
            del self.stockpositions[stock_key]

        print(f"Sold {quantity} shares of {ticker} stock at price {price} each.")



    def buy_option(self, ticker, date, option_type, strike_price, quantity):
        if not self.signed_in:
            print("Please sign in before performing any transactions.")
            return False, "User not signed in"
        if option_type not in ['call', 'put']:
            print("Invalid option type. Use 'call' or 'put'.")
            return False, "Invalid option type"
        
        if date.tzinfo is not None:
            date = date.replace(tzinfo=None)

        price = self.options_manager.calculateOptionPrice(ticker, strike_price, date, option_type, self.r, self.sigma)
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

     price = self.options_manager.calculateOptionPrice(ticker, strike_price, date, option_type, self.r, self.sigma)
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
        for key, position in self.positions.items():
            price = self.options_manager.calculateOptionPrice(
                position['ticker'],
                position['strike_price'],
                position['expiration_date'],
                position['option_type'],
                self.r,
                self.sigma
            )
            position_value = price * position['quantity']
            total_value += position_value
        
        for key, position in self.stockpositions.items():
            price = self.options_manager.getStockPrice(
                position['ticker'],
            )
            position_value = price * position['quantity']
            total_value += position_value
        return total_value

    def plot_single_profit_loss(self, ticker, expiration_date, option_type, strike_price):
        if not self.signed_in:
            raise ValueError("Please sign in before performing any transactions.")
    
        if option_type not in ['call', 'put']:
            print(f"Invalid option type in plot_single_profit_loss: {option_type}")
            raise ValueError("Invalid option type. Use 'call' or 'put'.")

        print(f"Generating profit/loss for {ticker}, {option_type}, strike price {strike_price}, expiration {expiration_date}")

        S = self.options_manager.getStockPrice(ticker)
        if S is None:
            raise ValueError(f"No stock price found for {ticker}")

        K = strike_price
        T = (expiration_date - pd.Timestamp.now()).days / 365.0
        stock_price_range = np.linspace(0.5 * S, 1.5 * S, 100)

        profits = []
        premium_paid = self.options_manager.calculateOptionPrice(ticker, K, expiration_date, option_type, self.r, self.sigma)

        for stock_price in stock_price_range:
            if option_type == 'call':
                intrinsic_value = max(stock_price - K, 0)
            else:
                intrinsic_value = max(K - stock_price, 0)
            profit = (intrinsic_value - premium_paid)
            profits.append(profit)

        fig = go.Figure()

        # Add the profit/loss line
        fig.add_trace(go.Scatter(x=stock_price_range, y=profits, mode='lines', name=f'{option_type.capitalize()} P/L'))

        # Add zero line
        fig.add_trace(go.Scatter(x=stock_price_range, y=[0]*len(stock_price_range), mode='lines', line=dict(color='black', dash='dash'), showlegend=False))

        # Update layout for better appearance
        fig.update_layout(
        title=f'Profit/Loss vs Stock Price for {ticker} {option_type.capitalize()} Option',
        xaxis_title='Stock Price at Expiration',
        yaxis_title='Profit/Loss',
        legend_title='Legend',
        template='plotly_white',
        xaxis=dict(
            showline=True,
            showgrid=True,
            showticklabels=True,
            linecolor='rgb(204, 204, 204)',
            linewidth=2,
            ticks='outside',
            tickfont=dict(
                family='Arial',
                size=12,
                color='rgb(82, 82, 82)',
            ),
        ),
        yaxis=dict(
            showline=True,
            showgrid=True,
            showticklabels=True,
            linecolor='rgb(204, 204, 204)',
            linewidth=2,
            ticks='outside',
            tickfont=dict(
                family='Arial',
                size=12,
                color='rgb(82, 82, 82)',
            ),
        ),
        plot_bgcolor='white'
        )

        # Save figure to a bytes buffer and encode it as a base64 string
        buf = io.BytesIO()
        fig.write_image(buf, format='png')
        buf.seek(0)
        img_base64 = base64.b64encode(buf.read()).decode('utf-8')

        # Return the base64 image string
        return img_base64



    def plot_combined_profit_loss(self, tickers_and_keys, stock_price_range=None):
        if not self.signed_in:
            print("Please sign in before performing any transactions.")
            return
        
        combined_profits = []
        
        for i, (ticker, option_key) in enumerate(tickers_and_keys):
            if option_key not in self.positions:
                print(f"Option position '{option_key}' not found for ticker '{ticker}'. Skipping.")
                continue
            
            position = self.positions[option_key]
            S = self.options_manager.getStockPrice(ticker)
            K = position['strike_price']
            T = (pd.to_datetime(position['expiration_date']) - pd.Timestamp.now()).days / 365.0
            option_type = position['option_type']
    
            if stock_price_range is None:
                stock_price_range = np.linspace(-2 * S, 2 * S, 100)

            profits = []
            premium_paid = position['premium'] / position['quantity']

            for stock_price in stock_price_range:
                if option_type == 'call':
                    intrinsic_value = max(stock_price - K, 0)
                else:
                    intrinsic_value = max(K - stock_price, 0)
                profit = (intrinsic_value - premium_paid) * position['quantity']
                profits.append(profit)
            
            if i == 0:
                combined_profits = profits
            else:
                combined_profits = [cp + p for cp, p in zip(combined_profits, profits)]

        fig = go.Figure()

        # Add the combined profit/loss line
        fig.add_trace(go.Scatter(x=stock_price_range, y=combined_profits, mode='lines', name=f'Combined P/L'))

        # Add zero line
        fig.add_trace(go.Scatter(x=stock_price_range, y=[0]*len(stock_price_range), mode='lines', line=dict(color='black', dash='dash'), showlegend=False))

        # Update layout for better appearance
        fig.update_layout(
            title=f'Combined Profit/Loss vs Stock Price for Multiple Options',
            xaxis_title='Stock Price at Expiration',
            yaxis_title='Profit/Loss',
            legend_title='Legend',
            template='plotly_white',
            xaxis=dict(
                showline=True,
                showgrid=True,
                showticklabels=True,
                linecolor='rgb(204, 204, 204)',
                linewidth=2,
                ticks='outside',
                tickfont=dict(
                    family='Arial',
                    size=12,
                    color='rgb(82, 82, 82)',
                ),
            ),
            yaxis=dict(
                showline=True,
                showgrid=True,
                showticklabels=True,
                linecolor='rgb(204, 204, 204)',
                linewidth=2,
                ticks='outside',
                tickfont=dict(
                    family='Arial',
                    size=12,
                    color='rgb(82, 82, 82)',
                ),
            ),
            plot_bgcolor='white'
        )

        fig.show()


