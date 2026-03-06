import json
import yfinance as yf
import requests
import time
from langchain_core.tools import tool
from backend.OptionsManager import OptionsManager, get_batch_prices


def _search_ticker_logic(query):
    """Search for stock/ETF tickers by name or symbol. Shared by route and chat tool."""
    query = query.strip().upper()
    if not query or len(query) < 2:
        return []

    try:
        time.sleep(0.2)
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept-Language': 'en-US,en;q=0.9',
            'Referer': 'https://finance.yahoo.com/',
        }
        response = requests.get(
            f"https://query2.finance.yahoo.com/v1/finance/search?q={query}",
            headers=headers,
            timeout=5,
        )
        if response.status_code != 200:
            return []

        search_results = response.json()
        results = []
        for result in search_results.get('quotes', []):
            if 'symbol' in result and 'shortname' in result and result.get('quoteType') in ['EQUITY', 'ETF']:
                results.append({
                    'symbol': result['symbol'],
                    'name': result['shortname'],
                    'type': result['quoteType'],
                })
            if len(results) >= 10:
                break
        return results
    except Exception:
        return []


def create_tools(session, db):
    """Return a list of LangChain tools that close over the Flask session and Firestore db."""

    @tool
    def search_ticker(query: str) -> str:
        """Search for a stock or ETF by name or ticker symbol. Returns matching symbols."""
        results = _search_ticker_logic(query)
        if not results:
            return "No matching tickers found."
        return json.dumps(results, indent=2)

    @tool
    def get_stock_price(ticker: str) -> str:
        """Get the current price for a stock ticker symbol."""
        ticker = ticker.strip().upper()
        try:
            result = get_batch_prices([ticker])
            data = result.get(ticker, {})
            price = data.get('price')
            if price is None:
                return f"Could not fetch price for {ticker}."
            return f"{ticker} is currently trading at ${price:.2f}"
        except Exception as e:
            return f"Error fetching price for {ticker}: {e}"

    @tool
    def get_options_chain(ticker: str, expiration: str = "") -> str:
        """Get the options chain for a ticker. Optionally specify an expiration date (YYYY-MM-DD). Returns near-the-money calls and puts."""
        ticker = ticker.strip().upper()
        try:
            om = OptionsManager()
            stock = yf.Ticker(ticker)
            available_exps = stock.options
            if not available_exps:
                return f"No options available for {ticker}."

            if expiration:
                if expiration not in available_exps:
                    return f"Expiration {expiration} not available. Available: {', '.join(available_exps[:10])}"
                exp = expiration
            else:
                exp = available_exps[0]

            chain = om.getChainData(ticker, exp)
            price_data = get_batch_prices([ticker])
            current_price = price_data.get(ticker, {}).get('price', 0)

            def summarize(df, n=5):
                if df.empty:
                    return []
                df = df.copy()
                df['distance'] = abs(df['strike'] - current_price)
                df = df.nsmallest(n, 'distance')
                rows = []
                for _, r in df.iterrows():
                    rows.append({
                        'contract': r.get('contractSymbol', ''),
                        'strike': float(r['strike']),
                        'lastPrice': float(r.get('lastPrice', 0)),
                        'bid': float(r.get('bid', 0)),
                        'ask': float(r.get('ask', 0)),
                        'iv': round(float(r.get('impliedVolatility', 0)) * 100, 1),
                    })
                return rows

            calls = summarize(chain.calls)
            puts = summarize(chain.puts)

            result = {
                'ticker': ticker,
                'expiration': exp,
                'currentPrice': current_price,
                'nearTheMoneyCallsTop5': calls,
                'nearTheMoneyPutsTop5': puts,
                'allExpirations': available_exps[:10],
            }
            return json.dumps(result, indent=2)
        except Exception as e:
            return f"Error fetching options chain for {ticker}: {e}"

    @tool
    def get_portfolio() -> str:
        """Get the current portfolio summary including balance, stock positions, option positions, and strategies."""
        account_data = session.get('options_account')
        if not account_data:
            return "No portfolio found. Please make sure you're logged in."

        balance = account_data.get('balance', 0)
        stocks = account_data.get('stockpositions', {})
        options = account_data.get('positions', {})
        strategies = account_data.get('strategies', {})

        lines = [f"Cash Balance: ${balance:,.2f}"]

        if stocks:
            lines.append("\nStock Positions:")
            for key, pos in stocks.items():
                lines.append(f"  {pos['ticker']}: {pos['quantity']} shares (cost basis: ${pos['cost']:,.2f})")
        else:
            lines.append("\nNo stock positions.")

        if options:
            lines.append("\nOption Positions:")
            for key, pos in options.items():
                lines.append(f"  {pos['ticker']} {pos['option_type']} strike ${pos['strike_price']} "
                             f"x{pos['quantity']} (premium: ${pos['premium']:,.2f})")
        else:
            lines.append("\nNo option positions.")

        if strategies:
            lines.append(f"\nStrategies: {len(strategies) if isinstance(strategies, (list, dict)) else 0}")

        return "\n".join(lines)

    @tool
    def add_stock_to_cart(ticker: str, action: str, quantity: int) -> str:
        """Add a stock buy or sell order to the trading cart. Action must be 'buy' or 'sell'. User must confirm trades before they execute."""
        ticker = ticker.strip().upper()
        action = action.lower()
        if action not in ('buy', 'sell'):
            return "Action must be 'buy' or 'sell'."
        if quantity <= 0:
            return "Quantity must be positive."

        price_data = get_batch_prices([ticker])
        price = price_data.get(ticker, {}).get('price')
        if price is None:
            return f"Could not fetch price for {ticker}."

        cart = session.get('cart', [])
        cart.append({
            'type': 'stock',
            'contract': ticker,
            'action': action,
            'quantity': quantity,
            'price': price,
        })
        session['cart'] = cart
        session.modified = True

        total = price * quantity
        return f"Added {quantity} shares of {ticker} ({action}) to cart at ${price:.2f}/share (total: ${total:,.2f}). Please confirm the trade to execute it."

    @tool
    def add_option_to_cart(contract: str, strike: float, option_type: str, expiration: str, action: str) -> str:
        """Add an option contract to the trading cart. option_type is 'call' or 'put'. expiration format: 'MM/DD/YYYY, HH:MM:SS AM/PM'. action is 'buy' or 'sell'."""
        action = action.lower()
        option_type = option_type.lower()
        if action not in ('buy', 'sell'):
            return "Action must be 'buy' or 'sell'."
        if option_type not in ('call', 'put'):
            return "Option type must be 'call' or 'put'."

        cart = session.get('cart', [])
        cart.append({
            'type': 'option',
            'contract': contract,
            'strike': str(strike),
            'option_type': option_type,
            'expiration': expiration,
            'action': action,
            'quantity': 1,
        })
        session['cart'] = cart
        session.modified = True

        return f"Added {option_type} option {contract} (strike ${strike}, exp {expiration}, {action}) to cart. Please confirm the trade to execute it."

    @tool
    def confirm_trades() -> str:
        """Confirm and execute all trades currently in the cart. Only call this when the user explicitly confirms."""
        from backend.OptionsAccount import OptionsAccount

        cart = session.get('cart', [])
        if not cart:
            return "Your cart is empty. Nothing to confirm."

        account_data = session.get('options_account')
        if not account_data:
            return "No account found in session."

        options_account = OptionsAccount.from_dict(account_data)
        options_account.signed_in = True

        user_id = session.get('user_id')
        if not user_id:
            return "Not authenticated."

        user_ref = db.collection('users').document(user_id)
        user_doc = user_ref.get()
        user_data = user_doc.to_dict()
        strategies = user_data.get('strategies', [])

        results = []
        for item in cart:
            if item['type'] == 'option':
                from datetime import datetime, timedelta
                expiration_date = datetime.strptime(item['expiration'], "%m/%d/%Y, %I:%M:%S %p")
                option_type = 'call' if 'C' in item['contract'] else 'put'
                quantity = int(item.get('quantity', 1))
                strike_price = float(item['strike'])
                ticker_sym = item['contract'][:-15]

                if item['action'] == 'buy':
                    success, message = options_account.buy_option(ticker_sym, expiration_date, option_type, strike_price, quantity)
                elif item['action'] == 'sell':
                    success, message = options_account.sell_option(ticker_sym, expiration_date, option_type, strike_price, quantity)
                else:
                    success, message = False, "Invalid action"
                results.append(f"{item['action']} {option_type} {ticker_sym}: {message}")

            elif item['type'] in ('stock', 'etf'):
                quantity = int(item.get('quantity', 1))
                if item['action'] == 'buy':
                    success, message = options_account.buy_stock(item['contract'], quantity)
                elif item['action'] == 'sell':
                    success, message = options_account.sell_stock(item['contract'], quantity)
                else:
                    success, message = False, "Invalid action"
                results.append(f"{item['action']} {item['contract']}: {message}")

        session['options_account'] = options_account.to_dict()
        user_ref.update({
            'balance': options_account.balance,
            'positions': options_account.positions,
            'stockpositions': options_account.stockpositions,
            'strategies': strategies,
        })
        session.pop('cart', None)
        session.modified = True

        return f"Trades executed. New balance: ${options_account.balance:,.2f}. Results: {'; '.join(results)}"

    @tool
    def sell_stock(ticker: str, quantity: int) -> str:
        """Sell shares of a stock immediately. This executes right away without needing cart confirmation."""
        from backend.OptionsAccount import OptionsAccount

        ticker = ticker.strip().upper()
        account_data = session.get('options_account')
        if not account_data:
            return "No account found."

        options_account = OptionsAccount.from_dict(account_data)
        options_account.signed_in = True

        success, message = options_account.sell_stock(ticker, quantity)
        if not success:
            return message

        session['options_account'] = options_account.to_dict()
        user_id = session.get('user_id')
        if user_id:
            user_ref = db.collection('users').document(user_id)
            user_ref.update({
                'balance': options_account.balance,
                'stockpositions': options_account.stockpositions,
            })
        session.modified = True

        return f"Sold {quantity} shares of {ticker}. New balance: ${options_account.balance:,.2f}"

    @tool
    def sell_option(ticker: str, strike: float, option_type: str, expiration: str, quantity: int = 1) -> str:
        """Sell an option position immediately. option_type is 'call' or 'put'. expiration format: 'MM/DD/YYYY, HH:MM:SS AM/PM'."""
        from backend.OptionsAccount import OptionsAccount
        from datetime import datetime

        account_data = session.get('options_account')
        if not account_data:
            return "No account found."

        options_account = OptionsAccount.from_dict(account_data)
        options_account.signed_in = True

        try:
            exp_date = datetime.strptime(expiration, "%m/%d/%Y, %I:%M:%S %p")
        except ValueError:
            return f"Invalid expiration format. Use 'MM/DD/YYYY, HH:MM:SS AM/PM'."

        success, message = options_account.sell_option(ticker.upper(), exp_date, option_type.lower(), strike, quantity)
        if not success:
            return message

        session['options_account'] = options_account.to_dict()
        user_id = session.get('user_id')
        if user_id:
            user_ref = db.collection('users').document(user_id)
            user_ref.update({
                'balance': options_account.balance,
                'positions': options_account.positions,
            })
        session.modified = True

        return f"Sold {quantity} {option_type} option(s) for {ticker.upper()} (strike ${strike}). New balance: ${options_account.balance:,.2f}"

    return [
        search_ticker,
        get_stock_price,
        get_options_chain,
        get_portfolio,
        add_stock_to_cart,
        add_option_to_cart,
        confirm_trades,
        sell_stock,
        sell_option,
    ]
