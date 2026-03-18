import json
import yfinance as yf
import requests
import time
from datetime import datetime
from typing import Literal, Optional
from langchain_core.tools import tool
from pydantic import BaseModel, Field
from backend.OptionsManager import OptionsManager, get_batch_prices


class StrategyLeg(BaseModel):
    contract: str = Field(description="Option contract symbol from get_options_chain")
    strike: float = Field(description="Strike price")
    expiration: str = Field(description="Expiration date in YYYY-MM-DD format")
    option_type: Literal["call", "put"] = Field(description="Option type")
    action: Literal["buy", "sell"] = Field(description="Buy (long) or sell (short) this leg")


class AddStrategyInput(BaseModel):
    strategy_name: str = Field(description="Descriptive name, e.g. 'AAPL Bull Call Spread'")
    contracts: list[StrategyLeg] = Field(description="List of option legs in the strategy")


def _normalize_expiration(expiration: str) -> Optional[str]:
    """Convert expiration to the internal format 'MM/DD/YYYY, 04:00:00 PM'.

    Accepts YYYY-MM-DD (preferred, from get_options_chain) or the legacy
    MM/DD/YYYY, HH:MM:SS AM/PM format. Returns None if unparseable.
    """
    expiration = expiration.strip()
    # Try YYYY-MM-DD first (returned by get_options_chain / yfinance)
    try:
        dt = datetime.strptime(expiration, "%Y-%m-%d")
        return dt.strftime("%m/%d/%Y, 04:00:00 PM")
    except ValueError:
        pass
    # Accept legacy format as-is
    try:
        datetime.strptime(expiration, "%m/%d/%Y, %I:%M:%S %p")
        return expiration
    except ValueError:
        return None


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
    def get_options_chain(ticker: str, expiration: str = "", num_strikes: int = 5) -> str:
        """Get the options chain for a ticker. Optionally specify an expiration date (YYYY-MM-DD) and num_strikes (1-20, default 5). Returns near-the-money calls and puts with contract symbols, strikes, and prices. Use more strikes (10-15) when building multi-leg strategies."""
        ticker = ticker.strip().upper()
        num_strikes = max(1, min(20, num_strikes))
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

            calls = summarize(chain.calls, num_strikes)
            puts = summarize(chain.puts, num_strikes)

            result = {
                'ticker': ticker,
                'expiration': exp,
                'currentPrice': current_price,
                'calls': calls,
                'puts': puts,
                'allExpirations': available_exps[:10],
            }
            return json.dumps(result, indent=2)
        except Exception as e:
            return f"Error fetching options chain for {ticker}: {e}"

    @tool
    def get_portfolio() -> str:
        """Get the user's full portfolio: cash balance, stock positions (with quantities and cost basis), option positions, and strategies. Use this when the user asks about their balance, holdings, positions, P&L, what they own, or portfolio value."""
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
            lines.append(f"\nStrategies ({len(strategies)}):")
            strat_items = strategies.values() if isinstance(strategies, dict) else strategies
            for strat in strat_items:
                name = strat.get('name', 'Unnamed')
                legs = strat.get('contracts', [])
                total_cost = strat.get('total_cost', 0)
                leg_descs = [f"{'short' if l.get('action', 'buy') == 'sell' else 'long'} {l.get('option_type', '?')} ${l.get('strike_price', l.get('strike', '?'))}" for l in legs]
                lines.append(f"  {name}: {', '.join(leg_descs)} (cost: ${total_cost:,.2f})")

        return "\n".join(lines)

    @tool
    def add_stock_to_cart(ticker: str, action: str, quantity: int) -> str:
        """Stage a stock trade in the cart. Action must be 'buy' or 'sell'. The trade is NOT executed until the user confirms — after calling this, ask the user to confirm."""
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
    def add_option_to_cart(contract: str, strike: float, option_type: str, expiration: str, action: str, quantity: int = 1) -> str:
        """Stage an option trade in the cart. option_type is 'call' or 'put'. expiration format: YYYY-MM-DD (as returned by get_options_chain). action is 'buy' or 'sell'. quantity defaults to 1. The trade is NOT executed until confirmed — after calling this, ask the user to confirm."""
        action = action.lower()
        option_type = option_type.lower()
        if action not in ('buy', 'sell'):
            return "Action must be 'buy' or 'sell'."
        if option_type not in ('call', 'put'):
            return "Option type must be 'call' or 'put'."
        if quantity <= 0:
            return "Quantity must be positive."

        exp_internal = _normalize_expiration(expiration)
        if exp_internal is None:
            return f"Invalid expiration format: '{expiration}'. Use YYYY-MM-DD."

        cart = session.get('cart', [])
        cart.append({
            'type': 'option',
            'contract': contract,
            'strike': str(strike),
            'option_type': option_type,
            'expiration': exp_internal,
            'action': action,
            'quantity': quantity,
        })
        session['cart'] = cart
        session.modified = True

        return f"Added {quantity}x {option_type} option {contract} (strike ${strike}, exp {expiration}, {action}) to cart. Please confirm the trade to execute it."

    @tool(args_schema=AddStrategyInput)
    def add_strategy_to_cart(strategy_name: str, contracts: list[StrategyLeg]) -> str:
        """Stage a multi-leg options strategy in the cart. Each leg specifies action='buy' or 'sell'. The trade is NOT executed until confirmed."""
        if not strategy_name or not strategy_name.strip():
            return "Strategy name is required."
        if not contracts or len(contracts) < 2:
            return "A strategy requires at least 2 contracts."

        normalized = []
        for i, c in enumerate(contracts):
            exp_internal = _normalize_expiration(str(c.expiration))
            if exp_internal is None:
                return f"Contract {i+1} has invalid expiration: '{c.expiration}'. Use YYYY-MM-DD."
            normalized.append({
                'contract': c.contract,
                'strike': str(c.strike),
                'option_type': c.option_type,
                'expiration': exp_internal,
                'action': c.action,
            })

        cart = session.get('cart', [])
        cart.append({
            'type': 'strategy',
            'name': strategy_name.strip(),
            'contracts': normalized,
        })
        session['cart'] = cart
        session.modified = True

        legs_desc = ", ".join(f"{c['action']} {c['option_type']} ${c['strike']}" for c in normalized)
        return f"Added strategy '{strategy_name}' ({len(normalized)} legs: {legs_desc}) to cart. Please confirm to execute."

    @tool
    def get_cart() -> str:
        """Get the current contents of the trading cart. Use this to check what's staged before confirming."""
        cart = session.get('cart', [])
        if not cart:
            return "Your cart is empty."
        lines = ["Current cart:"]
        for item in cart:
            if item['type'] == 'strategy':
                lines.append(f"  - Strategy '{item['name']}' ({len(item.get('contracts', []))} contracts)")
            else:
                lines.append(f"  - {item['action']} {item.get('quantity', 1)} {item['type']} {item['contract']}")
        return "\n".join(lines)

    @tool
    def remove_from_cart(contract: str, action: str = "") -> str:
        """Remove an item from the cart by contract/ticker name. For strategies, pass the strategy name. For stocks/options, pass the contract symbol. Optionally pass action ('buy'/'sell') to disambiguate."""
        cart = session.get('cart', [])
        if not cart:
            return "Your cart is empty. Nothing to remove."

        contract_upper = contract.strip().upper()
        original_len = len(cart)

        # Try matching as strategy name first
        new_cart = [item for item in cart if not (
            item.get('type') == 'strategy' and item.get('name', '').upper() == contract_upper
        )]

        # If nothing was removed, try matching by contract
        if len(new_cart) == original_len:
            if action:
                new_cart = [item for item in cart if not (
                    item.get('contract', '').upper() == contract_upper and item.get('action', '').lower() == action.lower()
                )]
            else:
                new_cart = [item for item in cart if item.get('contract', '').upper() != contract_upper]

        removed_count = original_len - len(new_cart)
        if removed_count == 0:
            return f"Could not find '{contract}' in your cart."

        session['cart'] = new_cart
        session.modified = True
        remaining = len(new_cart)
        return f"Removed '{contract}' from cart. {remaining} item(s) remaining."

    @tool
    def confirm_trades() -> str:
        """Execute all trades currently staged in the cart. Call this IMMEDIATELY when the user says "yes", "confirm", "do it", "execute", "go ahead", or otherwise agrees to proceed with pending cart items. Do NOT ask for confirmation again."""
        from app import _execute_cart_trades

        cart = session.get('cart', [])
        if not cart:
            return "Your cart is empty. Nothing to confirm."

        success, balance, results, error = _execute_cart_trades(session, db)
        if not success:
            return f"Trade failed: {error}"

        return f"Trades executed. New balance: ${balance:,.2f}. Results: {'; '.join(results)}"

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
        """Sell an option position immediately. option_type is 'call' or 'put'. expiration format: YYYY-MM-DD (as returned by get_options_chain)."""
        from backend.OptionsAccount import OptionsAccount

        account_data = session.get('options_account')
        if not account_data:
            return "No account found."

        options_account = OptionsAccount.from_dict(account_data)
        options_account.signed_in = True

        exp_internal = _normalize_expiration(expiration)
        if exp_internal is None:
            return f"Invalid expiration format: '{expiration}'. Use YYYY-MM-DD."
        exp_date = datetime.strptime(exp_internal, "%m/%d/%Y, %I:%M:%S %p")

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
        add_strategy_to_cart,
        get_cart,
        remove_from_cart,
        confirm_trades,
        sell_stock,
        sell_option,
    ]
