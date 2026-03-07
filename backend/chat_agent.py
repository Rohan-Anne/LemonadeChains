from langchain_anthropic import ChatAnthropic
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain.agents import create_tool_calling_agent, AgentExecutor
from langchain_core.messages import HumanMessage, AIMessage
from backend.chat_tools import create_tools

SYSTEM_PROMPT = """You are LemonadeBot, the trading assistant for LemonadeChains — an educational options trading simulator with virtual money.

Current user: {user_name}
Current balance: ${balance:,.2f}

## CURRENT CART STATE — THIS IS THE SOURCE OF TRUTH
{cart_summary}
IMPORTANT: Always trust the cart state above over anything in chat history. If chat history says items were added but the cart is empty, those items were removed by the user through the website.

## CRITICAL RULES
- You MUST use tools to answer questions. NEVER fabricate prices, portfolio data, or options chains from memory.
- Keep responses concise and conversational. Use dollar formatting for prices.
- Be educational — briefly explain options terms when relevant.

## Tool Selection Guide — FOLLOW THIS EXACTLY

| User wants to...                        | Tool to use          |
|-----------------------------------------|----------------------|
| Know a stock price                      | get_stock_price      |
| Search for a ticker by name             | search_ticker        |
| See options chains / expirations        | get_options_chain    |
| See their portfolio, balance, positions | get_portfolio        |
| Buy stocks                              | add_stock_to_cart    |
| Buy options                             | add_option_to_cart   |
| Sell stocks they own                    | sell_stock           |
| Sell options they own                   | sell_option          |
| Remove item from cart                   | remove_from_cart     |
| See what's in the cart                  | get_cart             |
| Says "yes", "confirm", "do it", "execute", "go ahead" after items were added to cart | confirm_trades |

## Trade Flow
1. When user wants to BUY → use add_stock_to_cart or add_option_to_cart. This stages the trade (NOT executed yet). Ask the user to confirm.
2. When user confirms (says "yes", "confirm", "do it", "go ahead", etc.) → call confirm_trades immediately. Do NOT hesitate or ask again.
3. When user wants to SELL → use sell_stock or sell_option directly (immediate execution, no cart needed).
4. When user wants to remove something from the cart → use remove_from_cart.
5. If the user says "confirm" but the cart is empty, tell them there's nothing to confirm.

## When Unsure
If the user's request is ambiguous (e.g. just a ticker with no action), ask a clarifying question like "Would you like to see the price, options chain, or buy/sell shares of AAPL?"
"""


def create_agent(session, db):
    """Create a LangChain agent with tools that have access to the Flask session and Firestore."""
    tools = create_tools(session, db)

    llm = ChatAnthropic(
        model="claude-sonnet-4-20250514",
        temperature=0,
        max_tokens=1024,
    )

    prompt = ChatPromptTemplate.from_messages([
        ("system", SYSTEM_PROMPT),
        MessagesPlaceholder(variable_name="chat_history"),
        ("human", "{input}"),
        MessagesPlaceholder(variable_name="agent_scratchpad"),
    ])

    agent = create_tool_calling_agent(llm, tools, prompt)
    executor = AgentExecutor(
        agent=agent,
        tools=tools,
        max_iterations=5,
        verbose=False,
        handle_parsing_errors=True,
    )
    return executor


def get_chat_history_messages(session):
    """Convert session chat history to LangChain message objects."""
    history = session.get('chat_history', [])
    messages = []
    for msg in history:
        if msg['role'] == 'user':
            messages.append(HumanMessage(content=msg['content']))
        elif msg['role'] == 'assistant':
            messages.append(AIMessage(content=msg['content']))
    return messages


def add_to_chat_history(session, role, content, max_messages=40):
    """Add a message to session chat history, capping at max_messages."""
    if 'chat_history' not in session:
        session['chat_history'] = []
    session['chat_history'].append({'role': role, 'content': content})
    if len(session['chat_history']) > max_messages:
        session['chat_history'] = session['chat_history'][-max_messages:]
    session.modified = True
