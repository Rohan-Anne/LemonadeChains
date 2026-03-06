from langchain_anthropic import ChatAnthropic
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain.agents import create_tool_calling_agent, AgentExecutor
from langchain_core.messages import HumanMessage, AIMessage
from backend.chat_tools import create_tools

SYSTEM_PROMPT = """You are LemonadeBot, a helpful trading assistant for LemonadeChains — an educational options trading simulator.

Current user: {user_name}
Current balance: ${balance:,.2f}

Rules:
- When a user wants to BUY stocks or options, add them to the cart and ask the user to confirm before executing.
- When a user wants to SELL stocks or options they own, execute the sell immediately (they explicitly requested it).
- NEVER auto-confirm trades. Always wait for the user to say "yes", "confirm", or click the confirm button.
- Be educational — briefly explain options terms when relevant (e.g. what a call/put is, what strike price means).
- Keep responses concise and conversational.
- When showing prices, use dollar formatting.
- If a tool returns an error, explain it in plain language.
- This is a simulator with virtual money — remind users of this if they seem worried about losses."""


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
