document.addEventListener('DOMContentLoaded', function () {
  const fab = document.getElementById('chat-fab');
  const drawer = document.getElementById('chat-drawer');
  const closeBtn = document.getElementById('chat-close');
  const input = document.getElementById('chat-input');
  const sendBtn = document.getElementById('chat-send');
  const messagesEl = document.getElementById('chat-messages');

  if (!fab || !drawer) return;

  fab.addEventListener('click', function () {
    drawer.classList.add('open');
    fab.classList.add('hidden');
    input.focus();
  });

  closeBtn.addEventListener('click', function () {
    drawer.classList.remove('open');
    fab.classList.remove('hidden');
  });

  function escapeHtml(text) {
    var div = document.createElement('div');
    div.appendChild(document.createTextNode(text));
    return div.innerHTML;
  }

  function scrollToBottom() {
    messagesEl.scrollTop = messagesEl.scrollHeight;
  }

  function addMessage(text, role) {
    var msg = document.createElement('div');
    msg.className = 'chat-message ' + role;
    msg.innerHTML = escapeHtml(text);
    messagesEl.appendChild(msg);
    scrollToBottom();
  }

  function addConfirmButton() {
    var wrapper = document.createElement('div');
    wrapper.className = 'chat-message assistant';
    var btn = document.createElement('button');
    btn.className = 'chat-confirm-btn';
    btn.textContent = 'Confirm Trades';
    btn.addEventListener('click', function () {
      btn.disabled = true;
      btn.textContent = 'Confirming...';
      fetch('/confirm_trades', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      })
        .then(function (res) { return res.json(); })
        .then(function (data) {
          if (data.success) {
            addMessage('Trades confirmed and executed successfully!', 'assistant');
          } else {
            addMessage('Trade confirmation failed: ' + (data.error || 'Unknown error'), 'assistant');
          }
          btn.textContent = 'Confirmed';
        })
        .catch(function () {
          addMessage('Error confirming trades. Please try again.', 'assistant');
          btn.disabled = false;
          btn.textContent = 'Confirm Trades';
        });
    });
    wrapper.appendChild(btn);
    messagesEl.appendChild(wrapper);
    scrollToBottom();
  }

  function showTyping() {
    var typing = document.createElement('div');
    typing.className = 'chat-typing';
    typing.id = 'chat-typing-indicator';
    typing.innerHTML = '<div class="dot"></div><div class="dot"></div><div class="dot"></div>';
    messagesEl.appendChild(typing);
    scrollToBottom();
  }

  function hideTyping() {
    var el = document.getElementById('chat-typing-indicator');
    if (el) el.remove();
  }

  function sendMessage() {
    var text = input.value.trim();
    if (!text) return;

    addMessage(text, 'user');
    input.value = '';
    sendBtn.disabled = true;
    showTyping();

    fetch('/api/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: text }),
    })
      .then(function (res) {
        if (res.status === 401) {
          hideTyping();
          addMessage('Your session has expired. Please log in again.', 'assistant');
          sendBtn.disabled = false;
          return null;
        }
        return res.json();
      })
      .then(function (data) {
        hideTyping();
        if (!data) return;
        addMessage(data.response, 'assistant');
        if (data.actions) {
          for (var i = 0; i < data.actions.length; i++) {
            if (data.actions[i].type === 'pending_confirmation') {
              addConfirmButton();
            }
          }
        }
        sendBtn.disabled = false;
      })
      .catch(function () {
        hideTyping();
        addMessage('Something went wrong. Please try again.', 'assistant');
        sendBtn.disabled = false;
      });
  }

  sendBtn.addEventListener('click', sendMessage);
  input.addEventListener('keydown', function (e) {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  });
});
