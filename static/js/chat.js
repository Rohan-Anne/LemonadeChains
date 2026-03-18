document.addEventListener('DOMContentLoaded', function () {
  var fab = document.getElementById('chat-fab');
  var drawer = document.getElementById('chat-drawer');
  var closeBtn = document.getElementById('chat-close');
  var input = document.getElementById('chat-input');
  var sendBtn = document.getElementById('chat-send');
  var messagesEl = document.getElementById('chat-messages');

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

  function formatResponse(text) {
    if (typeof text !== 'string') {
      try {
        text = JSON.stringify(text, null, 2);
      } catch (e) {
        text = String(text);
      }
    }
    return escapeHtml(text).replace(/\n/g, '<br>');
  }

  function scrollToBottom() {
    messagesEl.scrollTop = messagesEl.scrollHeight;
  }

  function addMessage(text, role) {
    var msg = document.createElement('div');
    msg.className = 'chat-message ' + role;
    msg.innerHTML = formatResponse(text);
    messagesEl.appendChild(msg);
    scrollToBottom();
    return msg;
  }

  function typeMessage(text, role, callback) {
    var formatted = formatResponse(text);
    var msg = document.createElement('div');
    msg.className = 'chat-message ' + role + ' typing-active';
    msg.innerHTML = '';
    messagesEl.appendChild(msg);
    scrollToBottom();

    var i = 0;
    var interval = setInterval(function () {
      if (i >= formatted.length) {
        clearInterval(interval);
        msg.classList.remove('typing-active');
        if (callback) callback();
        return;
      }
      // Handle HTML tags atomically — don't split <br> etc across frames
      if (formatted[i] === '<') {
        var closeIdx = formatted.indexOf('>', i);
        if (closeIdx !== -1) {
          msg.innerHTML += formatted.substring(i, closeIdx + 1);
          i = closeIdx + 1;
        } else {
          msg.innerHTML += formatted[i];
          i++;
        }
      } else if (formatted[i] === '&') {
        // Handle HTML entities like &amp; atomically
        var semiIdx = formatted.indexOf(';', i);
        if (semiIdx !== -1 && semiIdx - i < 8) {
          msg.innerHTML += formatted.substring(i, semiIdx + 1);
          i = semiIdx + 1;
        } else {
          msg.innerHTML += formatted[i];
          i++;
        }
      } else {
        msg.innerHTML += formatted[i];
        i++;
      }
      scrollToBottom();
    }, 12);
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
            var balanceMsg = data.balance
              ? ' New balance: $' + Number(data.balance).toLocaleString('en-US', {minimumFractionDigits: 2, maximumFractionDigits: 2})
              : '';
            addMessage('Trades confirmed!' + balanceMsg + ' Refreshing...', 'assistant');
            btn.textContent = 'Confirmed';
            setTimeout(function () { location.reload(); }, 800);
          } else {
            addMessage('Trade confirmation failed: ' + (data.error || 'Unknown error'), 'assistant');
            btn.disabled = false;
            btn.textContent = 'Confirm Trades';
          }
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

        if (data.error === true) {
          var errMsg = data.response || 'Something went wrong. Please try again.';
          addMessage(errMsg, 'assistant');
          sendBtn.disabled = false;
          return;
        }

        var response = data.response;
        if (typeof response !== 'string') {
          try {
            response = JSON.stringify(response, null, 2);
          } catch (e) {
            response = String(response);
          }
        }

        // If trade was confirmed via chat, show result and reload
        if (data.trade_confirmed) {
          typeMessage(response, 'assistant', function () {
            setTimeout(function () { location.reload(); }, 800);
          });
          sendBtn.disabled = false;
          return;
        }

        var hasConfirmAction = data.actions && data.actions.length > 0 &&
          data.actions.some(function (a) { return a.type === 'pending_confirmation'; });

        // Type out assistant response, then show confirm button if needed
        typeMessage(response, 'assistant', function () {
          if (hasConfirmAction) {
            addConfirmButton();
          }
        });

        // Update balance display on page if present
        if (data.balance !== undefined) {
          var balanceEls = document.querySelectorAll('.lc-stat-value, .balance-display');
          balanceEls.forEach(function (el) {
            if (el.textContent.indexOf('$') === 0) {
              el.textContent = '$' + Number(data.balance).toLocaleString('en-US', {minimumFractionDigits: 2, maximumFractionDigits: 2});
            }
          });
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
