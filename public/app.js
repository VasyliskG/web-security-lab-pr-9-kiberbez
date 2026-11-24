'use strict';

let csrfToken;

const form = document.querySelector('#feedback-form');
const nameInput = document.querySelector('#name');
const messageInput = document.querySelector('#message');
const status = document.querySelector('#status');
const messagesList = document.querySelector('#messages');

function showStatus(text, isError = false) {
  status.textContent = text;
  status.className = isError ? 'error' : 'success';
}

function renderMessages(messages) {
  messagesList.replaceChildren();
  for (const item of messages) {
    const listItem = document.createElement('li');
    const author = document.createElement('strong');
    author.textContent = item.name;
    const text = document.createElement('p');
    text.textContent = item.message;
    listItem.append(author, text);
    messagesList.append(listItem);
  }
}

async function loadMessages() {
  const response = await fetch('/api/messages');
  if (!response.ok) throw new Error('Не вдалося завантажити відгуки');
  const data = await response.json();
  renderMessages(data.messages);
}

async function initialize() {
  try {
    const sessionResponse = await fetch('/api/session');
    if (!sessionResponse.ok) throw new Error('Не вдалося створити сесію');
    ({ csrfToken } = await sessionResponse.json());
    await loadMessages();
  } catch (error) {
    showStatus(error.message, true);
  }
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  showStatus('');

  try {
    const response = await fetch('/api/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken,
      },
      body: JSON.stringify({
        name: nameInput.value,
        message: messageInput.value,
      }),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Не вдалося додати відгук');
    form.reset();
    showStatus('Відгук додано.');
    await loadMessages();
  } catch (error) {
    showStatus(error.message, true);
  }
});

initialize();
