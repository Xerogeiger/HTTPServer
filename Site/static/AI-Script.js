import {renderMarkdown} from "./md/core.js";

// 3. DOM references
const sendBtn    = document.getElementById('send-btn');
const userInput  = document.getElementById('user-input');
const messagesEl = document.getElementById('messages');
const modelSelect = document.getElementById('model-select');
const clearHistoryBtn = document.getElementById('clear-history');
const newChatBtn = document.getElementById('new-chat');

// 5. Clear chat history
clearHistoryBtn.addEventListener('click', () => {
    if (!confirm("Are you sure?")) return;
    localStorage.removeItem('chatHistory');
    chatHistory = [];
    chatIndex = 0;
    chat = new Chat("");           // reset to a fresh conversation
    messagesEl.innerHTML = '';     // clear the UI
    chatHistoryDiv.innerHTML = ''; // clear the saved‐chat list
});

// 6. Start a new chat
newChatBtn.addEventListener('click', () => {
    saveChatHistory(); // snapshot current chat
    chatIndex = chatHistory.length;
    chat = new Chat(""); // reset to a fresh conversation
    messagesEl.innerHTML = ''; // clear the UI
    userInput.value = ''; // clear input
    document.title = "New Chat"; // reset title
    const titleEl = document.getElementById("chat-title");
    if (titleEl) titleEl.textContent = "New Chat"; // reset title element
});

class Chat {
    constructor(systemPrompt) {
        this.messages = [];
        this.systemPrompt = systemPrompt;
        this.chatTitle = "";
    }

    addMessage(message) {
        if (typeof message === 'string') {
            this.messages.push({ role: "user", content: message });
        } else if (message && typeof message === 'object' && message.role && message.content) {
            this.messages.push(message);
        } else {
            throw new Error("Invalid message format");
        }
    }

    getMessages() {
        // always return a fresh array
        const sys = { role: 'system', content: this.systemPrompt };
        return this.messages[0]?.role === 'system'
            ? [sys, ...this.messages.slice(1)]
            : [sys, ...this.messages];
    }
}

let chatHistory = [];
let chatIndex = 0;
let chatHistoryDiv = document.getElementById('chats');

// Change saveChatHistory to snapshot the data
function saveChatHistory() {
    const raw = {
        messages: chat.messages,
        systemPrompt: chat.systemPrompt,
        chatTitle: chat.chatTitle,
    };
    if (chatIndex < chatHistory.length) {
        // replacing an existing conversation
        chatHistory[chatIndex] = raw;
    } else if(raw.messages.length > 0) {
        // pushing a new one
        chatHistory.push(raw);
        chatIndex = chatHistory.length - 1;
    }
    localStorage.setItem('chatHistory', JSON.stringify(chatHistory));
}

// And when you load from storage:
export function loadChatHistory() {
    chatHistory = JSON.parse(localStorage.getItem('chatHistory') || '[]');
    chatHistoryDiv.innerHTML = '';
    for (let i = 0; i < chatHistory.length; i++) {
        const raw = chatHistory[i];
        const chatDiv = document.createElement('div');
        chatDiv.className = 'saved-chat';
        chatDiv.textContent = raw.chatTitle || `Chat ${i+1}`;
        chatDiv.addEventListener('click', () => loadChat(i));
        chatHistoryDiv.appendChild(chatDiv);
    }
    chatIndex = chatHistory.length;  // so sending will create a new one by default
}

export function loadChat(index) {
    if (index < 0 || index >= chatHistory.length) return;
    // snapshot current before switching
    saveChatHistory();
    // reconstruct a Chat instance
    const raw = chatHistory[index];
    const loaded = new Chat(raw.systemPrompt);
    loaded.messages = [...raw.messages];
    loaded.chatTitle = raw.chatTitle;
    chat = loaded;
    chatIndex = index;
    messagesEl.innerHTML = '';
    document.title = chat.chatTitle || "Chat";
    for (const msg of chat.messages) {
        if (msg.role !== 'system') appendMessage(msg.content, msg.role);
    }
}


window.loadChatHistory = loadChatHistory;

let chat = new Chat("");

async function nameChat() {
    const nameSystemPrompt =
        "You are a helpful assistant that generates a concise title for a chat based on its content. Don't generate anything else, just the title. Make it short and descriptive, ideally under 10 words. ";

    const history = chat.getMessages().filter(m => m.role !== "system");
    const payload = {
        model:  "llama3.1:8b",
        stream: false,
        messages: [
            { role: "system",  content: nameSystemPrompt },
            ...history
        ],
        temperature: 0.5
    };

    const res  = await fetch("http://alex-bond.com:11435/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify(payload)
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    const title = data.message?.content?.trim();
    if (title) {
        chat.chatTitle = title;
        document.title  = title;
        const titleEl   = document.getElementById("chat-title");
        if (titleEl) titleEl.textContent = title;

        // Add the chat to the history list
        const chatDiv = document.createElement('div');
        chatDiv.className = 'saved-chat';
        chatDiv.textContent = title;
        const index = chatHistory.length;
        chatDiv.addEventListener('click', () => {
            loadChat(index);
        });
        chatHistoryDiv.appendChild(chatDiv);
        chatHistory.push({
            messages: chat.messages,
            systemPrompt: chat.systemPrompt,
            chatTitle: title
        });
    }
}

async function sendAIRequest() {
    const userText = userInput.value.trim();
    if (!userText) return;

    chat.systemPrompt = `
        You are ${modelSelect.value}, a helpful assistant that answers concisely,
        and when you think to yourself use <think></think> tags around your reasoning.
        Always think before you respond with anything.
        You have the ability to write html and use markdown directly in your responses.
        `.trim();

    chat.addMessage({ role: "user", content: userText });
    appendMessage(userText, 'user');

    sendBtn.disabled = true;
    userInput.value = '';

    const payload = {
        model:    modelSelect.value,
        stream:   true,
        messages: chat.getMessages(),
        temperature: document.getElementById('temperature').valueAsNumber || 0.5,
    };

    let aiText = "";
    let aiEl = null;

    try {
        const res = await fetch('http://alex-bond.com:11435/api/chat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);

        if(!chat.chatTitle) {
            // If the chat has no title, generate one
            nameChat();
        }

        const reader = res.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";

        aiEl = appendMessage('', 'ai', true);

        while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            buffer += decoder.decode(value, { stream: true });

            const parts = buffer.split('\n');
            buffer = parts.pop();

            for (const line of parts) {
                if (!line.trim()) continue;
                let parsed;
                try { parsed = JSON.parse(line); }
                catch { continue; }

                const delta = parsed.message?.content || "";
                aiText += delta;

                let html = renderMarkdown(aiText);

                // Convert <think>…</think> into collapsibles
                html = html.replaceAll(
                    /<think>([\s\S]*?)<\/think>/gi,
                    (_, thought) =>
                        `<details class="think"><summary>Thought</summary>${thought}</details>`
                );

                aiEl.innerHTML = html;
                messagesEl.scrollTop = messagesEl.scrollHeight;
            }
        }

        chat.addMessage({ role: "assistant", content: aiText });
        saveChatHistory();
    } catch (err) {
        if (aiEl) aiEl.textContent = `⚠️ ${err.message}`;
        else appendMessage(`⚠️ ${err.message}`, 'ai');
    } finally {
        sendBtn.disabled = false;
    }
}

// 4. Send handler
sendBtn.addEventListener('click', async () => {
    await sendAIRequest();
});

userInput.addEventListener('keyup', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        sendAIRequest();
    }
});

/**
 * Append a message bubble and return its element.
 */
function appendMessage(text, sender, streaming = false) {
    const el = document.createElement('div');
    el.className = `message ${sender}`;
    if (streaming) el.innerHTML = '';
    else {
        let html = renderMarkdown(text);

        // Convert <think>…</think> into collapsibles
        html = html.replaceAll(
            /<think>([\s\S]*?)<\/think>/gi,
            (_, thought) =>
                `<details class="think"><summary>Thought</summary>${thought}</details>`
        );
        el.innerHTML = html;
    }
    messagesEl.appendChild(el);
    messagesEl.scrollTop = messagesEl.scrollHeight;
    return el;
}
