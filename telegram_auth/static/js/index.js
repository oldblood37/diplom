const express = require('express');
const axios = require('axios');
const bodyParser = require('body-parser');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const TELEGRAM_API = 'https://api.telegram.org/bot';
const TELEGRAM_TOKEN = '6794656536:AAHRrqdax_iANoWmeAeMbX6C_YomWgWxsDw';
const WEBHOOK_URL = 'https://51f6-178-76-218-138.ngrok-free.app/telegram-webhook';

axios.post(`${TELEGRAM_API}${TELEGRAM_TOKEN}/setWebhook`, { url: WEBHOOK_URL })
    .then(response => {
        console.log('Webhook set successfully:', response.data);
    })
    .catch(error => {
        console.error('Error setting webhook:', error);
    });

let authCodes = new Map();

function sendMessage(chatId, text) {
    axios.post(`${TELEGRAM_API}${TELEGRAM_TOKEN}/sendMessage`, {
        chat_id: chatId,
        text: text
    })
    .then(response => {
        console.log('Message posted');
    })
    .catch(error => {
        console.log(error);
    });
}

function generateAuthCode() {
    return Math.random().toString(36).substring(2, 9);
}

app.post('/telegram-webhook', (req, res) => {
    const chatId = req.body.message.chat.id;
    const receivedText = req.body.message.text;

    if (receivedText === '/start') {
        let authCode = '';
        for (let [code, id] of authCodes.entries()) {
            if (id === chatId) {
                authCode = code;
                break;
            }
        }
        if (authCode === '') {
            authCode = generateAuthCode();
            authCodes.set(authCode, chatId);
        }
        sendMessage(chatId, `Ваш код авторизации: ${authCode}`);
        console.log(`Отправленный код для chatId ${chatId}: ${authCode}`); // Логирование отправленного кода
    }

    res.sendStatus(200);
});

app.post('/check-code', (req, res) => {
    const userCode = req.body.code;
    console.log(`Проверяемый код: ${userCode}`); // Логирование проверяемого кода
    const chatId = authCodes.get(userCode);

    if (chatId) {
        res.json({ success: true, message: "Код верный. Авторизация успешна.", userId: chatId });
        authCodes.delete(userCode);
    } else {
        res.json({ success: false, message: "Неверный код авторизации." });
    }
});

const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
