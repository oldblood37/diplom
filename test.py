import requests
import json

url = "http://34d9-178-76-218-138.ngrok-free.app/telegram-webhook/"
data = {
    "message": {
        "chat": {
            "id": "637378059"  # Замените на ваш chat_id
        },
        "text": "/start"  # Замените на ваш текст сообщения
    }
}

headers = {'Content-type': 'application/json'}

response = requests.post(url, data=json.dumps(data), headers=headers)

print(response.text)