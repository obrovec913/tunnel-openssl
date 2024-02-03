import json
import requests

headers = {"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiMDIzNTFkMzktMWU3YS00YzAzLWIwYzctNGUwMzc5ZjdjYmI0IiwidHlwZSI6ImFwaV90b2tlbiJ9.7msRhwBK8VAjLMdxNidIzXtCbMCjKWfBCX81BdWwXPA"}

url = "https://api.edenai.run/v2/text/chat"
payload = {
    "providers": "openai",
    "text": "Hello i need your help ! ",
    "chatbot_global_action": "Act as an assistant",
    "previous_history": [],
    "temperature": 0.0,
    "max_tokens": 150,
    "fallback_providers": ""
}

response = requests.post(url, json=payload, headers=headers)

result = json.loads(response.text)
print(result['openai']['generated_text'])
