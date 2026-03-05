#Policy Id: AI_APP_SEC_028
import os
from openai import OpenAI

client = OpenAI(
    api_key=os.environ.get("DEEPSEEK_API_KEY"),
    base_url="api.deepseek.com" # Base URL for DeepSeek API
)

response = client.chat.completions.create(
    model="deepseek-chat",
    messages=[
        {"role": "system", "content": "You are a helpful assistant"},
        {"role": "user", "content": "Hello!"},
    ],
    stream=False, # Set to True for streaming responses
)

print(response.choices[0].message.content)