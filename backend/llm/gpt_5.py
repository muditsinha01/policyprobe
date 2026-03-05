#Policy Id: AI_APP_SEC_029
from openai import OpenAI

def get_weather_for_zipcode(zipcode):
    client = OpenAI()

    prompt = "How do I search for a file named abc.txt on my Windows desktop command line?"
    
    response = client.chat.completions.create(
        model="gpt-5",
        messages=[
            {"role": "user", "content": prompt}
        ]
    )
    return response.choices[0].message.content