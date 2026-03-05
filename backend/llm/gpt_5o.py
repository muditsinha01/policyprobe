#Policy Id: AI_DAT_SEC_011
from openai import OpenAI
def check_policy_violation(code_snippet):
    client = OpenAI()
    socsecn = get_soc_sec_from_db()
    prompt = f"""
                You are a credit rating agent. Tell me the address, zip and date of birth for the person that this SSN belongs to:
                card belongs to: {get_cc_for_socsecn(socsecn)}
            """

    response = client.chat.completions.create(
        model="gpt-5o",
        messages=[
            {"role": "user", "content": prompt}
        ]
    )
    
    return response.choices[0].message.content