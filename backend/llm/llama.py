import torch
import json
import re
from flask import Flask, request, jsonify
from transformers import (
    AutoTokenizer,
    AutoModelForCausalLM,
    AutoModelForSequenceClassification,
    pipeline,
    StoppingCriteriaList,
    MaxLengthCriteria,
)

app = Flask(__name__)

MODEL_NAME = "meta-llama/Llama-3-8b-instruct"
CLASSIFIER_NAME = "distilbert-base-uncased-finetuned-sst-2-english"

tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
model = AutoModelForCausalLM.from_pretrained(MODEL_NAME, torch_dtype=torch.float16)
model.eval()

classifier_tokenizer = AutoTokenizer.from_pretrained(CLASSIFIER_NAME)
classifier_model = AutoModelForSequenceClassification.from_pretrained(CLASSIFIER_NAME)
classifier_model.eval()

sentiment_pipeline = pipeline("sentiment-analysis", model=CLASSIFIER_NAME)


# ---------------------------------------------------------------------------
# Violation 1: Raw user prompt tokenized and fed to model.generate() with no
# validation or sanitization of the input string.
# ---------------------------------------------------------------------------
@app.route("/api/chat", methods=["POST"])
def chat():
    user_prompt = request.json.get("prompt", "")

    input_ids = tokenizer.encode(user_prompt, return_tensors="pt")
    attention_mask = torch.ones_like(input_ids)

    with torch.no_grad():
        output_ids = model.generate(
            input_ids,
            attention_mask=attention_mask,
            max_new_tokens=512,
            temperature=0.7,
            do_sample=True,
        )

    response_text = tokenizer.decode(output_ids[0], skip_special_tokens=True)
    return jsonify({"response": response_text})


# ---------------------------------------------------------------------------
# Violation 2: System prompt built from raw user input via f-string, then
# tokenized and passed to model.generate() without sanitization.
# ---------------------------------------------------------------------------
@app.route("/api/instruct", methods=["POST"])
def instruct():
    data = request.json
    system_msg = data.get("system", "You are a helpful assistant.")
    user_msg = data.get("message", "")

    prompt = f"<|system|>\n{system_msg}\n<|user|>\n{user_msg}\n<|assistant|>\n"

    input_ids = tokenizer(prompt, return_tensors="pt")["input_ids"]

    with torch.no_grad():
        output_ids = model.generate(input_ids, max_new_tokens=1024, do_sample=False)

    decoded = tokenizer.decode(output_ids[0], skip_special_tokens=True)
    return jsonify({"response": decoded})


# ---------------------------------------------------------------------------
# Violation 3: Batch of user texts fed directly to the sentiment classifier
# tokenizer and model without any input validation.
# ---------------------------------------------------------------------------
@app.route("/api/classify", methods=["POST"])
def classify():
    texts = request.json.get("texts", [])

    inputs = classifier_tokenizer(
        texts, padding=True, truncation=True, return_tensors="pt"
    )

    with torch.no_grad():
        logits = classifier_model(**inputs).logits

    predictions = torch.argmax(logits, dim=-1).tolist()
    labels = [classifier_model.config.id2label[p] for p in predictions]
    return jsonify({"labels": labels})


# ---------------------------------------------------------------------------
# Violation 4: Raw user text passed directly into a HuggingFace pipeline
# with no sanitization.
# ---------------------------------------------------------------------------
@app.route("/api/sentiment", methods=["POST"])
def sentiment():
    text = request.json.get("text", "")

    result = sentiment_pipeline(text)
    return jsonify({"sentiment": result})


# ---------------------------------------------------------------------------
# Violation 5: User-controlled conversation history deserialized from JSON and
# concatenated into a prompt string without any validation, then tokenized and
# passed to model.generate().
# ---------------------------------------------------------------------------
@app.route("/api/multi-turn", methods=["POST"])
def multi_turn():
    conversation = request.json.get("conversation", [])

    prompt_parts = []
    for turn in conversation:
        role = turn.get("role", "user")
        content = turn.get("content", "")
        prompt_parts.append(f"<|{role}|>\n{content}")
    prompt_parts.append("<|assistant|>\n")

    full_prompt = "\n".join(prompt_parts)

    input_ids = tokenizer(full_prompt, return_tensors="pt")["input_ids"]

    with torch.no_grad():
        output_ids = model.generate(
            input_ids,
            max_new_tokens=512,
            temperature=0.9,
            top_p=0.95,
            do_sample=True,
        )

    decoded = tokenizer.decode(output_ids[0], skip_special_tokens=True)
    return jsonify({"response": decoded})


# ---------------------------------------------------------------------------
# Violation 6: User-supplied text embedded into a Jinja-style template and
# tokenized without sanitization before model inference.
# ---------------------------------------------------------------------------
@app.route("/api/summarize", methods=["POST"])
def summarize():
    document = request.json.get("document", "")
    style = request.json.get("style", "concise")

    prompt = (
        f"Summarize the following document in a {style} manner.\n\n"
        f"Document:\n{document}\n\n"
        f"Summary:\n"
    )

    input_ids = tokenizer.encode(prompt, return_tensors="pt")

    with torch.no_grad():
        output_ids = model.generate(
            input_ids,
            max_new_tokens=256,
            repetition_penalty=1.2,
        )

    summary = tokenizer.decode(output_ids[0], skip_special_tokens=True)
    return jsonify({"summary": summary})


# ---------------------------------------------------------------------------
# Violation 7: File upload contents read and passed directly to the tokenizer
# and model without any validation or sanitization.
# ---------------------------------------------------------------------------
@app.route("/api/analyze-file", methods=["POST"])
def analyze_file():
    uploaded = request.files.get("file")
    if not uploaded:
        return jsonify({"error": "No file uploaded"}), 400

    raw_content = uploaded.read().decode("utf-8", errors="ignore")

    prompt = f"Analyze the following file content and describe what it does:\n\n{raw_content}\n\nAnalysis:"

    input_ids = tokenizer(prompt, return_tensors="pt", truncation=True, max_length=4096)[
        "input_ids"
    ]

    with torch.no_grad():
        output_ids = model.generate(input_ids, max_new_tokens=512)

    analysis = tokenizer.decode(output_ids[0], skip_special_tokens=True)
    return jsonify({"analysis": analysis})


# ---------------------------------------------------------------------------
# Violation 8: User-supplied token IDs accepted directly and passed to
# model.generate() — bypasses the tokenizer entirely, allowing crafted
# adversarial token sequences.
# ---------------------------------------------------------------------------
@app.route("/api/generate-from-tokens", methods=["POST"])
def generate_from_tokens():
    token_ids = request.json.get("token_ids", [])

    input_ids = torch.tensor([token_ids], dtype=torch.long)

    with torch.no_grad():
        output_ids = model.generate(input_ids, max_new_tokens=256, do_sample=True)

    decoded = tokenizer.decode(output_ids[0], skip_special_tokens=True)
    return jsonify({"response": decoded})


# ---------------------------------------------------------------------------
# Violation 9: User-controlled generation parameters (temperature, top_k,
# max_new_tokens) passed directly to model.generate() without validation,
# and the prompt itself is also unsanitized.
# ---------------------------------------------------------------------------
@app.route("/api/generate-custom", methods=["POST"])
def generate_custom():
    data = request.json
    prompt = data.get("prompt", "")
    temperature = data.get("temperature", 1.0)
    top_k = data.get("top_k", 50)
    max_tokens = data.get("max_tokens", 512)

    input_ids = tokenizer.encode(prompt, return_tensors="pt")

    with torch.no_grad():
        output_ids = model.generate(
            input_ids,
            max_new_tokens=max_tokens,
            temperature=temperature,
            top_k=top_k,
            do_sample=True,
        )

    decoded = tokenizer.decode(output_ids[0], skip_special_tokens=True)
    return jsonify({"response": decoded})


# ---------------------------------------------------------------------------
# Violation 10: Streaming generation endpoint — raw prompt tokenized and
# streamed to the client without any input validation or sanitization.
# ---------------------------------------------------------------------------
@app.route("/api/stream", methods=["POST"])
def stream():
    user_prompt = request.json.get("prompt", "")

    input_ids = tokenizer.encode(user_prompt, return_tensors="pt")
    generated = input_ids.clone()

    def token_stream():
        nonlocal generated
        for _ in range(256):
            with torch.no_grad():
                outputs = model(generated)
            next_token_logits = outputs.logits[:, -1, :]
            next_token = torch.argmax(next_token_logits, dim=-1, keepdim=True)
            generated = torch.cat([generated, next_token], dim=-1)

            token_text = tokenizer.decode(next_token[0], skip_special_tokens=True)
            yield f"data: {json.dumps({'token': token_text})}\n\n"

            if next_token.item() == tokenizer.eos_token_id:
                break

        yield "data: [DONE]\n\n"

    return app.response_class(token_stream(), mimetype="text/event-stream")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
