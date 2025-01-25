from flask import Flask, request, jsonify
import requests
import json
from textwrap import dedent

app = Flask(__name__)

@app.route("/analyze", methods=["POST"])
def analyze_code():
    try:
        data = request.get_json()
        code_snippet = data.get("code", "")

        if not code_snippet:
            return jsonify({"error": "Code snippet is required"}), 400

        prompt = dedent(f"""
            Analyze the following C code for potential vulnerabilities and provide ratings for the following metrics. Provide only the metrics, no reasoning.

            - Confidentiality
            - Integrity
            - Availability

            Code: {code_snippet}

            Response format:
            Confidentiality: [High/Medium/Low]
            Integrity: [High/Medium/Low]
            Availability: [High/Medium/Low]
            """).strip()

        response = requests.post(
            "http://localhost:11434/api/generate",
            json={"model": "codegemma", "prompt": prompt},
            stream=True
        )

        if response.status_code != 200:
            return jsonify({"error": f"Ollama API request failed with status {response.status_code}"}), 500

        # accumulate response
        result = []
        done = False

        # Parse the response stream chunk by chunk
        for line in response.iter_lines():
            if line:  # Skip empty lines
                try:
                    chunk = json.loads(line)
                    # print("Received chunk:", chunk)  # Debugging

                    if isinstance(chunk, dict):
                        # The Ollama API returns a list of events; process each
                        if 'choices' in chunk and isinstance(chunk['choices'], list):
                            for choice in chunk['choices']:
                                if isinstance(choice, dict) and 'delta' in choice:
                                    delta = choice['delta']
                                    if isinstance(delta, str):
                                        result.append(delta)
                                    elif isinstance(delta, dict):
                                        # Handle both string and dict deltas
                                        if 'content' in delta:
                                            result.append(delta['content'])
                        elif 'response' in chunk:
                            result.append(chunk['response'])

                        # Check if the current chunk indicates completion
                        if 'done' in chunk and chunk['done'] is True:
                            done = True
                            break
                except Exception as e:
                    print(f"Error parsing chunk: {e}")
                    continue

        if not done:
            print("Ollama API response stream did not complete properly.")
            return jsonify({"error": "Ollama API response stream terminated unexpectedly"}), 500

        # Combine all chunks into the final response
        full_response = ''.join(result).strip()

        if not full_response:
            return jsonify({"error": "Ollama API returned an empty result"}), 500

        return jsonify({"result": full_response}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True)