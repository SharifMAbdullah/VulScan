from flask import Flask, request, jsonify
import requests
import json
import re
from textwrap import dedent

app = Flask(__name__)

def extract_functions(c_file_content):
    """
    Extract individual C functions from the given C file content.
    """
    # Regex to match C function definitions
    function_pattern = re.compile(
        r"""
        # Match the return type (e.g., int, void, float, etc.)
        (?:\b(?:int|void|char|float|double|long|short|struct)\b\s+)
        # Match pointers or whitespace before function name
        \**\w+\s*
        # Match function arguments in parentheses
        \([^)]*\)\s*
        # Match function body enclosed in braces
        \{
            (?:[^{}]*\{[^{}]*\}[^{}]*)*[^{}]*
        \}
        """,
        re.DOTALL | re.VERBOSE,
    )
    return function_pattern.findall(c_file_content)

def analyze_function_with_ollama(function):
    """
    Analyze a single C function for vulnerabilities using the Ollama API.
    """
    prompt = dedent(f"""
        Analyze the following C code for potential vulnerabilities and provide ratings for the following metrics. Provide only the metrics, no reasoning.

        - Confidentiality
        - Integrity
        - Availability
        - Access Gained
        - Attack Origin
        - Authentication Required
        - Complexity

        Code: {function}

        Response format:
        Confidentiality: [Complete/Partial/None]
        Integrity: [Complete/Partial/None]
        Availability: [Complete/Partial/None]
        AccessGained: [Admin/User/None]
        AttackOrigin: [Remote/Local]
        AuthenticationRequired: [Single/None]
        Complexity: [High/Medium/Low/None]
    """).strip()

    try:
        response = requests.post(
            "http://localhost:11434/api/generate",
            json={"model": "codegemma", "prompt": prompt},
            stream=True
        )
        if response.status_code != 200:
            return f"Ollama API failed with status {response.status_code}"

        result = []
        for line in response.iter_lines():
            if line:
                try:
                    chunk = json.loads(line)
                    if 'choices' in chunk and isinstance(chunk['choices'], list):
                        for choice in chunk['choices']:
                            if 'delta' in choice and 'content' in choice['delta']:
                                result.append(choice['delta']['content'])
                    elif 'response' in chunk:
                        result.append(chunk['response'])
                except Exception as e:
                    print(f"Error parsing chunk: {e}")
                    continue

        return ''.join(result).strip() or "No response"

    except Exception as e:
        return str(e)

@app.route("/analyze_file", methods=["POST"])
def analyze_c_file():
    try:
        # Receive the uploaded file from the request
        c_file = request.files.get("file")
        if not c_file:
            return jsonify({"error": "C file is required"}), 400

        # Read the file content
        c_file_content = c_file.read().decode("utf-8")
        if not c_file_content:
            return jsonify({"error": "C file is empty"}), 400

        # Extract individual functions from the file
        functions = extract_functions(c_file_content)
        if not functions:
            return jsonify({"error": "No functions found in the C file"}), 400

        # Analyze each function
        file_results = []
        for function in functions:
            result = analyze_function_with_ollama(function)
            file_results.append({"function": function, "result": result})

        return jsonify({
            "results": [
                {
                    "file": c_file.filename,
                    "functions": file_results
                }
            ]
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True)
