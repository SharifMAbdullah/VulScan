import requests
import json
from utils.extraction import extract_functions

def analyze_function_with_ollama(function):
    """
    Analyze a single C function for vulnerabilities using the Ollama API.
    """
    prompt = f"""
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
    """.strip()

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

def analyze_c_files(c_files):
    """
    Analyze all extracted C files and return the results.
    """
    results = []

    for c_file in c_files:
        with open(c_file, "r") as file:
            c_file_content = file.read()

        functions = extract_functions(c_file_content)
        if not functions:
            results.append({
                "file": c_file,
                "functions": [],
                "error": "No functions found in this file"
            })
            continue

        function_results = []
        for function in functions:
            result = analyze_function_with_ollama(function)
            function_results.append({
                "function": function,
                "result": result
            })

        results.append({
            "file": c_file,
            "functions": function_results
        })

    return results
