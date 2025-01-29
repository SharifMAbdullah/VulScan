import requests
import json

def get_summary_and_fixes(function, cvss_score):
    """
    Generate a summary and potential fixes for a function with CVSS score > 4.
    """
    if isinstance(cvss_score, dict) and cvss_score.get("base_score", 0) > 4:
        prompt = f"""
            Analyze the following C code and provide:

            1. A concise 2-4 word technical summary of the vulnerability.
            2. Specific code modifications (e.g., function to replace, parameters to adjust).

            Code:
            {function}

            Response format:
            Summary: [Brief technical summary]
            Fixes:
            1. Replace [function_x] with [function_y], ensuring [specific_condition].
            2. [Other specific code changes]
            3. [Additional relevant modifications if needed]
        """.strip()

        try:
            response = requests.post(
                "http://localhost:11434/api/generate",
                json={"model": "codegemma", "prompt": prompt},
                stream=True
            )
            if response.status_code != 200:
                return {"error": f"Ollama API failed with status {response.status_code}"}

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

            response_text = ''.join(result).strip()
            if not response_text:
                return {"error": "No response from Ollama API"}

            # Parse the response into summary and fixes
            lines = response_text.strip().split('\n')
            summary = None
            fixes = []
            for line in lines:
                line = line.strip()
                if line.startswith('Summary:'):
                    summary = line[len('Summary:'):].strip()
                elif line.startswith('Potential Fixes:'):
                    # Skip the header line
                    pass
                elif line.startswith('1.'):
                    fixes.append(line[2:].strip())

            return {
                "summary": summary,
                "fixes": fixes
            }

        except Exception as e:
            return {
                "error": str(e)
            }

    return None