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
#######
# import requests
# import json
# from utils.extraction import extract_functions

# def generate_prompt_for_metric(metric, function):
#     """
#     Generate a refined prompt for a specific metric using the Tree-of-Thought method.
#     """
#     return f"""
#         Analyze the following C code specifically for {metric} risks. 
#         Focus only on {metric} and provide your assessment concisely.

#         Code: {function}

#         Response format for {metric}:
#         {metric}: [Complete/Partial/None] or relevant details.
#     """.strip()

# def analyze_function_with_tree_of_thought(function):
#     """
#     Use the Tree-of-Thought method to analyze a single C function for vulnerabilities.
#     """
#     metrics = [
#         "Confidentiality", "Integrity", "Availability", 
#         "Access Gained", "Attack Origin", "Authentication Required", "Complexity"
#     ]
#     responses = {}

#     for metric in metrics:
#         prompt = generate_prompt_for_metric(metric, function)
#         try:
#             response = requests.post(
#                 "http://localhost:11434/api/generate",
#                 json={"model": "codegemma", "prompt": prompt},
#                 stream=True
#             )
#             if response.status_code != 200:
#                 responses[metric] = f"Ollama API failed with status {response.status_code}"
#                 continue

#             result = []
#             for line in response.iter_lines():
#                 if line:
#                     try:
#                         chunk = json.loads(line)
#                         if 'choices' in chunk and isinstance(chunk['choices'], list):
#                             for choice in chunk['choices']:
#                                 if 'delta' in choice and 'content' in choice['delta']:
#                                     result.append(choice['delta']['content'])
#                         elif 'response' in chunk:
#                             result.append(chunk['response'])
#                     except Exception as e:
#                         print(f"Error parsing chunk: {e}")
#                         continue

#             responses[metric] = ''.join(result).strip() or "No response"
#         except Exception as e:
#             responses[metric] = str(e)

#     # Combine all responses for the function
#     return responses

# def analyze_c_files(c_files):
#     """
#     Analyze all extracted C files and return the results using the Tree-of-Thought method.
#     """
#     results = []

#     for c_file in c_files:
#         with open(c_file, "r") as file:
#             c_file_content = file.read()

#         functions = extract_functions(c_file_content)
#         if not functions:
#             results.append({
#                 "file": c_file,
#                 "functions": [],
#                 "error": "No functions found in this file"
#             })
#             continue

#         function_results = []
#         for function in functions:
#             result = analyze_function_with_tree_of_thought(function)
#             function_results.append({
#                 "function": function,
#                 "result": result
#             })

#         results.append({
#             "file": c_file,
#             "functions": function_results
#         })

#     return results
###############
# from utils.extraction import extract_functions
# from utils.rag_utils import analyze_function_with_rag_and_kb
# from utils.indexing import VectorIndex

# def analyze_c_files_with_rag(c_files, index_path="index"):
#     """
#     Analyze C files using the RAG pipeline.
#     """
#     index = VectorIndex(index_path=index_path)
#     results = []

#     for c_file in c_files:
#         with open(c_file, "r") as file:
#             c_file_content = file.read()

#         functions = extract_functions(c_file_content)
#         if not functions:
#             results.append({
#                 "file": c_file,
#                 "functions": [],
#                 "error": "No functions found in this file"
#             })
#             continue

#         function_results = []
#         for function in functions:
#             result = analyze_function_with_rag(function, index)
#             function_results.append({
#                 "function": function,
#                 "result": result
#             })

#         results.append({
#             "file": c_file,
#             "functions": function_results
#         })

#     return results

# #############
# from utils.rag_utils import analyze_function_with_rag_and_kb
# from utils.indexing import VectorIndex
# from utils.extraction import extract_functions

# def analyze_c_files_with_kb(c_files, index_path="index", kb_path="KB.json"):
#     """
#     Analyze C files using RAG with knowledge base integration.
#     """
#     index = VectorIndex(index_path=index_path)
    
#     # Load KB into the index if not already loaded
#     if not os.path.exists(f"{index_path}_metadata.json"):
#         index.load_kb_to_index(kb_path)

#     results = []
#     for c_file in c_files:
#         with open(c_file, "r") as file:
#             c_file_content = file.read()

#         functions = extract_functions(c_file_content)
#         if not functions:
#             results.append({
#                 "file": c_file,
#                 "functions": [],
#                 "error": "No functions found in this file"
#             })
#             continue

#         function_results = []
#         for function in functions:
#             result = analyze_function_with_rag_and_kb(function, index)
#             function_results.append({
#                 "function": function,
#                 "result": result
#             })

#         results.append({
#             "file": c_file,
#             "functions": function_results
#         })

#     return results