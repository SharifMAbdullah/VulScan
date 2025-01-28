import requests
from utils.indexing import VectorIndex

from utils.indexing import VectorIndex
from utils.kb_prompt import generate_rag_prompt_with_kb

def analyze_function_with_rag_and_kb(function, index, similarity_threshold=0.8):
    """
    Analyze a function using RAG and integrate KB-based suggestions.
    """
    # Retrieve the most relevant KB entries
    kb_results = index.search(function, top_k=1)
    if kb_results and kb_results[0]["distance"] <= similarity_threshold:
        kb_match = kb_results[0]["metadata"]
    else:
        kb_match = None

    # Generate RAG prompt based on KB match
    prompt = generate_rag_prompt_with_kb(function, kb_match)

    # Send prompt to the LLM
    response = requests.post(
        "http://localhost:11434/api/generate",
        json={"model": "codegemma", "prompt": prompt},
        stream=True
    )
    return response.text

