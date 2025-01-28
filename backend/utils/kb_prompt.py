def generate_rag_prompt_with_kb(function, kb_match=None):
    """
    Generate a refined prompt that incorporates KB suggestions if available.
    """
    if kb_match:
        summary = kb_match.get("Summary", "No summary available")
        func_after = kb_match.get("func_after", "No suggested fix available")

        return f"""
        The following code has been analyzed based on the knowledge base. Suggest improvements and analyze vulnerabilities:

        Original Function:
        {function}

        Matched Knowledge Base Summary:
        {summary}

        Suggested Fix (from KB):
        {func_after}

        Based on the above, please confirm or refine the suggested fix and provide detailed reasoning for any additional changes.

        Response format:
        - Confirmed Fix: [Yes/No]
        - Suggested Fix (if applicable): [Provide code]
        - Additional Reasoning: [Explain vulnerabilities and fixes]
        """.strip()

    # Fallback to a generic prompt if no KB match is found
    return f"""
        The following code requires analysis for vulnerabilities. Suggest improvements based on best practices:

        Code:
        {function}

        Response format:
        - Suggested Fix: [Provide code]
        - Additional Reasoning: [Explain vulnerabilities and fixes]
    """.strip()
