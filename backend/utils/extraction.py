import re

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


import re

def extract_function_signatures(c_file_content):
    """
    Extract function signatures along with their return types from the given C file content.
    """
    # Regex to match C function signatures with return type
    function_pattern = re.compile(
        r"""
        # Match the return type (e.g., int, void, char, etc.)
        (\b(?:int|void|char|float|double|long|short|struct|unsigned)\b(?:\s+\b[\w_]+\b)?\s*\**)
        # Match the function name and its parameters
        (\*?[\w_]+\s*\([^)]*\))
        # Look ahead for the opening brace of the function body
        (?=\s*\{)
        """,
        re.DOTALL | re.VERBOSE,
    )
    
    # Find all function signatures
    matches = function_pattern.finditer(c_file_content)
    
    signatures = []
    for match in matches:
        # Extract return type and signature
        return_type = match.group(1).strip()
        signature = match.group(2).strip()
        # Append a tuple of (return_type, signature)
        signatures.append((return_type + " " + signature))
    
    return signatures[0]
