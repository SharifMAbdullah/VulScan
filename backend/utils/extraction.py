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
