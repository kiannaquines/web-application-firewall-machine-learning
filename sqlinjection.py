import re
from urllib.parse import unquote, parse_qs, urlparse
from typing import Dict, Union, List, Tuple

# Categorize SQL injection patterns by risk level
high_risk_patterns = [
    "union select", "select", "insert", "update", "delete", "drop", "truncate", "alter", "create", 
    "exec", "execute", "sleep", "benchmark", "1=1", "1=2", "0=0", "union all",
    "information_schema", "load_file", "into outfile", "into dumpfile", "sp_executesql", "sp_oacreate",
    "xp_cmdshell", "xp_regread", "xp_dirtree", "pg_sleep", "waitfor delay", "dbms_pipe"
]

medium_risk_patterns = [
    "from", "table", "database()", "user()", "concat", "substring", "substr",
    "cast", "convert", "char", "varchar", "nchar", "nvarchar", 
    "/*", "*/", "--;", "--+", "/*+", ";", "'--", "\"--", "' or ", "\" or "
]

# Common terms that appear in normal requests but might be SQL keywords
common_benign_terms = [
    "where", "or", "and", "not", "like", "is", "in", "between", "order", "user", "select"
]

def preprocess_http_request(request: Union[Dict, str]) -> Dict:
    """
    Process HTTP request and analyze for SQL injection attempts with improved accuracy
    
    Args:
        request: HTTP request as dict or raw string
        
    Returns:
        Dictionary containing:
        - original_request: The original request
        - decoded_request: URL decoded request
        - high_risk_keywords: List of high-risk SQL keywords found
        - medium_risk_keywords: List of medium-risk SQL keywords found
        - risk_score: Numeric risk score (0-100)
        - is_sql_injection: Boolean flag if high-risk patterns found
    """
    # Convert request to analyzable format
    if isinstance(request, dict):
        request_dict = request
        request_str = str(request)
    else:
        request_str = request
        request_dict = {"body": request}
    
    # URL decode the request
    decoded_request = unquote(request_str)
    
    # Extract key components to analyze
    components_to_check = []
    
    # Extract URL parameters if present
    if isinstance(request_dict, dict) and "request" in request_dict and "url" in request_dict["request"]:
        url = request_dict["request"]["url"]
        parsed_url = urlparse(url)
        
        # Add path segments
        path_segments = parsed_url.path.split('/')
        components_to_check.extend(path_segments)
        
        # Add query parameters
        query_params = parse_qs(parsed_url.query)
        for param, values in query_params.items():
            components_to_check.append(param)
            components_to_check.extend(values)
    
    # Extract body parameters if present
    if isinstance(request_dict, dict) and "request" in request_dict and "body" in request_dict["request"]:
        body = request_dict["request"]["body"]
        if body:
            # Try to parse body as query string
            try:
                body_params = parse_qs(body)
                for param, values in body_params.items():
                    components_to_check.append(param)
                    components_to_check.extend(values)
            except:
                # If not parseable, just add the whole body
                components_to_check.append(body)
    
    # If we couldn't extract specific components, analyze the whole request
    if not components_to_check:
        components_to_check = [decoded_request]
    
    # Initialize results
    high_risk_found = []
    medium_risk_found = []
    
    # Check for high-risk patterns
    for pattern in high_risk_patterns:
        pattern_regex = r'\b' + re.escape(pattern) + r'\b'
        for component in components_to_check:
            if isinstance(component, str):
                matches = re.finditer(pattern_regex, component.lower())
                for match in matches:
                    matched_text = match.group()
                    if matched_text not in high_risk_found:
                        # Check if the match appears in a suspicious context
                        if _is_suspicious_context(component, match.start(), match.end()):
                            high_risk_found.append(matched_text)
    
    # Check for medium-risk patterns
    for pattern in medium_risk_patterns:
        pattern_regex = r'\b' + re.escape(pattern) + r'\b'
        for component in components_to_check:
            if isinstance(component, str):
                matches = re.finditer(pattern_regex, component.lower())
                for match in matches:
                    matched_text = match.group()
                    if matched_text not in medium_risk_found and matched_text not in high_risk_found:
                        # Check if the match appears in a suspicious context
                        if _is_suspicious_context(component, match.start(), match.end()):
                            medium_risk_found.append(matched_text)
    
    # Calculate risk score (0-100)
    high_risk_weight = 20  # Each high-risk keyword adds 20 points
    medium_risk_weight = 5  # Each medium-risk keyword adds 5 points
    risk_score = min(100, (len(high_risk_found) * high_risk_weight) + 
                         (len(medium_risk_found) * medium_risk_weight))
    
    # Determine if this is likely SQL injection
    is_sql_injection = risk_score >= 20  # Threshold for positive detection
    
    return {
        'original_request': request_str,
        'decoded_request': decoded_request,
        'high_risk_keywords': high_risk_found,
        'medium_risk_keywords': medium_risk_found,
        'risk_score': risk_score,
        'is_sql_injection': is_sql_injection
    }

def _is_suspicious_context(text: str, start_idx: int, end_idx: int) -> bool:
    """
    Determine if a keyword appears in a suspicious context
    
    Args:
        text: The full text containing the keyword
        start_idx: Start index of the keyword
        end_idx: End index of the keyword
        
    Returns:
        Boolean indicating if the context is suspicious
    """
    if not text:
        return False
        
    # Check if term is in common_benign_terms and appears in a normal context
    keyword = text[start_idx:end_idx].lower()
    if keyword in common_benign_terms:
        # Check for surrounding characters that would indicate SQL injection
        suspicious_chars = ["'", "\"", ";", "--", "/*", "*/", "="]
        
        # Get surrounding context (10 chars before and after)
        context_start = max(0, start_idx - 10)
        context_end = min(len(text), end_idx + 10)
        context = text[context_start:context_end].lower()
        
        # If none of the suspicious characters are in the context, likely benign
        if not any(char in context for char in suspicious_chars):
            return False
    
    # Look for SQL injection indicators
    indicators = [
        # Quote manipulation
        "'--", "\"--", "' or ", "\" or ", "';", "\";",
        # Multiple statements
        "; select ", "; insert ", "; update ", "; delete ",
        # Comment manipulation
        "/*", "*/", "--",
        # Boolean operations
        " or 1=1", " or true", " or 'a'='a", " or \"a\"=\"a"
    ]
    
    # Get a broader context for checking indicators
    context_start = max(0, start_idx - 20)
    context_end = min(len(text), end_idx + 20)
    context = text[context_start:context_end].lower()
    
    return any(indicator in context for indicator in indicators)


with open('collected_data.json', 'r') as file:
    collected_data = file.read()

# Test with the example request
result = preprocess_http_request(request_example)
print(f"Risk Score: {result['risk_score']}")
print(f"High-Risk Keywords: {result['high_risk_keywords']}")
print(f"Medium-Risk Keywords: {result['medium_risk_keywords']}")
print(f"Is SQL Injection: {result['is_sql_injection']}")

# Test with a request containing SQL injection
sql_injection_request = "admin' OR 1=1--"
result = preprocess_http_request(sql_injection_request)
print("\nSQL Injection Test:")
print(f"Risk Score: {result['risk_score']}")
print(f"High-Risk Keywords: {result['high_risk_keywords']}")
print(f"Medium-Risk Keywords: {result['medium_risk_keywords']}")
print(f"Is SQL Injection: {result['is_sql_injection']}")