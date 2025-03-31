import json
from urllib.parse import unquote
from typing import Dict, Union
import re

high_risk_patterns = [
    ("union select", 10), ("select", 10), ("insert", 10), ("update", 10), 
    ("delete", 10), ("drop", 10), ("truncate", 10), ("alter", 10), ("create", 10),
    ("exec", 10), ("execute", 10), ("sleep", 10), ("benchmark", 10), 
    ("1=1", 10), ("union all", 10), ("information_schema", 10), 
    ("load_file", 10), ("into outfile", 10), ("into dumpfile", 10),
    ("sp_executesql", 10), ("sp_oacreate", 10), ("xp_cmdshell", 10),
    ("xp_regread", 10), ("xp_dirtree", 10), ("pg_sleep", 10), 
    ("waitfor delay", 10), ("dbms_pipe", 10),
]

medium_risk_patterns = [
    ("from", 5), ("table", 5), ("database()", 5), ("user()", 5),
    ("concat", 5), ("substring", 5), ("substr", 5), ("cast", 5),
    ("convert", 5), ("char", 5), ("varchar", 5), ("nchar", 5),
    ("nvarchar", 5), ("/*", 5), ("*/", 5), ("--;", 5), ("--+", 5),
    ("/*+", 5), (";", 5), ("'--", 5), ("\"--", 5), ("' or ", 5),
    ("\" or ", 5), ("OR 1=1", 5), ("OR 1=2", 5), ("OR 0=0", 5),
    ("AND 1=1", 5), ("AND 1=2", 5), ("AND 0=0", 5),
]

common_benign_terms = [
    ("where", 3), ("or", 3), ("and", 3), ("not", 3), 
    ("like", 3), ("is", 3), ("in", 3), ("between", 3),
    ("order", 3), ("user", 3), ("select", 3)
]


def header_extraction_decode(headers: Dict) -> Dict:
    return {unquote(k): unquote(v) for k, v in headers.items()}

def preprocess_http_request(request: Union[Dict, str]) -> Dict:
    request = json.dumps(request) if isinstance(request, str) else request
    
    if request['request']['method'] == "GET":
        url = request['request']['url']
        headers = request['request']['headers']

        if headers:
            header_extraction_decode(headers)

        if url:
            parameters = url.split('&')

            for param in parameters:
                param = unquote(param)
                print('Decoded parameter:', param)

    
    if request['request']['method'] == "POST":
        body = request['request']['body']
        headers = request['request']['headers']

        if body:
            parameters = body.split('&')

            for param in parameters:
                param = unquote(param)
                print('Decoded parameter:', param)

        if headers:
            header_extraction_decode(headers)


if __name__ == "__main__":
    with open('collected_data_sql_injection.json', 'r') as file:
        requests = file.read()
        requests = json.loads(requests)

    for request in requests:
        preprocess_http_request(request)