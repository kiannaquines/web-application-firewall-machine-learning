from mitmproxy import http

collected_data = []

def response(flow: http.HTTPFlow) -> None:
    """
    This function is called for every HTTP response.
    It collects data from the request and response.
    """

    request = flow.request
    request_data = {
        "url": request.pretty_url,
        "method": request.method,
        "headers": dict(request.headers),
        "body": request.text if request.text else None,
    }

    entry = {
        "request": request_data,
    }

    collected_data.append(entry)

    save_to_file(collected_data)

def save_to_file(data):
    """
    Save the collected data to a JSON file.
    """
    import json
    with open("clean_data_no_sql_injection.json", "w") as f:
        json.dump(data, f, indent=4)

def done():
    """
    Called when the script is shutting down.
    """
    print(f"Collected {len(collected_data)} entries.")