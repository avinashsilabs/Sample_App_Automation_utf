import os
import json
import cgitb
import sys

cgitb.enable()


if __name__ == "__main__":
    print("Content-Type: text/html")
    print()
    print("<TITLE>CGI script output</TITLE>")
    print("<H1>This is my first CGI script</H1>")
    print("Hello, world!")

    content_length = int(os.environ["CONTENT_LENGTH"])
    content_type = os.environ.get("CONTENT_TYPE")
    http_cookie = os.environ.get("HTTP_COOKIE")
    http_user_agent = os.environ.get("HTTP_USER_AGENT")
    http_accept_encoding = os.environ.get("HTTP_ACCEPT_ENCODING")
    http_accept = os.environ.get("HTTP_ACCEPT")
    query_string = os.environ.get("QUERY_STRING")
    request_method = os.environ.get("REQUEST_METHOD")
    request_uri = os.environ.get("REQUEST_URI")

    print(f"Content Length: {content_length}")
    print(f"Content Type: {content_type}")
    print(f"HTTP Cookie: {http_cookie}")
    print(f"HTTP User Agent: {http_user_agent}")
    print(f"HTTP Accept: {http_accept}")
    print(f"HTTP Accept Encoding: {http_accept_encoding}")
    print(f"Request Method: {request_method}")
    print(f"Query String: {query_string}")
    print(f"Request URI: {request_uri}")

    if content_length > 0 and "application/json" in content_type:
        data = sys.stdin.read()
        try:
            json_data = json.loads(data)
            print("JSON content decoded successfully")
        except json.JSONDecodeError:
            print("Error decoding JSON content")
