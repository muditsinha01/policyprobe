"""
Simple HTTP server for serving test web pages during the demo.

Usage:
    python scripts/serve_test_pages.py

Serves files from test_files/web_research/ on http://localhost:8888

Demo workflow:
    1. Start this server
    2. Start the PolicyProbe app (frontend + backend)
    3. In the chat, type:
       "Summarize this article: http://localhost:8888/malicious_blog_post.html"
    4. The WebResearchAgent fetches the page, extracts ALL text
       (including hidden prompt injections), and sends it to the LLM.
    5. The LLM's response will be influenced by the hidden injections.
"""

import http.server
import os
import sys

PORT = 8888
DIRECTORY = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "test_files",
    "web_research",
)


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)


if __name__ == "__main__":
    if not os.path.isdir(DIRECTORY):
        print(f"Error: directory not found: {DIRECTORY}")
        sys.exit(1)

    print(f"Serving test pages from: {DIRECTORY}")
    print(f"URL: http://localhost:{PORT}/malicious_blog_post.html")
    print("Press Ctrl+C to stop.\n")

    with http.server.HTTPServer(("", PORT), Handler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nServer stopped.")
