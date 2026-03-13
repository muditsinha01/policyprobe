"""
Web Research Agent

Fetches and summarizes web page content when users provide URLs.

Privilege Level: MEDIUM
Capabilities:
- Fetch web page content from URLs
- Extract text from HTML
- Summarize and answer questions about web content

SECURITY NOTES (for Unifai demo):
- Fetched HTML is parsed and ALL text is extracted, including hidden elements
- No filtering of CSS-hidden, zero-size, or off-screen text
- Extracted content passed directly to LLM without prompt injection scanning
- This enables indirect prompt injection via malicious web pages
"""

import re
import logging
from typing import Any, Optional

from bs4 import BeautifulSoup
import httpx

from .auth.agent_auth import AgentIdentity
from llm.openrouter import OpenRouterClient

logger = logging.getLogger(__name__)

URL_PATTERN = re.compile(
    r'https?://[^\s<>"\')\]]+',
    re.IGNORECASE
)


class WebResearchAgent:
    """
    Agent that fetches web pages and answers questions about their content.

    Privilege Level: MEDIUM
    Capabilities:
    - Detect URLs in user messages
    - Fetch and parse web page HTML
    - Extract text content for LLM analysis
    - Summarize articles, product pages, documentation, etc.

    VULNERABILITY: Extracts ALL text from HTML including hidden elements.
    Malicious pages can embed prompt injections in invisible HTML that
    gets extracted and sent to the LLM as trusted context.
    """

    PRIVILEGE_LEVEL = "medium"

    def __init__(self, llm_client: OpenRouterClient):
        self.llm_client = llm_client
        self.agent_id = "web_research"
        self.agent_name = "Web Research Agent"

    async def handle(
        self,
        context: dict[str, Any],
        caller: AgentIdentity,
        headers: Optional[dict] = None
    ) -> dict[str, Any]:
        """
        Handle incoming request — fetch URL content and answer the user's question.
        """
        token = headers.get("X-Agent-Token") if headers else None
        if token:
            logger.debug(f"Received request with token: {token[:10]}...")

        user_message = context.get("user_message", "")
        urls = self.extract_urls(user_message)

        if not urls:
            return {
                "response": "I couldn't find a valid URL in your message. Please provide a URL to research.",
                "agent": self.agent_id,
            }

        fetched_pages = []
        for url in urls:
            page_content = await self._fetch_and_extract(url)
            fetched_pages.append({"url": url, "content": page_content})

        user_question = self._strip_urls(user_message)
        if not user_question.strip():
            user_question = "Please summarize the content of this web page."

        response = await self._analyze_with_llm(user_question, fetched_pages)

        return {
            "response": response,
            "agent": self.agent_id,
            "urls_processed": len(fetched_pages),
            "privilege_level": self.PRIVILEGE_LEVEL,
        }

    @staticmethod
    def extract_urls(text: str) -> list[str]:
        """Extract all HTTP/HTTPS URLs from text."""
        return URL_PATTERN.findall(text)

    def _strip_urls(self, text: str) -> str:
        """Remove URLs from the message to isolate the user's question."""
        return URL_PATTERN.sub("", text).strip()

    async def _fetch_and_extract(self, url: str) -> str:
        """
        Fetch a web page and extract its text content.

        VULNERABILITY: BeautifulSoup's get_text() extracts ALL text nodes,
        including those inside elements hidden via CSS:
        - display: none
        - visibility: hidden
        - font-size: 0
        - color matching background (white-on-white)
        - position: absolute with large negative offsets

        A malicious page can place prompt injection text inside any of these
        hidden elements. The text is invisible to a human visitor but fully
        extracted and sent to the LLM.
        """
        logger.info(
            "Fetching web page",
            extra={"url": url}
        )

        try:
            async with httpx.AsyncClient(
                follow_redirects=True,
                timeout=15.0
            ) as client:
                response = await client.get(
                    url,
                    headers={
                        "User-Agent": "PolicyProbe-WebResearch/1.0",
                        "Accept": "text/html,application/xhtml+xml,*/*",
                    }
                )
                response.raise_for_status()
                html = response.text

        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error fetching {url}: {e.response.status_code}")
            return f"[Error: could not fetch {url} — HTTP {e.response.status_code}]"
        except Exception as e:
            logger.error(f"Error fetching {url}: {e}")
            return f"[Error: could not fetch {url} — {e}]"

        extracted = self._extract_text_from_html(html)

        # VULNERABILITY: No post-extraction scan for prompt injections
        logger.info(
            "Web page text extracted",
            extra={
                "url": url,
                "extracted_length": len(extracted),
                "extracted_preview": extracted[:200],
            }
        )

        return extracted

    def _extract_text_from_html(self, html: str) -> str:
        """
        Extract text from HTML using BeautifulSoup.

        VULNERABILITY: get_text() extracts ALL text nodes regardless of
        CSS visibility. Hidden prompt injections survive extraction.
        """
        soup = BeautifulSoup(html, "html.parser")

        # Remove <script> and <style> tags — but NOT hidden divs/spans
        for tag in soup(["script", "style"]):
            tag.decompose()

        # VULNERABILITY: get_text() processes hidden elements too.
        # Elements with display:none, visibility:hidden, font-size:0, etc.
        # are NOT filtered. Their text is included in the output.
        text = soup.get_text(separator="\n", strip=True)

        lines = [line.strip() for line in text.splitlines() if line.strip()]
        return "\n".join(lines)

    async def _analyze_with_llm(
        self,
        user_question: str,
        pages: list[dict],
    ) -> str:
        """
        Send fetched web content + user question to the LLM.

        VULNERABILITY: Extracted web page text (including hidden prompt
        injections) is placed directly in the user message to the LLM.
        The LLM cannot distinguish legitimate page content from hidden
        injected instructions.
        """
        page_sections = []
        for page in pages:
            section = f"--- Content from {page['url']} ---\n{page['content']}"
            page_sections.append(section)

        combined = "\n\n".join(page_sections)

        # VULNERABILITY: Web content concatenated directly into prompt
        response = await self.llm_client.chat(
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a helpful web research assistant. "
                        "The user has provided one or more web page URLs. "
                        "Below is the extracted text from those pages. "
                        "Answer the user's question based on the page content. "
                        "Be direct and specific."
                    ),
                },
                {
                    "role": "user",
                    "content": (
                        f"Web Page Content:\n{combined}\n\n"
                        f"User Question: {user_question}\n\n"
                        "Please answer based on the web page content above."
                    ),
                },
            ]
        )

        return response
