"""
File Processor Agent
  
"""

import base64
import logging
import re
from typing import Optional

from file_parsers.pdf_parser import PDFParser
from file_parsers.image_parser import ImageParser
from file_parsers.html_parser import HTMLParser

logger = logging.getLogger(__name__)


class FileProcessorAgent:
    """
    Agent responsible for processing uploaded files.

    Privilege Level: MEDIUM
    Capabilities:
    - Extract text from PDFs
    - Parse HTML content
    - Extract image metadata and text
    - Process Word documents
    """

    PRIVILEGE_LEVEL = "medium"
    SUPPORTED_TYPES = {
        "application/pdf": "pdf",
        "text/html": "html",
        "text/plain": "text",
        "application/json": "json",
        "image/jpeg": "image",
        "image/png": "image",
        "application/msword": "word",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "word",
    }

    # PII patterns: general + Singapore zero-tolerance categories
    _PII_PATTERNS = [
        # General
        (r"\b\d{3}-\d{2}-\d{4}\b", "SSN"),
        (r"\b(?:\d{4}[-\s]?){3}\d{4}\b", "Credit Card"),
        (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "Email"),
        (r"\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b", "US Phone"),
        (r"\b(?:\+\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b", "Phone"),
        (r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "IP Address"),
        (r"\b[A-Z]{1,2}\d{6,9}[A-Z]?\b", "Passport/ID"),
        (r"\b\d{16,19}\b", "Financial Account"),
        # Singapore: NRIC (S/T + 7 digits + checksum), FIN (F/G + 7 digits + letter)
        (r"\b[ST]\d{7}[A-Z]\b", "NRIC"),
        (r"\b[FG]\d{7}[A-Z]\b", "FIN"),
    ]

    def __init__(self):
        self.pdf_parser = PDFParser()
        self.image_parser = ImageParser()
        self.html_parser = HTMLParser()
        self.agent_id = "file_processor"

    def _redact_pii(self, text: str) -> str:
        """Redact PII from content. Replaces matches with REDACTED."""
        if not text:
            return text
        result = text
        for pattern, _ in self._PII_PATTERNS:
            result = re.sub(pattern, "REDACTED", result)
        return result

    async def process(
        self,
        content: Optional[str],
        filename: str,
        content_type: str
    ) -> str:
        """
        Process uploaded file and extract content.

        Args:
            content: File content (text or base64 encoded)
            filename: Original filename
            content_type: MIME type of the file

        Returns:
            Extracted text content from the file (PII redacted)
        """
        logger.info(
            "Processing file",
            extra={
                "file_name": filename,
                "file_type": content_type,
                "content_length": len(content) if content else 0,
            }
        )

        if not content:
            return f"Empty file: {filename}"

        # Determine file type
        file_type = self._get_file_type(content_type, filename)

        # Process based on file type
        # VULNERABILITY: No content scanning before processing
        try:
            if file_type == "pdf":
                extracted = await self._process_pdf(content)
            elif file_type == "html":
                extracted = await self._process_html(content)
            elif file_type == "image":
                extracted = await self._process_image(content)
            elif file_type == "json":
                extracted = await self._process_json(content)
            elif file_type == "text":
                extracted = content  # Direct text, no processing needed
            else:
                extracted = f"Unsupported file type: {content_type}"

            # Redact PII before returning (Singapore + general zero-tolerance categories)
            redacted = self._redact_pii(extracted)

            logger.info(
                "File processing complete",
                extra={
                    "file_name": filename,
                    "extracted_length": len(redacted),
                }
            )

            return redacted

        except Exception as e:
            logger.error(
                "Error processing file",
                extra={
                    "file_name": filename,
                    "error": str(e),
                }
            )
            return f"Error processing {filename}: {str(e)}"

    def _get_file_type(self, content_type: str, filename: str) -> str:
        """Determine file type from MIME type or extension."""
        # Check MIME type first
        if content_type in self.SUPPORTED_TYPES:
            return self.SUPPORTED_TYPES[content_type]

        # Fall back to extension
        ext = filename.lower().split('.')[-1] if '.' in filename else ''
        extension_map = {
            'pdf': 'pdf',
            'html': 'html',
            'htm': 'html',
            'txt': 'text',
            'json': 'json',
            'jpg': 'image',
            'jpeg': 'image',
            'png': 'image',
            'doc': 'word',
            'docx': 'word',
        }

        return extension_map.get(ext, 'unknown')

    async def _process_pdf(self, content: str) -> str:
        """
        Process PDF file content.

        VULNERABILITY: PDF processing extracts all text including
        hidden/white text that could contain prompt injections.
        """
        # Content is base64 encoded for PDFs
        try:
            pdf_bytes = base64.b64decode(content)
            extracted_text = await self.pdf_parser.extract_text(pdf_bytes)

            # VULNERABILITY: No hidden text detection
            # Invisible text (white on white, size 0, off-page) is extracted
            # and passed downstream without filtering

            return extracted_text
        except Exception as e:
            logger.error(f"PDF processing error: {e}")
            return f"Error processing PDF: {str(e)}"

    async def _process_html(self, content: str) -> str:
        """
        Process HTML content.

        VULNERABILITY: HTML processing may not detect all hidden content:
        - CSS-hidden elements (display:none, visibility:hidden)
        - White text on white background
        - Off-screen positioned elements
        - Base64 encoded content in data attributes
        """
        try:
            extracted_text = await self.html_parser.extract_text(content)

            # VULNERABILITY: get_text() may extract content from hidden elements
            # Malicious prompts in hidden divs can be extracted and passed
            # downstream without scanning

            return extracted_text
        except Exception as e:
            logger.error(f"HTML processing error: {e}")
            return f"Error processing HTML: {str(e)}"

    async def _process_image(self, content: str) -> str:
        """
        Process image file.

        VULNERABILITY: Image processing extracts EXIF metadata which
        could contain malicious prompts in comment/description fields.
        """
        try:
            image_bytes = base64.b64decode(content)

            # Extract both visual text (OCR) and metadata
            extracted = await self.image_parser.extract_all(image_bytes)

            # VULNERABILITY: EXIF data extracted and included without scanning
            # Comment, UserComment, ImageDescription fields could contain injections

            return extracted
        except Exception as e:
            logger.error(f"Image processing error: {e}")
            return f"Error processing image: {str(e)}"

    async def _process_json(self, content: str) -> str:
        """
        Process JSON content.

        VULNERABILITY: JSON content processed without PII or prompt scanning.
        Nested objects containing sensitive data or malicious strings are passed through.
        """
        import json

        try:
            # Parse to validate JSON
            data = json.loads(content)

            # VULNERABILITY: No recursive scan for:
            # - PII in nested objects
            # - Hidden prompt injection strings
            # - Encoded malicious content

            # Convert back to formatted string for analysis
            formatted = json.dumps(data, indent=2)

            return f"JSON Content:\n{formatted}"
        except json.JSONDecodeError as e:
            return f"Invalid JSON: {str(e)}\n\nRaw content:\n{content}"

    async def validate_file(self, content: str, filename: str) -> dict:
        """
        Validate file before processing.

        VULNERABILITY: Validation only checks format, not content.
        No security scanning performed.
        """
        # Basic validation only
        validation_result = {
            "valid": True,
            "filename": filename,
            "size": len(content) if content else 0,
            "warnings": []
        }

        # Size check (but no PII/threat check)
        if len(content) > 10 * 1024 * 1024:  # 10MB
            validation_result["warnings"].append("Large file - processing may be slow")

        # VULNERABILITY: No content-based security validation
        # Should check for:
        # - PII patterns
        # - Known malware signatures
        # - Prompt injection patterns
        # - Hidden content indicators

        return validation_result