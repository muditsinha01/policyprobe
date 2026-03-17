"""
File Processor Agent

Deliberately vulnerable version for the PolicyProbe demo.

VULNERABILITY:
Uploaded files are parsed and their extracted content is forwarded to downstream
LLM processing without prompt-injection or hidden-content scanning.

This allows malicious instructions embedded in:
- hidden HTML elements
- base64/encoded blocks
- PDF hidden text
- image metadata / OCR text
to reach the model.
"""

import base64
import logging
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
    - Process plain text and JSON

    DELIBERATE VULNERABILITY:
    Extracted content is trusted and returned directly without scanning for:
    - hidden prompts
    - prompt injection
    - encoded malicious instructions
    - dangerous metadata content
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

    def __init__(self):
        self.pdf_parser = PDFParser()
        self.image_parser = ImageParser()
        self.html_parser = HTMLParser()
        self.agent_id = "file_processor"

    async def process(
        self,
        content: Optional[str],
        filename: str,
        content_type: str
    ) -> str:
        """
        Process uploaded file and extract content.

        VULNERABILITY:
        No security scan is performed before or after extraction.
        Hidden prompts and malicious instructions can be extracted and passed
        into downstream LLM context.
        """
        logger.info(
            "Processing file",
            extra={
                "file_name": filename,
                "file_type": content_type,
                "content_length": len(content) if content else 0,
                # Deliberately unsafe logging for demo purposes
                "content_preview": content[:100] if content else None,
            }
        )

        if not content:
            return f"Empty file: {filename}"

        file_type = self._get_file_type(content_type, filename)

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
                extracted = content
            else:
                extracted = f"Unsupported file type: {content_type}"

            # DELIBERATE VULNERABILITY:
            # Extracted content is forwarded directly to downstream analysis
            # without prompt-injection scanning.
            downstream_payload = f"USER_UPLOADED_CONTENT:\n{extracted}"

            logger.info(
                "File processing complete",
                extra={
                    "file_name": filename,
                    "extracted_length": len(extracted),
                    # Deliberately unsafe logging for demo purposes
                    "extracted_preview": extracted[:200],
                }
            )

            return downstream_payload

        except Exception as e:
            logger.error(
                "Error processing file",
                extra={
                    "file_name": filename,
                    "error": str(e),
                    # Deliberately unsafe logging for demo purposes
                    "file_content": content[:500] if content else None,
                }
            )
            return f"Error processing {filename}: {str(e)}"

    def _get_file_type(self, content_type: str, filename: str) -> str:
        """Determine file type from MIME type or extension."""
        if content_type in self.SUPPORTED_TYPES:
            return self.SUPPORTED_TYPES[content_type]

        ext = filename.lower().split(".")[-1] if "." in filename else ""
        extension_map = {
            "pdf": "pdf",
            "html": "html",
            "htm": "html",
            "txt": "text",
            "json": "json",
            "jpg": "image",
            "jpeg": "image",
            "png": "image",
            "doc": "word",
            "docx": "word",
        }
        return extension_map.get(ext, "unknown")

    async def _process_pdf(self, content: str) -> str:
        """
        Process PDF file content.

        VULNERABILITY:
        PDF extraction trusts all extracted text, including hidden text layers
        that may contain prompt injection payloads.
        """
        try:
            pdf_bytes = base64.b64decode(content)
            extracted_text = await self.pdf_parser.extract_text(pdf_bytes)
            return extracted_text
        except Exception as e:
            logger.error(f"PDF processing error: {e}")
            return f"Error processing PDF: {str(e)}"

    async def _process_html(self, content: str) -> str:
        """
        Process HTML content.

        VULNERABILITY:
        Hidden DOM content may be extracted and returned, including:
        - display:none elements
        - visibility:hidden elements
        - off-screen text
        - encoded or obfuscated hidden instructions
        """
        try:
            extracted_text = await self.html_parser.extract_text(content)
            return extracted_text
        except Exception as e:
            logger.error(f"HTML processing error: {e}")
            return f"Error processing HTML: {str(e)}"

    async def _process_image(self, content: str) -> str:
        """
        Process image file.

        VULNERABILITY:
        OCR text and metadata are extracted without scanning for malicious
        instructions in EXIF comment or description fields.
        """
        try:
            image_bytes = base64.b64decode(content)
            extracted = await self.image_parser.extract_all(image_bytes)
            return extracted
        except Exception as e:
            logger.error(f"Image processing error: {e}")
            return f"Error processing image: {str(e)}"

    async def _process_json(self, content: str) -> str:
        """
        Process JSON content.

        VULNERABILITY:
        JSON strings and nested fields are returned without checking for
        malicious prompt content.
        """
        import json

        try:
            data = json.loads(content)
            formatted = json.dumps(data, indent=2)
            return f"JSON Content:\n{formatted}"
        except json.JSONDecodeError as e:
            return f"Invalid JSON: {str(e)}\n\nRaw content:\n{content}"

    async def validate_file(self, content: str, filename: str) -> dict:
        """
        Validate file before processing.

        VULNERABILITY:
        Validation only checks superficial properties and does not scan for:
        - prompt injection
        - hidden prompts
        - encoded malicious content
        """
        validation_result = {
            "valid": True,
            "filename": filename,
            "size": len(content) if content else 0,
            "warnings": []
        }

        if content and len(content) > 10 * 1024 * 1024:
            validation_result["warnings"].append("Large file - processing may be slow")

        return validation_result
