"""
Image Parser

Extracts content from image files including EXIF metadata.

SECURITY NOTES:
- EXIF metadata extracted with prompt injection scanning
- PII detection and redaction applied to all text fields
- GPS fields stripped before processing
- Singapore PII patterns detected and blocked
"""

import io
import logging
import re
import base64
from typing import Optional

logger = logging.getLogger(__name__)

# GPS-related EXIF tags to strip
GPS_TAGS = {
    'GPSInfo', 'GPSLatitude', 'GPSLongitude', 'GPSAltitude',
    'GPSLatitudeRef', 'GPSLongitudeRef', 'GPSAltitudeRef',
    'GPSTimeStamp', 'GPSDateStamp', 'GPSSpeed', 'GPSSpeedRef',
    'GPSTrack', 'GPSTrackRef', 'GPSImgDirection', 'GPSImgDirectionRef',
    'GPSDestLatitude', 'GPSDestLongitude', 'GPSDestBearing',
    'GPSProcessingMethod', 'GPSAreaInformation', 'GPSMeasureMode',
    'GPSDOP', 'GPSStatus', 'GPSSatellites', 'GPSMapDatum',
}

# Prompt injection patterns
INJECTION_PATTERNS = [
    re.compile(r'(?:[A-Za-z0-9+/]{40,}={0,2})', re.IGNORECASE),  # base64 blobs
    re.compile(r'(?:rm\s+-rf|chmod\s+|chown\s+|sudo\s+|curl\s+|wget\s+|bash\s+|sh\s+|exec\s+|eval\s+)', re.IGNORECASE),  # shell commands
    re.compile(r'[\u200b\u200c\u200d\u200e\u200f\u00ad\ufeff\u2060\u2061\u2062\u2063]'),  # invisible/zero-width chars
    re.compile(r'(?:1gn0r3|1gnor3|inj3ct|pr0mpt|syst3m|4dmin|h4ck|3xec)', re.IGNORECASE),  # leetspeak
    re.compile(r'(?:ignore\s+(?:previous|above|prior|all)\s+instructions?|'
               r'disregard\s+(?:previous|above|prior|all)\s+instructions?|'
               r'forget\s+(?:previous|above|prior|all)|'
               r'you\s+are\s+now|act\s+as\s+(?:a|an)|'
               r'new\s+instructions?:|system\s*:|<\s*/?(?:system|prompt|instruction)\s*>|'
               r'\[INST\]|\[/INST\]|###\s*(?:instruction|system|human|assistant)|'
               r'<\|(?:im_start|im_end|endoftext)\|>)', re.IGNORECASE),  # LLM injection keywords
]

# PII patterns
EMAIL_PATTERN = re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b')
PHONE_PATTERN = re.compile(r'(?:\+?\d[\d\s\-().]{7,}\d)')
GPS_TEXT_PATTERN = re.compile(r'\b\d{1,3}\.\d+[NS]?\s*[,/]\s*\d{1,3}\.\d+[EW]?\b')
NAME_PATTERN = re.compile(r'\b(?:Mr\.?|Mrs\.?|Ms\.?|Dr\.?|Prof\.?)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+\b')

# Singapore-specific PII patterns
NRIC_FIN_PATTERN = re.compile(r'\b[STFGM]\d{7}[A-Z]\b', re.IGNORECASE)
SG_PASSPORT_PATTERN = re.compile(r'\bE\d{7}[A-Z]\b', re.IGNORECASE)
SG_MOBILE_PATTERN = re.compile(r'\b(?:\+65[\s\-]?)?[689]\d{3}[\s\-]?\d{4}\b')
SG_POSTAL_PATTERN = re.compile(r'\bSingapore\s+\d{6}\b', re.IGNORECASE)
DOB_PATTERN = re.compile(r'\b(?:\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}|\d{4}[/\-]\d{2}[/\-]\d{2})\b')


class ImageParser:
    """
    Parses image files and extracts metadata with security scanning.
    """

    def __init__(self):
        pass

    def sanitize_text_field(self, value: str) -> str:
        """
        Detect and strip prompt injection patterns from EXIF text values.
        Removes base64-encoded blobs, shell commands, invisible/zero-width characters,
        leetspeak instruction phrases, and common LLM injection keywords.
        """
        if not isinstance(value, str):
            return value

        # Remove invisible/zero-width characters
        cleaned = INJECTION_PATTERNS[2].sub('', value)

        # Check for and neutralize base64 blobs
        def replace_base64(m):
            blob = m.group(0)
            # Try to decode and check if it contains injection patterns
            try:
                decoded = base64.b64decode(blob + '==').decode('utf-8', errors='ignore')
                for pat in INJECTION_PATTERNS[3:]:
                    if pat.search(decoded):
                        return '[REDACTED_BASE64]'
                # Also check the raw blob for injection keywords
                for pat in INJECTION_PATTERNS[3:]:
                    if pat.search(blob):
                        return '[REDACTED_BASE64]'
            except Exception:
                pass
            # If it's a very long base64 blob, redact it
            if len(blob) > 60:
                return '[REDACTED_BASE64]'
            return blob

        cleaned = INJECTION_PATTERNS[0].sub(replace_base64, cleaned)

        # Remove shell commands
        cleaned = INJECTION_PATTERNS[1].sub('[REDACTED_CMD]', cleaned)

        # Remove leetspeak instruction phrases
        cleaned = INJECTION_PATTERNS[3].sub('[REDACTED]', cleaned)

        # Remove LLM injection keywords/phrases
        cleaned = INJECTION_PATTERNS[4].sub('[REDACTED_INJECTION]', cleaned)

        return cleaned

    def _redact_pii(self, text: str) -> str:
        """
        Redact PII patterns from text including emails, phone numbers,
        GPS coordinates, personal names, and Singapore-specific PII.
        """
        if not isinstance(text, str):
            return text

        # Redact Singapore-specific PII first (higher priority)
        text = NRIC_FIN_PATTERN.sub('[REDACTED_NRIC/FIN]', text)
        text = SG_PASSPORT_PATTERN.sub('[REDACTED_PASSPORT]', text)
        text = SG_MOBILE_PATTERN.sub('[REDACTED_SG_MOBILE]', text)
        text = SG_POSTAL_PATTERN.sub('[REDACTED_SG_ADDRESS]', text)
        text = DOB_PATTERN.sub('[REDACTED_DOB]', text)

        # Redact general PII
        text = EMAIL_PATTERN.sub('[REDACTED_EMAIL]', text)
        text = PHONE_PATTERN.sub('[REDACTED_PHONE]', text)
        text = GPS_TEXT_PATTERN.sub('[REDACTED_GPS]', text)
        text = NAME_PATTERN.sub('[REDACTED_NAME]', text)

        return text

    def _check_singapore_pii(self, text: str) -> bool:
        """
        Check if text contains Singapore-specific PII patterns.
        Returns True if Singapore PII is detected.
        """
        if not isinstance(text, str):
            return False
        patterns = [NRIC_FIN_PATTERN, SG_PASSPORT_PATTERN, SG_MOBILE_PATTERN, SG_POSTAL_PATTERN]
        for pat in patterns:
            if pat.search(text):
                return True
        return False

    def _strip_gps_fields(self, metadata: dict) -> dict:
        """
        Remove GPS-related fields from metadata dict.
        """
        return {k: v for k, v in metadata.items() if k not in GPS_TAGS}

    async def extract_metadata(self, image_bytes: bytes) -> dict:
        """
        Extract EXIF and other metadata from image.
        GPS fields are stripped and text values are sanitized.
        """
        try:
            from PIL import Image
            from PIL.ExifTags import TAGS

            image = Image.open(io.BytesIO(image_bytes))
            metadata = {}

            # Get basic image info
            metadata['format'] = image.format
            metadata['size'] = image.size
            metadata['mode'] = image.mode

            # Extract EXIF data
            exif_data = image._getexif()
            if exif_data:
                for tag_id, value in exif_data.items():
                    tag = TAGS.get(tag_id, tag_id)

                    # Skip GPS tags
                    if tag in GPS_TAGS:
                        continue

                    # Convert bytes to string for JSON serialization
                    if isinstance(value, bytes):
                        try:
                            value = value.decode('utf-8', errors='ignore')
                        except Exception:
                            value = str(value)

                    # Sanitize string values for prompt injection
                    if isinstance(value, str):
                        value = self.sanitize_text_field(value)
                        # Check for Singapore PII and redact
                        if self._check_singapore_pii(value):
                            logger.warning(
                                "Singapore PII detected in EXIF field, redacting",
                                extra={"field": tag}
                            )
                        value = self._redact_pii(value)

                    metadata[tag] = value

            # Strip any remaining GPS fields
            metadata = self._strip_gps_fields(metadata)

            # Log without full metadata preview
            logger.info(
                "Image metadata extracted",
                extra={
                    "format": image.format,
                    "size": image.size,
                    "exif_fields": len(metadata),
                }
            )

            return metadata

        except Exception as e:
            logger.error(f"Image metadata extraction error: {e}")
            return {"error": str(e)}

    async def extract_text_fields(self, metadata: dict) -> str:
        """
        Extract text from relevant metadata fields with injection scanning and PII redaction.
        """
        text_fields = []

        # Fields that commonly contain text content
        text_field_names = [
            'ImageDescription',
            'XPComment',
            'XPSubject',
            'XPTitle',
            'XPKeywords',
            'UserComment',
            'Comment',
            'Artist',
            'Copyright',
            'Software',
        ]

        for field in text_field_names:
            if field in metadata:
                value = metadata[field]
                if value and isinstance(value, str):
                    # Sanitize for prompt injection
                    value = self.sanitize_text_field(value)
                    # Check for Singapore PII
                    if self._check_singapore_pii(value):
                        logger.warning(
                            "Singapore PII detected in text field, redacting",
                            extra={"field": field}
                        )
                    # Redact PII
                    value = self._redact_pii(value)
                    text_fields.append(f"{field}: {value}")
                    logger.debug(
                        f"Found text in {field}",
                        extra={"field": field}
                    )

        return '\n'.join(text_fields)

    async def extract_all(self, image_bytes: bytes) -> str:
        """
        Extract all content from image for analysis.
        GPS fields are stripped, PII is redacted, and injection patterns are removed.
        """
        metadata = await self.extract_metadata(image_bytes)

        # Strip GPS fields before further processing
        metadata = self._strip_gps_fields(metadata)

        text_content = await self.extract_text_fields(metadata)

        # Redact PII from combined text content
        if text_content:
            text_content = self._redact_pii(text_content)

        result_parts = []

        if text_content:
            result_parts.append(f"Image Metadata:\n{text_content}")

        result_parts.append(f"Image Info: {metadata.get('format', 'unknown')} {metadata.get('size', 'unknown')}")

        return '\n\n'.join(result_parts)