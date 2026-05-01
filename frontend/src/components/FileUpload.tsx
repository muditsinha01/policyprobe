'use client'

import { useState, useCallback } from 'react'
import { Upload, FileText, Image, File } from 'lucide-react'

interface FileUploadProps {
  onFilesSelected: (files: File[]) => void
}

const MAX_FILE_SIZE = 10 * 1024 * 1024 // 10 MB

const FILE_MAGIC_BYTES: Record<string, number[][]> = {
  'application/pdf': [[0x25, 0x50, 0x44, 0x46]],
  'image/jpeg': [[0xff, 0xd8, 0xff]],
  'image/png': [[0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]],
  'application/msword': [[0xd0, 0xcf, 0x11, 0xe0]],
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document': [
    [0x50, 0x4b, 0x03, 0x04],
  ],
}

const TEXT_BASED_TYPES = [
  'text/html',
  'text/plain',
  'application/json',
]

const TEXT_BASED_EXTENSIONS = ['.html', '.htm', '.txt', '.json']

const PROMPT_INJECTION_PATTERNS = [
  /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)/i,
  /you\s+are\s+now\s+(a\s+)?/i,
  /disregard\s+(all\s+)?(previous|prior|above)/i,
  /forget\s+(all\s+)?(previous|prior|above|your)/i,
  /new\s+instructions?:/i,
  /system\s*:\s*/i,
  /\[INST\]/i,
  /<<SYS>>/i,
  /act\s+as\s+(a\s+)?/i,
  /pretend\s+(you\s+are|to\s+be)/i,
  /jailbreak/i,
  /bypass\s+(your\s+)?(safety|filter|restriction|guideline)/i,
  /override\s+(your\s+)?(instruction|directive|rule)/i,
]

const SCRIPT_TAG_PATTERN = /<script[\s\S]*?>[\s\S]*?<\/script>/gi
const NULL_BYTE_PATTERN = /\x00/g

// Hidden/invisible text patterns
const ZERO_WIDTH_CHARS = /[\u200b\u200c\u200d\u200e\u200f\ufeff\u00ad]/g
const TINY_FONT_PATTERN = /<font[^>]+size\s*=\s*["']?[01]["']?[^>]*>/gi
const WHITE_ON_WHITE_PATTERN = /color\s*:\s*(?:white|#fff(?:fff)?|rgb\s*\(\s*255\s*,\s*255\s*,\s*255\s*\))/gi

// Base64 blob pattern (long base64 strings that could hide content)
const BASE64_BLOB_PATTERN = /[A-Za-z0-9+/]{100,}={0,2}/g

// Leetspeak injection patterns
const LEETSPEAK_INJECTION_PATTERN = /[1!][Gg][Nn][0Oo][Rr][Ee]|[Ii][Gg][Nn][0Oo][Rr][3Ee]/i

// Binary/shell command signatures
const SHELL_COMMAND_PATTERN = /(?:^|\s)(?:bash|sh|cmd|powershell|exec|eval|system|popen)\s*[(\s]/i
const SHEBANG_PATTERN = /^#!\s*\/(?:bin|usr)/

// PII patterns (general)
const PII_PATTERNS = {
  email: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g,
  phone: /(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/g,
  ssn: /\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b/g,
  creditCard: /\b(?:\d{4}[-\s]?){3}\d{4}\b/g,
}

// Singapore PII patterns
const SG_PII_PATTERNS = {
  nric: /\b[STFGM]\d{7}[A-Z]\b/gi,
  sgPhone: /\b(?:\+65[-\s]?)?[689]\d{3}[-\s]?\d{4}\b/g,
  passport: /\b[A-Z]\d{7}[A-Z]?\b/g,
  bankAccount: /\b\d{3}[-\s]?\d{5}[-\s]?\d{3}\b/g,
  sgAddress: /\b(?:blk|block|lot)\s+\d+[a-z]?\s+\w+/gi,
  dateOfBirth: /\b(?:\d{1,2}[-\/]\d{1,2}[-\/]\d{2,4}|\d{4}[-\/]\d{1,2}[-\/]\d{1,2})\b/g,
}

function isTextBasedFile(file: File): boolean {
  return (
    TEXT_BASED_TYPES.includes(file.type) ||
    TEXT_BASED_EXTENSIONS.some(ext => file.name.toLowerCase().endsWith(ext))
  )
}

function isImageFile(file: File): boolean {
  return file.type === 'image/jpeg' || file.type === 'image/png'
}

async function validateMagicBytes(file: File): Promise<boolean> {
  const knownMagic = FILE_MAGIC_BYTES[file.type]
  if (!knownMagic) {
    // For types we don't have magic bytes for (text types), skip binary check
    return true
  }

  const buffer = await file.slice(0, 16).arrayBuffer()
  const bytes = new Uint8Array(buffer)

  return knownMagic.some(magic =>
    magic.every((byte, index) => bytes[index] === byte)
  )
}

async function scanFileForMaliciousContent(file: File): Promise<{ safe: boolean; reason?: string }> {
  if (!isTextBasedFile(file)) {
    return { safe: true }
  }

  let content: string
  try {
    content = await file.text()
  } catch {
    return { safe: false, reason: 'Could not read file content' }
  }

  // Check for null bytes
  if (NULL_BYTE_PATTERN.test(content)) {
    NULL_BYTE_PATTERN.lastIndex = 0
    return { safe: false, reason: 'File contains null bytes' }
  }
  NULL_BYTE_PATTERN.lastIndex = 0

  // Check for script tags
  if (SCRIPT_TAG_PATTERN.test(content)) {
    SCRIPT_TAG_PATTERN.lastIndex = 0
    return { safe: false, reason: 'File contains script tags' }
  }
  SCRIPT_TAG_PATTERN.lastIndex = 0

  // Check for zero-width/invisible characters
  if (ZERO_WIDTH_CHARS.test(content)) {
    ZERO_WIDTH_CHARS.lastIndex = 0
    return { safe: false, reason: 'File contains hidden/invisible characters' }
  }
  ZERO_WIDTH_CHARS.lastIndex = 0

  // Check for tiny font tags (hidden text)
  if (TINY_FONT_PATTERN.test(content)) {
    TINY_FONT_PATTERN.lastIndex = 0
    return { safe: false, reason: 'File contains hidden text patterns' }
  }
  TINY_FONT_PATTERN.lastIndex = 0

  // Check for white-on-white text
  if (WHITE_ON_WHITE_PATTERN.test(content)) {
    WHITE_ON_WHITE_PATTERN.lastIndex = 0
    return { safe: false, reason: 'File contains hidden text (white-on-white)' }
  }
  WHITE_ON_WHITE_PATTERN.lastIndex = 0

  // Check for large base64 blobs
  const base64Matches = content.match(BASE64_BLOB_PATTERN)
  if (base64Matches && base64Matches.length > 0) {
    return { safe: false, reason: 'File contains suspicious base64-encoded content' }
  }

  // Check for leetspeak injection
  if (LEETSPEAK_INJECTION_PATTERN.test(content)) {
    return { safe: false, reason: 'File contains suspicious leetspeak patterns' }
  }

  // Check for shell command signatures
  if (SHELL_COMMAND_PATTERN.test(content) || SHEBANG_PATTERN.test(content)) {
    return { safe: false, reason: 'File contains shell command signatures' }
  }

  // Check for prompt injection patterns
  for (const pattern of PROMPT_INJECTION_PATTERNS) {
    if (pattern.test(content)) {
      return { safe: false, reason: 'File contains prompt injection patterns' }
    }
  }

  return { safe: true }
}

async function scanForSingaporePII(file: File): Promise<{ hasPII: boolean; types?: string[] }> {
  if (isImageFile(file)) {
    return { hasPII: false }
  }

  if (!isTextBasedFile(file)) {
    return { hasPII: false }
  }

  let content: string
  try {
    content = await file.text()
  } catch {
    return { hasPII: false }
  }

  const detectedTypes: string[] = []

  if (SG_PII_PATTERNS.nric.test(content)) {
    detectedTypes.push('NRIC/FIN number')
  }
  SG_PII_PATTERNS.nric.lastIndex = 0

  if (SG_PII_PATTERNS.sgPhone.test(content)) {
    detectedTypes.push('Singapore phone number')
  }
  SG_PII_PATTERNS.sgPhone.lastIndex = 0

  if (SG_PII_PATTERNS.passport.test(content)) {
    detectedTypes.push('passport number')
  }
  SG_PII_PATTERNS.passport.lastIndex = 0

  if (SG_PII_PATTERNS.bankAccount.test(content)) {
    detectedTypes.push('bank account number')
  }
  SG_PII_PATTERNS.bankAccount.lastIndex = 0

  if (SG_PII_PATTERNS.sgAddress.test(content)) {
    detectedTypes.push('Singapore address')
  }
  SG_PII_PATTERNS.sgAddress.lastIndex = 0

  if (SG_PII_PATTERNS.dateOfBirth.test(content)) {
    detectedTypes.push('date of birth')
  }
  SG_PII_PATTERNS.dateOfBirth.lastIndex = 0

  if (detectedTypes.length > 0) {
    return { hasPII: true, types: detectedTypes }
  }

  return { hasPII: false }
}

async function redactPIIFromFile(file: File): Promise<File> {
  if (isImageFile(file)) {
    return file
  }

  if (!isTextBasedFile(file)) {
    return file
  }

  let content: string
  try {
    content = await file.text()
  } catch {
    return file
  }

  let redacted = content
  redacted = redacted.replace(PII_PATTERNS.email, '[REDACTED_EMAIL]')
  redacted = redacted.replace(PII_PATTERNS.ssn, '[REDACTED_SSN]')
  redacted = redacted.replace(PII_PATTERNS.creditCard, '[REDACTED_CREDIT_CARD]')
  redacted = redacted.replace(PII_PATTERNS.phone, '[REDACTED_PHONE]')

  if (redacted === content) {
    return file
  }

  return new File([redacted], file.name, { type: file.type, lastModified: file.lastModified })
}

async function validateAndSanitizeFiles(
  files: File[],
  onFilesSelected: (files: File[]) => void
): Promise<void> {
  const rejectedFiles: { name: string; reason: string }[] = []
  const validatedFiles: File[] = []

  for (const file of files) {
    // Check file size
    if (file.size > MAX_FILE_SIZE) {
      rejectedFiles.push({ name: file.name, reason: 'File exceeds maximum size of 10 MB' })
      continue
    }

    // Validate magic bytes
    const magicValid = await validateMagicBytes(file)
    if (!magicValid) {
      rejectedFiles.push({ name: file.name, reason: 'File type does not match its declared type' })
      continue
    }

    // Scan for malicious content
    const maliciousScan = await scanFileForMaliciousContent(file)
    if (!maliciousScan.safe) {
      rejectedFiles.push({ name: file.name, reason: maliciousScan.reason || 'File contains malicious content' })
      continue
    }

    // Scan for Singapore PII
    const sgPIIScan = await scanForSingaporePII(file)
    if (sgPIIScan.hasPII) {
      rejectedFiles.push({
        name: file.name,
        reason: `File contains Singapore PII: ${sgPIIScan.types?.join(', ')}`,
      })
      continue
    }

    // Redact general PII
    const sanitizedFile = await redactPIIFromFile(file)
    validatedFiles.push(sanitizedFile)
  }

  if (rejectedFiles.length > 0) {
    const messages = rejectedFiles
      .map(r => `• ${r.name}: ${r.reason}`)
      .join('\n')
    alert(`The following files were rejected:\n\n${messages}`)
  }

  if (validatedFiles.length > 0) {
    onFilesSelected(validatedFiles)
  }
}

export function FileUpload({ onFilesSelected }: FileUploadProps) {
  const [isDragOver, setIsDragOver] = useState(false)

  const handleDrop = useCallback(
    async (e: React.DragEvent<HTMLDivElement>) => {
      e.preventDefault()
      setIsDragOver(false)

      const files = Array.from(e.dataTransfer.files)
      const typeFilteredFiles = files.filter(isValidFileType)

      if (typeFilteredFiles.length > 0) {
        await validateAndSanitizeFiles(typeFilteredFiles, onFilesSelected)
      }
    },
    [onFilesSelected]
  )

  const handleDragOver = useCallback((e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault()
    setIsDragOver(true)
  }, [])

  const handleDragLeave = useCallback((e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault()
    setIsDragOver(false)
  }, [])

  const handleFileInput = useCallback(
    async (e: React.ChangeEvent<HTMLInputElement>) => {
      if (e.target.files) {
        const files = Array.from(e.target.files)
        const typeFilteredFiles = files.filter(isValidFileType)

        if (typeFilteredFiles.length > 0) {
          await validateAndSanitizeFiles(typeFilteredFiles, onFilesSelected)
        }
      }
    },
    [onFilesSelected]
  )

  return (
    <div
      className={`file-upload-zone rounded-[24px] p-6 text-center cursor-pointer ${
        isDragOver ? 'drag-over' : ''
      }`}
      onDrop={handleDrop}
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
    >
      <input
        type="file"
        multiple
        accept=".pdf,.doc,.docx,.html,.htm,.txt,.json,.jpg,.jpeg,.png"
        className="hidden"
        id="file-upload-input"
        onChange={handleFileInput}
      />
      <label htmlFor="file-upload-input" className="cursor-pointer">
        <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-2xl bg-slate-800 text-slate-200">
          <Upload className="h-6 w-6" />
        </div>
        <p className="mb-2 text-sm font-medium text-slate-100 sm:text-base">
          Drag and drop files here, or click to browse
        </p>
        <p className="mx-auto mb-4 max-w-xl text-sm text-slate-400">
          Add a document to the conversation.
        </p>
        <div className="flex flex-wrap justify-center gap-4 text-xs text-slate-500">
          <div className="flex items-center gap-1">
            <FileText className="h-4 w-4" />
            <span>PDF, DOC, HTML</span>
          </div>
          <div className="flex items-center gap-1">
            <Image className="h-4 w-4" />
            <span>JPG, PNG</span>
          </div>
          <div className="flex items-center gap-1">
            <File className="h-4 w-4" />
            <span>TXT, JSON</span>
          </div>
        </div>
      </label>
    </div>
  )
}

function isValidFileType(file: File): boolean {
  const validTypes = [
    'application/pdf',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'text/html',
    'text/plain',
    'application/json',
    'image/jpeg',
    'image/png',
  ]

  const validExtensions = ['.pdf', '.doc', '.docx', '.html', '.htm', '.txt', '.json', '.jpg', '.jpeg', '.png']

  const hasValidType = validTypes.includes(file.type)
  const hasValidExtension = validExtensions.some(ext =>
    file.name.toLowerCase().endsWith(ext)
  )

  return hasValidType || hasValidExtension
}