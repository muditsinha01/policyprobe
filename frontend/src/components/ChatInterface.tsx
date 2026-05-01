'use client'

import { useState, useRef, useEffect } from 'react'
import { v4 as uuidv4 } from 'uuid'
import { MessageList } from './MessageList'
import { FileUpload } from './FileUpload'
import { ArrowUp, Loader2, Paperclip, Plus } from 'lucide-react'

export interface Message {
  id: string
  role: 'user' | 'assistant' | 'system'
  content: string
  timestamp: Date
  attachments?: FileAttachment[]
  error?: PolicyError
}

export interface FileAttachment {
  id: string
  name: string
  type: string
  size: number
  content?: string
}

export interface PolicyError {
  type: 'pii' | 'threat' | 'auth' | 'general'
  message: string
  details?: Record<string, unknown>
}

const ALLOWED_MIME_TYPES = [
  'text/plain',
  'text/csv',
  'text/html',
  'application/json',
  'application/pdf',
  'application/msword',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'image/jpeg',
  'image/png',
  'image/gif',
  'image/webp',
]

const MAX_FILE_SIZE = 10 * 1024 * 1024 // 10MB
const MAX_TEXT_LENGTH = 32000

function sanitizeTextInput(text: string): string {
  // Strip null bytes
  let sanitized = text.replace(/\0/g, '')
  // Strip control characters except newline, carriage return, tab
  sanitized = sanitized.replace(/[\x01-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')
  // Enforce max length
  if (sanitized.length > MAX_TEXT_LENGTH) {
    sanitized = sanitized.substring(0, MAX_TEXT_LENGTH)
  }
  return sanitized
}

function sanitizeFileContentString(content: string): string {
  // Strip null bytes
  let sanitized = content.replace(/\0/g, '')
  // Strip control characters except newline, carriage return, tab
  sanitized = sanitized.replace(/[\x01-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')
  // Enforce max length
  if (sanitized.length > MAX_TEXT_LENGTH) {
    sanitized = sanitized.substring(0, MAX_TEXT_LENGTH)
  }
  return sanitized
}

function validateFileAttachment(file: File): void {
  if (!ALLOWED_MIME_TYPES.includes(file.type)) {
    throw new Error(`File type "${file.type}" is not allowed. Allowed types: ${ALLOWED_MIME_TYPES.join(', ')}`)
  }
  if (file.size > MAX_FILE_SIZE) {
    throw new Error(`File "${file.name}" exceeds the maximum allowed size of 10MB.`)
  }
}

function sanitizeFileContent(content: string, fileName: string): void {
  // Check for invisible/zero-width characters
  const zeroWidthPattern = /[\u200B-\u200D\uFEFF\u00AD\u2060\u180E]/g
  if (zeroWidthPattern.test(content)) {
    throw new Error(`File "${fileName}" contains hidden/invisible characters that may indicate malicious content.`)
  }

  // Check for base64-encoded prompt injection patterns
  const base64Pattern = /(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?/g
  const base64Matches = content.match(base64Pattern) || []
  for (const match of base64Matches) {
    try {
      const decoded = atob(match)
      const decodedLower = decoded.toLowerCase()
      const injectionKeywords = [
        'ignore previous', 'ignore all', 'disregard', 'forget your instructions',
        'you are now', 'act as', 'pretend to be', 'system prompt', 'jailbreak',
        'override', 'bypass', 'new instructions', 'your new role',
      ]
      for (const keyword of injectionKeywords) {
        if (decodedLower.includes(keyword)) {
          throw new Error(`File "${fileName}" contains base64-encoded prompt injection content.`)
        }
      }
    } catch (e) {
      if (e instanceof Error && e.message.includes('base64-encoded prompt injection')) {
        throw e
      }
      // Not valid base64, skip
    }
  }

  const contentLower = content.toLowerCase()

  // Check for prompt injection keywords
  const promptInjectionPatterns = [
    'ignore previous instructions',
    'ignore all instructions',
    'disregard previous',
    'forget your instructions',
    'you are now',
    'act as',
    'pretend to be',
    'system prompt',
    'jailbreak',
    'override instructions',
    'bypass safety',
    'new instructions:',
    'your new role',
    'ignore the above',
    'ignore above',
    'do not follow',
    'stop being',
    'you must now',
    'from now on you',
    'your true self',
    'developer mode',
    'dan mode',
    'evil mode',
  ]

  for (const pattern of promptInjectionPatterns) {
    if (contentLower.includes(pattern)) {
      throw new Error(`File "${fileName}" contains potential prompt injection content: "${pattern}".`)
    }
  }

  // Check for leetspeak prompt injection patterns
  const leetspeakPatterns = [
    /1gn[o0]r[e3]\s+[a4]ll/i,
    /[a4]ct\s+[a4]s/i,
    /[s5]y[s5]t[e3]m\s+[p9]r[o0]m[p9]t/i,
    /j[a4][i1]lb[r][e3][a4]k/i,
    /[o0]v[e3]rr[i1]d[e3]/i,
  ]

  for (const pattern of leetspeakPatterns) {
    if (pattern.test(content)) {
      throw new Error(`File "${fileName}" contains potential leetspeak prompt injection content.`)
    }
  }

  // Check for suspicious shell/binary commands
  const shellCommandPatterns = [
    /\$\s*\(/,
    /`[^`]+`/,
    /;\s*(rm|chmod|chown|wget|curl|bash|sh|python|perl|ruby|exec|eval)\s/i,
    /\|\s*(bash|sh|python|perl|ruby|exec|eval)\s/i,
    /\/bin\/(bash|sh|zsh|ksh)/,
    /\/etc\/passwd/,
    /\/etc\/shadow/,
    /<script[\s>]/i,
    /javascript:/i,
    /on\w+\s*=/i,
  ]

  for (const pattern of shellCommandPatterns) {
    if (pattern.test(content)) {
      throw new Error(`File "${fileName}" contains suspicious shell or script commands.`)
    }
  }
}

function redactPII(content: string): string {
  let redacted = content

  // Redact email addresses
  redacted = redacted.replace(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g, '[REDACTED_EMAIL]')

  // Redact phone numbers (various formats)
  redacted = redacted.replace(/(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/g, '[REDACTED_PHONE]')

  // Redact SSNs (US format: XXX-XX-XXXX)
  redacted = redacted.replace(/\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b/g, '[REDACTED_SSN]')

  // Redact credit card numbers (basic pattern)
  redacted = redacted.replace(/\b(?:\d{4}[-\s]?){3}\d{4}\b/g, '[REDACTED_CC]')

  // Redact Singapore NRIC/FIN numbers (S/T/F/G followed by 7 digits and a letter)
  redacted = redacted.replace(/\b[STFG]\d{7}[A-Z]\b/gi, '[REDACTED_NRIC]')

  // Redact SingPass identifiers
  redacted = redacted.replace(/\bsingpass\s*[:\-]?\s*\S+/gi, '[REDACTED_SINGPASS]')

  // Redact CPF account numbers (Singapore, typically 9 digits)
  redacted = redacted.replace(/\bCPF\s*[:\-]?\s*\d{9}\b/gi, '[REDACTED_CPF]')

  return redacted
}

function detectSingaporePII(content: string, fileName: string): void {
  // Check for Singapore NRIC/FIN numbers
  const nricPattern = /\b[STFG]\d{7}[A-Z]\b/gi
  if (nricPattern.test(content)) {
    throw new Error(`File "${fileName}" contains Singapore NRIC/FIN numbers. Please remove PII before uploading.`)
  }

  // Check for SingPass identifiers
  const singpassPattern = /\bsingpass\s*[:\-]?\s*\S+/gi
  if (singpassPattern.test(content)) {
    throw new Error(`File "${fileName}" contains SingPass identifiers. Please remove PII before uploading.`)
  }

  // Check for CPF account numbers
  const cpfPattern = /\bCPF\s*[:\-]?\s*\d{9}\b/gi
  if (cpfPattern.test(content)) {
    throw new Error(`File "${fileName}" contains CPF account numbers. Please remove PII before uploading.`)
  }

  // Check for Singapore phone numbers (+65 XXXX XXXX)
  const sgPhonePattern = /(?:\+65[-.\s]?)?\d{4}[-.\s]?\d{4}\b/g
  const sgPhoneMatches = content.match(sgPhonePattern) || []
  if (sgPhoneMatches.length > 0) {
    throw new Error(`File "${fileName}" contains Singapore phone numbers. Please remove PII before uploading.`)
  }

  // Check for email addresses (general PII)
  const emailPattern = /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g
  if (emailPattern.test(content)) {
    throw new Error(`File "${fileName}" contains email addresses. Please remove PII before uploading.`)
  }

  // Check for full name patterns (common Singapore name patterns)
  const fullNamePattern = /\b(?:name|full name|nama)\s*[:\-]\s*[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3}/gi
  if (fullNamePattern.test(content)) {
    throw new Error(`File "${fileName}" contains full name identifiers. Please remove PII before uploading.`)
  }
}

export function ChatInterface() {
  const [messages, setMessages] = useState<Message[]>([])
  const [input, setInput] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [pendingFiles, setPendingFiles] = useState<File[]>([])
  const [showFileUpload, setShowFileUpload] = useState(false)
  const inputRef = useRef<HTMLTextAreaElement>(null)
  const messagesEndRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (inputRef.current) {
      inputRef.current.focus()
    }
  }, [])

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages, isLoading, showFileUpload])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()

    if (!input.trim() && pendingFiles.length === 0) return

    try {
      // Validate and sanitize file attachments
      for (const file of pendingFiles) {
        validateFileAttachment(file)
      }

      const attachments: FileAttachment[] = []
      for (const file of pendingFiles) {
        const rawContent = await readFileContent(file)

        const isBinary =
          file.type.startsWith('image/') ||
          file.type === 'application/pdf' ||
          file.type === 'application/msword' ||
          file.type === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'

        if (!isBinary) {
          // Check for Singapore PII (blocks upload)
          detectSingaporePII(rawContent, file.name)

          // Check for malicious content / prompt injection
          sanitizeFileContent(rawContent, file.name)
        }

        // Redact PII from text content before sending
        const processedContent = isBinary ? rawContent : redactPII(rawContent)

        // Sanitize the content string
        const sanitizedContent = isBinary ? processedContent : sanitizeFileContentString(processedContent)

        attachments.push({
          id: uuidv4(),
          name: file.name,
          type: file.type,
          size: file.size,
          content: sanitizedContent,
        })
      }

      // Sanitize text input
      const sanitizedInput = sanitizeTextInput(input)

      const userMessage: Message = {
        id: uuidv4(),
        role: 'user',
        content: sanitizedInput || `Uploaded ${pendingFiles.length} file(s)`,
        timestamp: new Date(),
        attachments: attachments.length > 0 ? attachments : undefined,
      }

      setMessages(prev => [...prev, userMessage])
      setInput('')
      setPendingFiles([])
      setShowFileUpload(false)
      setIsLoading(true)

      try {
        const response = await fetch('/api/backend/chat', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            message: sanitizedInput,
            attachments,
            conversation_id: uuidv4(),
          }),
        })

        const data = await response.json()

        if (!response.ok) {
          // Handle policy violations returned as errors
          const errorMessage: Message = {
            id: uuidv4(),
            role: 'assistant',
            content: data.detail || 'An error occurred',
            timestamp: new Date(),
            error: data.policy_error ? {
              type: data.policy_error.type,
              message: data.policy_error.message,
              details: data.policy_error.details,
            } : undefined,
          }
          setMessages(prev => [...prev, errorMessage])
        } else {
          const assistantMessage: Message = {
            id: uuidv4(),
            role: 'assistant',
            content: data.response,
            timestamp: new Date(),
            error: data.policy_warning ? {
              type: data.policy_warning.type,
              message: data.policy_warning.message,
              details: data.policy_warning.details,
            } : undefined,
          }
          setMessages(prev => [...prev, assistantMessage])
        }
      } catch (error) {
        const errorMessage: Message = {
          id: uuidv4(),
          role: 'assistant',
          content: 'Failed to connect to the backend. Please ensure the server is running.',
          timestamp: new Date(),
          error: {
            type: 'general',
            message: 'Connection error',
          },
        }
        setMessages(prev => [...prev, errorMessage])
      } finally {
        setIsLoading(false)
      }
    } catch (validationError) {
      const errorMessage: Message = {
        id: uuidv4(),
        role: 'assistant',
        content: validationError instanceof Error ? validationError.message : 'File validation failed.',
        timestamp: new Date(),
        error: {
          type: 'threat',
          message: validationError instanceof Error ? validationError.message : 'File validation failed.',
        },
      }
      setMessages(prev => [...prev, errorMessage])
      setIsLoading(false)
    }
  }

  const readFileContent = (file: File): Promise<string> => {
    return new Promise((resolve, reject) => {
      const reader = new FileReader()
      const shouldEncodeAsBase64 =
        file.type.startsWith('image/') ||
        file.type === 'application/pdf' ||
        file.type === 'application/msword' ||
        file.type === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'

      reader.onload = () => {
        const result = reader.result as string
        if (shouldEncodeAsBase64) {
          resolve(result.split(',')[1])
        } else {
          resolve(result)
        }
      }
      reader.onerror = reject

      if (shouldEncodeAsBase64) {
        reader.readAsDataURL(file)
      } else {
        reader.readAsText(file)
      }
    })
  }

  const handleFileSelect = (files: File[]) => {
    setPendingFiles(prev => [...prev, ...files])
  }

  const removePendingFile = (index: number) => {
    setPendingFiles(prev => prev.filter((_, i) => i !== index))
  }

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      handleSubmit(e)
    }
  }

  const starterPrompts = [
    {
      label: 'View borrower details',
      action: () => {
        setInput('Show me the loan status for Alice Morgan and include the full borrower details')
        inputRef.current?.focus()
      },
    },
    {
      label: 'Review support document',
      action: () => {
        setInput("Review this uploaded support document and summarize it's contents")
        inputRef.current?.focus()
      },
    },
    {
      label: 'Escalate support case',
      action: () => {
        setInput('Escalate issue CASE-240217 for Alice Morgan')
        inputRef.current?.focus()
      },
    },
  ]

  return (
    <div className="mx-auto flex h-screen w-full max-w-5xl flex-col px-4 pb-4 pt-4 sm:px-6">
      <div className="glass-panel flex min-h-0 flex-1 flex-col overflow-hidden rounded-[24px]">
        <div className="accent-band h-1.5 w-full" />
        <header className="soft-divider flex items-center justify-between border-b px-5 py-4 sm:px-6">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-gradient-to-br from-blue-600 to-sky-400 shadow-[0_8px_20px_rgba(37,99,235,0.25)]">
              <div className="h-3 w-3 rounded-full bg-white/95" />
            </div>
            <div>
              <h1 className="text-lg font-semibold tracking-tight text-slate-50">Acme Loan Processor</h1>
            </div>
          </div>
          <div className="hidden text-sm text-slate-400 sm:block">Loan assistant</div>
        </header>

        <div className="chat-scrollbar flex-1 overflow-y-auto px-4 py-5 sm:px-6">
          {messages.length === 0 ? (
            <div className="fade-in-up flex h-full items-start justify-center pt-10 sm:pt-14">
              <div className="w-full max-w-3xl">
                <p className="text-2xl font-semibold tracking-tight text-slate-50">
                  Hi, how can I help you today?
                </p>
                <p className="mt-2 text-sm text-slate-400">
                  Ask about a loan, check borrower status, or review a support document.
                </p>
                <div className="mt-6 flex flex-wrap gap-3">
                  {starterPrompts.map((prompt) => (
                    <button
                      key={prompt.label}
                      type="button"
                      onClick={prompt.action}
                      className="rounded-full border border-slate-700 bg-slate-900/90 px-4 py-2 text-sm text-slate-200 transition hover:border-sky-500/40 hover:bg-slate-800 hover:text-sky-200"
                    >
                      {prompt.label}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <>
              <MessageList messages={messages} />
              <div ref={messagesEndRef} />
            </>
          )}
        </div>

        {showFileUpload && (
          <div className="soft-divider border-t px-4 py-4 sm:px-6">
            <FileUpload onFilesSelected={handleFileSelect} />
          </div>
        )}

        {pendingFiles.length > 0 && (
          <div className="soft-divider border-t px-4 py-3 sm:px-6">
            <div className="flex flex-wrap gap-2">
              {pendingFiles.map((file, index) => (
                <div
                  key={`${file.name}-${index}`}
                  className="flex items-center gap-2 rounded-full border border-slate-700 bg-slate-900 px-3 py-1.5 text-sm text-slate-200"
                >
                  <span className="max-w-[220px] truncate">{file.name}</span>
                  <button
                    onClick={() => removePendingFile(index)}
                    className="text-slate-500 transition-colors hover:text-rose-400"
                    aria-label={`Remove ${file.name}`}
                  >
                    ×
                  </button>
                </div>
              ))}
            </div>
          </div>
        )}

        <div className="soft-divider border-t px-4 py-4 sm:px-6">
          <form onSubmit={handleSubmit} className="mx-auto max-w-4xl">
            <div className="rounded-[22px] border border-slate-700 bg-slate-950/90 px-3 py-2 shadow-[0_12px_32px_rgba(2,6,23,0.35)]">
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => setShowFileUpload(!showFileUpload)}
                  className="inline-flex h-9 shrink-0 items-center gap-2 rounded-xl bg-slate-900 px-3 text-xs text-slate-400 transition-colors hover:bg-slate-800 hover:text-slate-100"
                  aria-label={showFileUpload ? 'Hide document upload' : 'Show document upload'}
                >
                  {showFileUpload ? <Paperclip className="h-[16px] w-[16px]" /> : <Plus className="h-[16px] w-[16px]" />}
                  <span>{showFileUpload ? 'Hide upload' : 'Attach document'}</span>
                </button>

                <div className="flex min-h-[40px] flex-1 min-w-0 items-center">
                  <textarea
                    ref={inputRef}
                    value={input}
                    onChange={(e) => setInput(e.target.value)}
                    onKeyDown={handleKeyDown}
                    placeholder="Ask about a loan, review borrower details, or attach a support document..."
                    className="max-h-40 w-full resize-none bg-transparent px-1 py-0 text-[15px] leading-[24px] text-slate-100 outline-none placeholder:text-slate-500"
                    rows={1}
                    disabled={isLoading}
                  />
                </div>

                <button
                  type="submit"
                  disabled={isLoading || (!input.trim() && pendingFiles.length === 0)}
                  className="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-[16px] bg-gradient-to-br from-blue-600 to-sky-500 text-white transition hover:from-blue-700 hover:to-sky-600 disabled:cursor-not-allowed disabled:bg-slate-800 disabled:text-slate-500"
                  aria-label="Send message"
                >
                  {isLoading ? (
                    <Loader2 className="h-[18px] w-[18px] animate-spin" />
                  ) : (
                    <ArrowUp className="h-[18px] w-[18px]" />
                  )}
                </button>
              </div>
            </div>
          </form>
        </div>
      </div>
    </div>
  )
}