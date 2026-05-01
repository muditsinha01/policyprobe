'use client'

import { Message } from './ChatInterface'
import { ErrorDisplay } from './ErrorDisplay'
import { Paperclip, AlertTriangle } from 'lucide-react'

interface MessageListProps {
  messages: Message[]
}

interface MaliciousContentResult {
  isSuspicious: boolean
  reasons: string[]
}

function detectMaliciousContent(name: string, content?: string): MaliciousContentResult {
  const reasons: string[] = []

  // Check for hidden/invisible characters in attachment name
  const invisibleCharPattern = /[\u200B-\u200D\uFEFF\u00AD\u2060\u180E\u00A0]/
  if (invisibleCharPattern.test(name)) {
    reasons.push('Hidden or invisible characters detected in filename')
  }

  // Check for base64-encoded prompts in name
  const base64Pattern = /[A-Za-z0-9+/]{20,}={0,2}/
  if (base64Pattern.test(name)) {
    try {
      const decoded = atob(name.match(/[A-Za-z0-9+/]{20,}={0,2}/)?.[0] || '')
      const injectionKeywords = /ignore|prompt|system|instruction|jailbreak|bypass|override/i
      if (injectionKeywords.test(decoded)) {
        reasons.push('Base64-encoded prompt injection detected in filename')
      }
    } catch {
      // Not valid base64, ignore
    }
  }

  // Check for leetspeak patterns in name
  const leetspeakPattern = /[1!][gG][n][o0][rR][e3]|[pP][rR][o0][mM][pP][tT]|[sS][yY][sS][tT][e3][mM]/
  if (leetspeakPattern.test(name)) {
    reasons.push('Leetspeak injection pattern detected in filename')
  }

  // Check for suspicious injection patterns in name
  const injectionPatterns = [
    /ignore\s+(previous|above|all)\s+(instructions?|prompts?)/i,
    /system\s*prompt/i,
    /you\s+are\s+now/i,
    /jailbreak/i,
    /bypass\s+(safety|filter|restriction)/i,
    /override\s+(instruction|prompt|system)/i,
    /act\s+as\s+(if|a|an)/i,
    /disregard\s+(previous|all)/i,
    /\[INST\]|\[\/INST\]|<\|im_start\|>|<\|im_end\|>/i,
  ]
  for (const pattern of injectionPatterns) {
    if (pattern.test(name)) {
      reasons.push('Suspicious injection pattern detected in filename')
      break
    }
  }

  // Check for binary/shell command indicators in name
  const shellCommandPattern = /(\.\.(\/|\\)|\/etc\/|\/bin\/|cmd\.exe|powershell|bash|sh\s+-c|eval\(|exec\()/i
  if (shellCommandPattern.test(name)) {
    reasons.push('Binary or shell command indicator detected in filename')
  }

  // Check content if provided
  if (content) {
    // Check for hidden/invisible characters in content
    if (invisibleCharPattern.test(content)) {
      reasons.push('Hidden or invisible characters detected in file content')
    }

    // Check for base64-encoded prompts in content
    const base64Matches = content.match(/[A-Za-z0-9+/]{40,}={0,2}/g) || []
    for (const match of base64Matches) {
      try {
        const decoded = atob(match)
        const injectionKeywords = /ignore|prompt|system|instruction|jailbreak|bypass|override/i
        if (injectionKeywords.test(decoded)) {
          reasons.push('Base64-encoded prompt injection detected in file content')
          break
        }
      } catch {
        // Not valid base64, ignore
      }
    }

    // Check for injection patterns in content
    for (const pattern of injectionPatterns) {
      if (pattern.test(content)) {
        reasons.push('Suspicious injection pattern detected in file content')
        break
      }
    }

    // Check for leetspeak in content
    if (leetspeakPattern.test(content)) {
      reasons.push('Leetspeak injection pattern detected in file content')
    }

    // Check for shell commands in content
    if (shellCommandPattern.test(content)) {
      reasons.push('Binary or shell command indicator detected in file content')
    }
  }

  return {
    isSuspicious: reasons.length > 0,
    reasons,
  }
}

function sanitizeText(text: string): string {
  // Remove hidden/invisible characters
  return text.replace(/[\u200B-\u200D\uFEFF\u00AD\u2060\u180E]/g, '')
    .replace(/[^\x20-\x7E\u00A1-\uFFFF]/g, '')
}

export function MessageList({ messages }: MessageListProps) {
  return (
    <div className="mx-auto flex w-full max-w-4xl flex-col gap-4">
      {messages.map((message) => (
        <div
          key={message.id}
          className={`fade-in-up flex ${
            message.role === 'user' ? 'justify-end' : 'justify-start'
          }`}
        >
          <div
            className={`flex w-full max-w-3xl gap-3 ${
              message.role === 'user' ? 'flex-row-reverse' : 'flex-row'
            }`}
          >
            <div
              className={`mt-1 flex h-10 w-10 flex-shrink-0 items-center justify-center rounded-2xl ${
                message.role === 'user'
                  ? 'bg-slate-200 text-slate-900'
                  : 'bg-gradient-to-br from-blue-600 to-sky-400 text-white shadow-[0_8px_18px_rgba(37,99,235,0.2)]'
              }`}
            >
              {message.role === 'user' ? (
                <span className="text-xs font-semibold uppercase tracking-[0.18em]">You</span>
              ) : (
                <div className="h-3 w-3 rounded-full bg-white/95" />
              )}
            </div>

            <div className="min-w-0 flex-1">
              <div
                className={`overflow-hidden rounded-[24px] border px-5 py-4 shadow-[0_18px_50px_rgba(2,6,23,0.18)] ${
                  message.role === 'user'
                    ? 'border-slate-700 bg-slate-100 text-slate-900'
                    : 'border-slate-700 bg-slate-900 text-slate-100 shadow-[0_12px_30px_rgba(2,6,23,0.28)]'
                }`}
              >
              {message.attachments && message.attachments.length > 0 && (
                  <div className="mb-3 flex flex-wrap gap-2">
                  {message.attachments.map((attachment) => {
                    const maliciousCheck = detectMaliciousContent(attachment.name)
                    const safeName = sanitizeText(attachment.name)
                    return (
                      <div key={attachment.id}>
                        <div
                          className={`flex items-center gap-2 rounded-full border px-3 py-1.5 text-sm ${
                            maliciousCheck.isSuspicious
                              ? 'border-red-500 bg-red-50 text-red-700'
                              : message.role === 'user'
                              ? 'border-slate-300 bg-white text-slate-700'
                              : 'border-slate-700 bg-slate-800 text-slate-300'
                          }`}
                        >
                          {maliciousCheck.isSuspicious ? (
                            <AlertTriangle className="h-4 w-4 text-red-500 opacity-90" />
                          ) : (
                            <Paperclip className="h-4 w-4 opacity-70" />
                          )}
                          <span className="max-w-[180px] truncate">{safeName}</span>
                          <span className="text-xs opacity-60">
                            ({formatFileSize(attachment.size)})
                          </span>
                        </div>
                        {maliciousCheck.isSuspicious && (
                          <div className="mt-1 rounded-md border border-red-300 bg-red-50 px-2 py-1 text-xs text-red-600">
                            <span className="font-semibold">⚠ Suspicious content detected:</span>
                            <ul className="mt-0.5 list-inside list-disc">
                              {maliciousCheck.reasons.map((reason, idx) => (
                                <li key={idx}>{reason}</li>
                              ))}
                            </ul>
                          </div>
                        )}
                      </div>
                    )
                  })}
                  </div>
              )}

              {message.error ? (
                <ErrorDisplay error={message.error} />
              ) : (
                  <div className="message-content text-sm sm:text-[15px]">{message.content}</div>
              )}
              </div>

              <div
                className={`mt-2 px-1 text-xs text-slate-500 ${
                  message.role === 'user' ? 'text-right' : 'text-left'
                }`}
              >
                {formatTime(message.timestamp)}
              </div>
            </div>
          </div>
        </div>
      ))}
    </div>
  )
}

function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

function formatTime(date: Date): string {
  return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
}