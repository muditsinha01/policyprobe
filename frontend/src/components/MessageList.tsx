'use client'

import { Message } from './ChatInterface'
import { ErrorDisplay } from './ErrorDisplay'
import { Paperclip } from 'lucide-react'

interface MessageListProps {
  messages: Message[]
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
                  ? 'bg-slate-900 text-white'
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
                    ? 'border-slate-900 bg-slate-900 text-white'
                    : 'border-slate-200 bg-white text-slate-900 shadow-[0_12px_30px_rgba(148,163,184,0.14)]'
                }`}
              >
              {message.attachments && message.attachments.length > 0 && (
                  <div className="mb-3 flex flex-wrap gap-2">
                  {message.attachments.map((attachment) => (
                    <div
                      key={attachment.id}
                        className={`flex items-center gap-2 rounded-full border px-3 py-1.5 text-sm ${
                          message.role === 'user'
                            ? 'border-slate-700 bg-slate-800 text-slate-100'
                            : 'border-slate-200 bg-slate-50 text-slate-600'
                        }`}
                    >
                        <Paperclip className="h-4 w-4 opacity-70" />
                        <span className="max-w-[180px] truncate">{attachment.name}</span>
                        <span className="text-xs opacity-60">
                        ({formatFileSize(attachment.size)})
                      </span>
                    </div>
                  ))}
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
