'use client'

import { useState, useCallback } from 'react'
import { Upload, FileText, Image, File } from 'lucide-react'

interface FileUploadProps {
  onFilesSelected: (files: File[]) => void
}

export function FileUpload({ onFilesSelected }: FileUploadProps) {
  const [isDragOver, setIsDragOver] = useState(false)

  const handleDrop = useCallback(
    (e: React.DragEvent<HTMLDivElement>) => {
      e.preventDefault()
      setIsDragOver(false)

      const files = Array.from(e.dataTransfer.files)
      const validFiles = files.filter(isValidFileType)

      if (validFiles.length > 0) {
        onFilesSelected(validFiles)
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
    (e: React.ChangeEvent<HTMLInputElement>) => {
      if (e.target.files) {
        const files = Array.from(e.target.files)
        const validFiles = files.filter(isValidFileType)

        if (validFiles.length > 0) {
          onFilesSelected(validFiles)
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
