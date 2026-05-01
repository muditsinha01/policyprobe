import { NextRequest, NextResponse } from 'next/server'

const BACKEND_URL = process.env.BACKEND_URL || 'http://127.0.0.1:5500'
const BACKEND_API_KEY = process.env.BACKEND_API_KEY

const MAX_MESSAGE_LENGTH = 10000

export async function POST(request: NextRequest) {
  try {
    if (!BACKEND_API_KEY) {
      console.error('BACKEND_API_KEY environment variable is not set')
      return NextResponse.json(
        {
          detail: 'Backend service misconfigured',
          policy_error: {
            type: 'general',
            message: 'Backend service unavailable',
          },
        },
        { status: 503 }
      )
    }

    const body = await request.json()

    if (!body || typeof body.message !== 'string' || body.message.trim() === '') {
      return NextResponse.json(
        {
          detail: 'Invalid request: message field is required and must be a non-empty string',
          policy_error: {
            type: 'validation',
            message: 'Missing or invalid message field',
          },
        },
        { status: 400 }
      )
    }

    if (body.message.length > MAX_MESSAGE_LENGTH) {
      return NextResponse.json(
        {
          detail: `Invalid request: message exceeds maximum length of ${MAX_MESSAGE_LENGTH} characters`,
          policy_error: {
            type: 'validation',
            message: 'Message too long',
          },
        },
        { status: 400 }
      )
    }

    const sanitizedMessage = body.message
      .replace(/<[^>]*>/g, '')
      .trim()

    const sanitizedBody: Record<string, unknown> = {
      message: sanitizedMessage,
    }

    if (body.conversation_id !== undefined && typeof body.conversation_id === 'string') {
      sanitizedBody.conversation_id = body.conversation_id
    }

    if (body.file_content !== undefined && typeof body.file_content === 'string') {
      sanitizedBody.file_content = body.file_content
    }

    if (body.file_name !== undefined && typeof body.file_name === 'string') {
      sanitizedBody.file_name = body.file_name
    }

    if (body.file_type !== undefined && typeof body.file_type === 'string') {
      sanitizedBody.file_type = body.file_type
    }

    const response = await fetch(`${BACKEND_URL}/chat`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': BACKEND_API_KEY,
      },
      body: JSON.stringify(sanitizedBody),
    })

    const data = await response.json()

    if (!response.ok) {
      return NextResponse.json(data, { status: response.status })
    }

    return NextResponse.json(data)
  } catch (error) {
    console.error('Backend proxy error:', error)
    return NextResponse.json(
      {
        detail: 'Failed to connect to backend service',
        policy_error: {
          type: 'general',
          message: 'Backend service unavailable',
        },
      },
      { status: 503 }
    )
  }
}