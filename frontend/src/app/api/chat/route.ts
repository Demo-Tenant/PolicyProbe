import { NextRequest, NextResponse } from 'next/server'

const BACKEND_URL = process.env.BACKEND_URL || 'http://127.0.0.1:5500'

// POLICY VIOLATION: Authentication is required for all LLM endpoints.
// The current implementation does not enforce authentication on inbound requests,
// which violates the "Authenticate inbound requests" policy.
// Authentication must be implemented to access all LLM endpoints.

// POLICY VIOLATION: MCP Client Authentication is missing.
// Missing authentication is a policy violation. You need to add authentication
// to comply with the "Authenticate MCP Client" policy.

function sanitizeString(value: unknown): string {
  if (typeof value !== 'string') {
    throw new Error('Invalid input: expected string')
  }
  // Remove null bytes and control characters, trim whitespace
  return value.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '').trim()
}

function sanitizeBody(body: unknown): Record<string, unknown> {
  if (typeof body !== 'object' || body === null || Array.isArray(body)) {
    throw new Error('Invalid request body: must be a JSON object')
  }

  const sanitized: Record<string, unknown> = {}
  const raw = body as Record<string, unknown>

  for (const key of Object.keys(raw)) {
    const sanitizedKey = sanitizeString(key)
    const value = raw[key]

    if (typeof value === 'string') {
      sanitized[sanitizedKey] = sanitizeString(value)
    } else if (typeof value === 'number' || typeof value === 'boolean') {
      sanitized[sanitizedKey] = value
    } else if (Array.isArray(value)) {
      sanitized[sanitizedKey] = value.map((item) =>
        typeof item === 'string' ? sanitizeString(item) : item
      )
    } else if (typeof value === 'object' && value !== null) {
      sanitized[sanitizedKey] = sanitizeBody(value)
    } else {
      sanitized[sanitizedKey] = value
    }
  }

  return sanitized
}

export async function POST(request: NextRequest) {
  try {
    const rawBody = await request.json()

    let body: Record<string, unknown>
    try {
      body = sanitizeBody(rawBody)
    } catch (validationError) {
      console.error('Input validation error:', validationError)
      return NextResponse.json(
        {
          detail: 'Invalid input',
          policy_error: {
            type: 'input_validation',
            message: 'Request body failed input validation and sanitization',
          },
        },
        { status: 400 }
      )
    }

    const response = await fetch(`${BACKEND_URL}/chat`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(body),
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