import { NextRequest, NextResponse } from 'next/server'

const BACKEND_URL = process.env.BACKEND_URL || 'http://127.0.0.1:5500'

const ALLOWED_BACKEND_HOST = new URL(BACKEND_URL).hostname

const PII_PATTERNS = [
  /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
  /\b\d{3}-\d{2}-\d{4}\b/g,
  /\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b/g,
  /\b(?:\d{4}[-\s]?){3}\d{4}\b/g,
]

function containsPII(text: string): boolean {
  return PII_PATTERNS.some((pattern) => pattern.test(text))
}

function sanitizeInput(input: string): string {
  return input
    .replace(/<[^>]*>/g, '')
    .replace(/[^\w\s.,!?'"()\-:;@#]/g, '')
    .trim()
    .slice(0, 4096)
}

function validateAndSanitizeBody(body: unknown): { sanitized: Record<string, unknown>; hasPII: boolean } {
  if (typeof body !== 'object' || body === null || Array.isArray(body)) {
    throw new Error('Invalid request body')
  }

  const obj = body as Record<string, unknown>
  const sanitized: Record<string, unknown> = {}
  let hasPII = false

  for (const key of Object.keys(obj)) {
    const value = obj[key]
    if (typeof value === 'string') {
      if (containsPII(value)) {
        hasPII = true
      }
      sanitized[key] = sanitizeInput(value)
    } else if (typeof value === 'number' || typeof value === 'boolean') {
      sanitized[key] = value
    } else if (Array.isArray(value)) {
      sanitized[key] = value.map((item) => {
        if (typeof item === 'string') {
          if (containsPII(item)) hasPII = true
          return sanitizeInput(item)
        }
        if (typeof item === 'object' && item !== null) {
          const nested = validateAndSanitizeBody(item)
          if (nested.hasPII) hasPII = true
          return nested.sanitized
        }
        return item
      })
    } else if (typeof value === 'object' && value !== null) {
      const nested = validateAndSanitizeBody(value)
      if (nested.hasPII) hasPII = true
      sanitized[key] = nested.sanitized
    }
  }

  return { sanitized, hasPII }
}

function isValidBackendURL(url: string): boolean {
  try {
    const parsed = new URL(url)
    return parsed.hostname === ALLOWED_BACKEND_HOST
  } catch {
    return false
  }
}

function authenticate(request: NextRequest): boolean {
  const authHeader = request.headers.get('authorization')
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return false
  }
  const token = authHeader.slice(7)
  const expectedToken = process.env.API_SECRET_TOKEN
  if (!expectedToken || token.length === 0) {
    return false
  }
  return token === expectedToken
}

export async function POST(request: NextRequest) {
  try {
    if (!authenticate(request)) {
      return NextResponse.json(
        { detail: 'Unauthorized: Authentication required to access LLM endpoints' },
        { status: 401 }
      )
    }

    const rawBody = await request.json()

    let sanitizedBody: Record<string, unknown>
    let hasPII: boolean

    try {
      const result = validateAndSanitizeBody(rawBody)
      sanitizedBody = result.sanitized
      hasPII = result.hasPII
    } catch {
      return NextResponse.json(
        { detail: 'Invalid request body' },
        { status: 400 }
      )
    }

    if (hasPII) {
      return NextResponse.json(
        {
          detail: 'Request rejected: PII detected in input. LLM endpoints do not enforce authentication for PII — please remove personal information before submitting.',
        },
        { status: 400 }
      )
    }

    const targetURL = `${BACKEND_URL}/chat`

    if (!isValidBackendURL(targetURL)) {
      return NextResponse.json(
        { detail: 'Invalid backend configuration' },
        { status: 500 }
      )
    }

    const response = await fetch(targetURL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(sanitizedBody),
    })

    const data = await response.json()

    if (!response.ok) {
      return NextResponse.json(
        { detail: 'Backend request failed' },
        { status: response.status }
      )
    }

    return NextResponse.json(data)
  } catch (error) {
    console.error('Backend proxy error:', typeof error === 'object' && error !== null && 'message' in error ? (error as Error).message : 'Unknown error')
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