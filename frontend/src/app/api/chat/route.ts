import { NextRequest, NextResponse } from 'next/server'

const BACKEND_URL = process.env.BACKEND_URL || 'http://127.0.0.1:5500'

// Dangerous code execution patterns to detect in LLM responses
const DANGEROUS_RESPONSE_PATTERNS = [
  /\beval\s*\(/gi,
  /\bexec\s*\(/gi,
  /\bsubprocess\s*\.\s*\w*\s*\(.*shell\s*=\s*True/gi,
  /\b__import__\s*\(/gi,
  /\bos\.system\s*\(/gi,
  /\bos\.popen\s*\(/gi,
  /\bcommand\s*\(/gi,
  /\bspawn\s*\(/gi,
  /\bnew\s+Function\s*\(/gi,
  /\bsetTimeout\s*\(\s*["'`]/gi,
  /\bsetInterval\s*\(\s*["'`]/gi,
]

// Suspicious input patterns: hidden prompts, base64, leetspeak, shell commands, binary
const SUSPICIOUS_INPUT_PATTERNS = [
  // Base64 encoded content (long base64 strings)
  /(?:[A-Za-z0-9+/]{40,}={0,2})/,
  // Shell commands
  /(\b(bash|sh|zsh|cmd|powershell|wget|curl|nc|netcat|chmod|chown|sudo|su|rm\s+-rf|mkfifo|mknod)\b)/i,
  // Binary/null bytes
  /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/,
  // Invisible/zero-width characters
  /[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]/,
  // Leetspeak patterns for common attack words
  /\b(3x3c|3v4l|ex3c|ev4l|3x3cu73|syst3m|0s\.|sh3ll)\b/i,
  // Prompt injection attempts
  /ignore\s+(previous|above|prior)\s+instructions/i,
  /system\s*:\s*(you\s+are|act\s+as|pretend)/i,
  /\[INST\]|\[\/INST\]|<\|im_start\|>|<\|im_end\|>/i,
  // Suspicious font-size or color tricks (if HTML is passed)
  /font-size\s*:\s*0/i,
  /color\s*:\s*white.*background.*white/i,
]

function sanitizeInput(input: string): { sanitized: string; suspicious: boolean } {
  let suspicious = false

  for (const pattern of SUSPICIOUS_INPUT_PATTERNS) {
    if (pattern.test(input)) {
      suspicious = true
      break
    }
  }

  // Remove null bytes and invisible characters
  const sanitized = input
    .replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, '')
    .replace(/[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]/g, '')
    .trim()

  return { sanitized, suspicious }
}

function sanitizeLLMResponse(text: string): string {
  const lines = text.split('\n')
  const sanitizedLines = lines.filter((line) => {
    for (const pattern of DANGEROUS_RESPONSE_PATTERNS) {
      pattern.lastIndex = 0
      if (pattern.test(line)) {
        console.warn('[LLM Response Sanitization] Removed dangerous line:', line)
        return false
      }
    }
    return true
  })
  return sanitizedLines.join('\n')
}

function sanitizeResponseObject(obj: unknown): unknown {
  if (typeof obj === 'string') {
    return sanitizeLLMResponse(obj)
  }
  if (Array.isArray(obj)) {
    return obj.map(sanitizeResponseObject)
  }
  if (obj !== null && typeof obj === 'object') {
    const sanitized: Record<string, unknown> = {}
    for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
      sanitized[key] = sanitizeResponseObject(value)
    }
    return sanitized
  }
  return obj
}

function logInteraction(
  requestId: string,
  stage: string,
  data: Record<string, unknown>
): void {
  const logEntry = {
    timestamp: new Date().toISOString(),
    requestId,
    stage,
    ...data,
  }
  console.log('[LLM Interaction Log]', JSON.stringify(logEntry))
}

function generateRequestId(): string {
  return `req_${Date.now()}_${Math.random().toString(36).substring(2, 11)}`
}

export async function POST(request: NextRequest) {
  const requestId = generateRequestId()

  // Authenticate inbound requests
  const authHeader = request.headers.get('authorization')
  const apiKey = process.env.API_SECRET_KEY

  if (!apiKey) {
    console.error('[Auth] API_SECRET_KEY environment variable is not set. LLM endpoints require authentication.')
    return NextResponse.json(
      {
        detail: 'Authentication is not configured. LLM endpoints do not enforce authentication, which is a violation of policy.',
        policy_error: {
          type: 'authentication',
          message: 'API authentication is required to access LLM endpoints. Please configure API_SECRET_KEY.',
        },
      },
      { status: 500 }
    )
  }

  if (!authHeader || authHeader !== `Bearer ${apiKey}`) {
    logInteraction(requestId, 'AUTH_FAILURE', { reason: 'Missing or invalid authorization header' })
    return NextResponse.json(
      {
        detail: 'Unauthorized. Valid authentication is required to access LLM endpoints.',
        policy_error: {
          type: 'authentication',
          message: 'Authentication required.',
        },
      },
      { status: 401 }
    )
  }

  try {
    const body = await request.json()

    // Sanitize and validate input
    let sanitizedBody = { ...body }
    let inputSuspicious = false

    if (typeof body.message === 'string') {
      const { sanitized, suspicious } = sanitizeInput(body.message)
      sanitizedBody.message = sanitized
      inputSuspicious = suspicious
    }

    if (typeof body.prompt === 'string') {
      const { sanitized, suspicious } = sanitizeInput(body.prompt)
      sanitizedBody.prompt = sanitized
      if (suspicious) inputSuspicious = true
    }

    if (Array.isArray(body.messages)) {
      sanitizedBody.messages = body.messages.map((msg: unknown) => {
        if (msg !== null && typeof msg === 'object') {
          const msgObj = msg as Record<string, unknown>
          if (typeof msgObj.content === 'string') {
            const { sanitized, suspicious } = sanitizeInput(msgObj.content)
            if (suspicious) inputSuspicious = true
            return { ...msgObj, content: sanitized }
          }
        }
        return msg
      })
    }

    if (inputSuspicious) {
      logInteraction(requestId, 'SUSPICIOUS_INPUT_BLOCKED', {
        reason: 'Input contained suspicious patterns (hidden prompts, shell commands, encoded content, etc.)',
      })
      return NextResponse.json(
        {
          detail: 'Request blocked: suspicious or potentially malicious content detected in input.',
          policy_error: {
            type: 'input_validation',
            message: 'Input contains disallowed content.',
          },
        },
        { status: 400 }
      )
    }

    logInteraction(requestId, 'REQUEST_SENT', {
      endpoint: `${BACKEND_URL}/chat`,
      bodyKeys: Object.keys(sanitizedBody),
    })

    const response = await fetch(`${BACKEND_URL}/chat`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(sanitizedBody),
    })

    const data = await response.json()

    if (!response.ok) {
      logInteraction(requestId, 'BACKEND_ERROR', { status: response.status })
      return NextResponse.json(data, { status: response.status })
    }

    // Sanitize LLM response
    const sanitizedData = sanitizeResponseObject(data)

    logInteraction(requestId, 'RESPONSE_RECEIVED', {
      status: response.status,
      sanitized: true,
    })

    return NextResponse.json(sanitizedData)
  } catch (error) {
    logInteraction(requestId, 'PROXY_ERROR', {
      error: error instanceof Error ? error.message : 'Unknown error',
    })
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