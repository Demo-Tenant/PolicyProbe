import { NextRequest, NextResponse } from 'next/server'

const BACKEND_URL = process.env.BACKEND_URL || 'http://127.0.0.1:5500'
const API_SECRET = process.env.API_SECRET || ''

// ── PII redaction ──────────────────────────────────────────────────────────────
const PII_PATTERNS: Array<{ name: string; pattern: RegExp; replacement: string }> = [
  { name: 'SSN', pattern: /\b\d{3}-\d{2}-\d{4}\b/g, replacement: '[REDACTED-SSN]' },
  { name: 'CreditCard', pattern: /\b(?:\d[ -]?){13,16}\b/g, replacement: '[REDACTED-CC]' },
  { name: 'Email', pattern: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g, replacement: '[REDACTED-EMAIL]' },
  { name: 'Phone', pattern: /\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g, replacement: '[REDACTED-PHONE]' },
  { name: 'Passport', pattern: /\b[A-Z]{1,2}\d{6,9}\b/g, replacement: '[REDACTED-PASSPORT]' },
  { name: 'DriversLicense', pattern: /\b[A-Z]{1,2}\d{5,8}\b/g, replacement: '[REDACTED-DL]' },
  { name: 'TIN', pattern: /\b\d{2}-\d{7}\b/g, replacement: '[REDACTED-TIN]' },
  { name: 'FinancialAccount', pattern: /\b\d{8,17}\b/g, replacement: '[REDACTED-ACCT]' },
  { name: 'IPAddress', pattern: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g, replacement: '[REDACTED-IP]' },
  { name: 'MACAddress', pattern: /\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b/g, replacement: '[REDACTED-MAC]' },
  { name: 'VIN', pattern: /\b[A-HJ-NPR-Z0-9]{17}\b/g, replacement: '[REDACTED-VIN]' },
  { name: 'YearOfBirth', pattern: /\bborn\s+(?:in\s+)?(19|20)\d{2}\b/gi, replacement: '[REDACTED-YOB]' },
  { name: 'HomeAddress', pattern: /\b\d{1,5}\s+\w+(?:\s+\w+){0,3}\s+(?:St|Ave|Blvd|Rd|Dr|Ln|Way|Ct|Pl|Terr|Ter|Circle|Cir|Court|Lane|Road|Drive|Street|Avenue|Boulevard)\.?\b/gi, replacement: '[REDACTED-ADDRESS]' },
]

function redactPII(text: string): string {
  let redacted = text
  for (const { pattern, replacement } of PII_PATTERNS) {
    redacted = redacted.replace(pattern, replacement)
  }
  return redacted
}

// ── Dangerous code-execution primitive detection ───────────────────────────────
const DANGEROUS_LINE_PATTERNS = [
  /\beval\s*\(/i,
  /\bexec\s*\(/i,
  /\bsubprocess\s*\.\s*\w*\s*\(.*shell\s*=\s*True/i,
  /\bos\.system\s*\(/i,
  /\bspawn\s*\(/i,
  /\bpopen\s*\(/i,
  /\bnew\s+Function\s*\(/i,
  /\bsetTimeout\s*\(\s*["'`]/i,
  /\bsetInterval\s*\(\s*["'`]/i,
]

function sanitizeLLMResponse(text: string): string {
  const lines = text.split('\n')
  const filtered = lines.filter(line => !DANGEROUS_LINE_PATTERNS.some(p => p.test(line)))
  return filtered.join('\n')
}

// ── Prompt injection / suspicious input detection ─────────────────────────────
const BASE64_PATTERN = /(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?/g
const BINARY_PATTERN = /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/
const LEET_PATTERN = /(?:[e3][v\/][a@][l1]|[e3][x><][e3][c<])/i
const INVISIBLE_CHARS_PATTERN = /[\u200b-\u200f\u202a-\u202e\ufeff\u00ad]/
const SHELL_CMD_PATTERN = /(?:rm\s+-rf|chmod\s+\d+|wget\s+http|curl\s+http|bash\s+-[ci]|sh\s+-[ci]|\/bin\/sh|\/bin\/bash|cmd\.exe|powershell)/i
const HIDDEN_PROMPT_PATTERN = /(?:ignore\s+(?:all\s+)?(?:previous|above|prior)\s+instructions?|you\s+are\s+now|disregard\s+(?:all\s+)?(?:previous|above)|act\s+as\s+(?:a\s+)?(?:different|new)|forget\s+(?:all\s+)?(?:previous|your))/i

function isSuspiciousPrompt(text: string): { suspicious: boolean; reason: string } {
  if (BINARY_PATTERN.test(text)) {
    return { suspicious: true, reason: 'Binary or control characters detected in prompt' }
  }
  if (INVISIBLE_CHARS_PATTERN.test(text)) {
    return { suspicious: true, reason: 'Invisible or zero-width characters detected in prompt' }
  }
  if (LEET_PATTERN.test(text)) {
    return { suspicious: true, reason: 'Leetspeak obfuscation detected in prompt' }
  }
  if (SHELL_CMD_PATTERN.test(text)) {
    return { suspicious: true, reason: 'Shell command detected in prompt' }
  }
  if (HIDDEN_PROMPT_PATTERN.test(text)) {
    return { suspicious: true, reason: 'Hidden or injection prompt pattern detected' }
  }
  // Check for suspicious base64 blobs (long encoded strings)
  const b64Matches = text.match(BASE64_PATTERN) || []
  for (const match of b64Matches) {
    if (match.length > 100) {
      try {
        const decoded = Buffer.from(match, 'base64').toString('utf-8')
        if (SHELL_CMD_PATTERN.test(decoded) || HIDDEN_PROMPT_PATTERN.test(decoded)) {
          return { suspicious: true, reason: 'Base64-encoded suspicious content detected in prompt' }
        }
      } catch {
        // ignore decode errors
      }
    }
  }
  return { suspicious: false, reason: '' }
}

// ── Input sanitization ────────────────────────────────────────────────────────
function sanitizeInput(text: string): string {
  // Remove null bytes and control characters (except common whitespace)
  let sanitized = text.replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, '')
  // Remove invisible/zero-width characters
  sanitized = sanitized.replace(/[\u200b-\u200f\u202a-\u202e\ufeff\u00ad]/g, '')
  // Trim excessive whitespace
  sanitized = sanitized.trim()
  return sanitized
}

// ── Logging ───────────────────────────────────────────────────────────────────
function logInteraction(entry: Record<string, unknown>): void {
  console.log(JSON.stringify({ timestamp: new Date().toISOString(), ...entry }))
}

// ── Authentication ────────────────────────────────────────────────────────────
function isAuthenticated(request: NextRequest): boolean {
  const authHeader = request.headers.get('authorization')
  if (!authHeader) return false
  // Support Bearer token scheme
  const parts = authHeader.split(' ')
  if (parts.length === 2 && parts[0].toLowerCase() === 'bearer') {
    return parts[1] === API_SECRET && API_SECRET.length > 0
  }
  return false
}

export async function POST(request: NextRequest) {
  // ── Authentication check ───────────────────────────────────────────────────
  if (!isAuthenticated(request)) {
    logInteraction({ event: 'auth_failure', message: 'Unauthenticated request rejected' })
    return NextResponse.json(
      { detail: 'Authentication required. LLM endpoints enforce authentication per policy.' },
      { status: 401 }
    )
  }

  try {
    const body = await request.json()

    // ── Validate body structure ────────────────────────────────────────────────
    if (!body || typeof body !== 'object') {
      return NextResponse.json({ detail: 'Invalid request body' }, { status: 400 })
    }

    // ── Extract and validate the prompt/message ────────────────────────────────
    const rawMessage: string =
      typeof body.message === 'string'
        ? body.message
        : typeof body.prompt === 'string'
        ? body.prompt
        : ''

    // ── Suspicious prompt check ────────────────────────────────────────────────
    if (rawMessage) {
      const suspicion = isSuspiciousPrompt(rawMessage)
      if (suspicion.suspicious) {
        logInteraction({ event: 'prompt_blocked', reason: suspicion.reason })
        return NextResponse.json(
          { detail: `Request blocked: ${suspicion.reason}` },
          { status: 400 }
        )
      }
    }

    // ── Sanitize input ─────────────────────────────────────────────────────────
    const sanitizedBody = { ...body }
    if (typeof sanitizedBody.message === 'string') {
      sanitizedBody.message = sanitizeInput(sanitizedBody.message)
    }
    if (typeof sanitizedBody.prompt === 'string') {
      sanitizedBody.prompt = sanitizeInput(sanitizedBody.prompt)
    }

    // ── Redact PII before sending to LLM ──────────────────────────────────────
    if (typeof sanitizedBody.message === 'string') {
      sanitizedBody.message = redactPII(sanitizedBody.message)
    }
    if (typeof sanitizedBody.prompt === 'string') {
      sanitizedBody.prompt = redactPII(sanitizedBody.prompt)
    }

    logInteraction({ event: 'llm_request', bodyKeys: Object.keys(sanitizedBody) })

    const response = await fetch(`${BACKEND_URL}/chat`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(sanitizedBody),
    })

    const data = await response.json()

    // ── Sanitize LLM response ──────────────────────────────────────────────────
    if (data && typeof data.response === 'string') {
      data.response = sanitizeLLMResponse(data.response)
    }
    if (data && typeof data.message === 'string') {
      data.message = sanitizeLLMResponse(data.message)
    }
    if (data && typeof data.content === 'string') {
      data.content = sanitizeLLMResponse(data.content)
    }

    logInteraction({ event: 'llm_response', status: response.status, ok: response.ok })

    if (!response.ok) {
      return NextResponse.json(data, { status: response.status })
    }

    return NextResponse.json(data)
  } catch (error) {
    // Avoid leaking internal error details
    console.error('Backend proxy error:', error instanceof Error ? error.message : 'Unknown error')
    logInteraction({ event: 'proxy_error', message: 'Backend proxy error occurred' })
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