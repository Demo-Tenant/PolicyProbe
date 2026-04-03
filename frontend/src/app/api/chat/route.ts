import { NextRequest, NextResponse } from 'next/server'
import crypto from 'crypto'

const BACKEND_URL = process.env.BACKEND_URL || 'http://127.0.0.1:5500'
const API_SECRET = process.env.API_SECRET || ''

// PII redaction patterns
const PII_PATTERNS: { name: string; pattern: RegExp; replacement: string }[] = [
  { name: 'SSN', pattern: /\b\d{3}-\d{2}-\d{4}\b/g, replacement: '[REDACTED-SSN]' },
  { name: 'SSN_NO_DASH', pattern: /\b\d{9}\b/g, replacement: '[REDACTED-SSN]' },
  { name: 'CREDIT_CARD', pattern: /\b(?:\d[ -]?){13,16}\b/g, replacement: '[REDACTED-CC]' },
  { name: 'EMAIL', pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, replacement: '[REDACTED-EMAIL]' },
  { name: 'PHONE', pattern: /\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g, replacement: '[REDACTED-PHONE]' },
  { name: 'IP_ADDRESS', pattern: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g, replacement: '[REDACTED-IP]' },
  { name: 'MAC_ADDRESS', pattern: /\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b/g, replacement: '[REDACTED-MAC]' },
  { name: 'PASSPORT', pattern: /\b[A-Z]{1,2}\d{6,9}\b/g, replacement: '[REDACTED-PASSPORT]' },
  { name: 'DRIVERS_LICENSE', pattern: /\b[A-Z]{1,2}\d{5,8}\b/g, replacement: '[REDACTED-DL]' },
  { name: 'TIN', pattern: /\b\d{2}-\d{7}\b/g, replacement: '[REDACTED-TIN]' },
  { name: 'FINANCIAL_ACCOUNT', pattern: /\b\d{8,17}\b/g, replacement: '[REDACTED-ACCOUNT]' },
  { name: 'VIN', pattern: /\b[A-HJ-NPR-Z0-9]{17}\b/g, replacement: '[REDACTED-VIN]' },
  { name: 'HOME_ADDRESS', pattern: /\b\d{1,5}\s+\w+\s+(Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl)\b/gi, replacement: '[REDACTED-ADDRESS]' },
  { name: 'YEAR_OF_BIRTH', pattern: /\b(19|20)\d{2}\b/g, replacement: '[REDACTED-YEAR]' },
]

// Dangerous code execution patterns for LLM response sanitization
const DANGEROUS_PATTERNS: RegExp[] = [
  /\beval\s*\(/gi,
  /\bexec\s*\(/gi,
  /\bsubprocess\s*\(\s*.*shell\s*=\s*True/gi,
  /\bos\.system\s*\(/gi,
  /\bos\.popen\s*\(/gi,
  /\bexecfile\s*\(/gi,
  /\b__import__\s*\(/gi,
  /\bcompile\s*\(/gi,
  /\bexecSync\s*\(/gi,
  /\bspawnSync\s*\(/gi,
  /\bchild_process/gi,
  /\bFunction\s*\(/gi,
  /\bnew\s+Function\s*\(/gi,
  /\bsetTimeout\s*\(\s*["'`]/gi,
  /\bsetInterval\s*\(\s*["'`]/gi,
]

// Suspicious prompt injection patterns
const SUSPICIOUS_PROMPT_PATTERNS: RegExp[] = [
  // Base64 encoded content
  /[A-Za-z0-9+/]{40,}={0,2}/g,
  // Leet speak patterns
  /[4@][Ss5][Ss5][Ii1][Gg9][Nn]/g,
  // Hidden/invisible characters (zero-width, etc.)
  /[\u200B-\u200D\uFEFF\u00AD]/g,
  // Binary executable signatures
  /\x7fELF/g,
  /MZ\x90\x00/g,
  // Shell command patterns
  /\b(bash|sh|cmd|powershell|wget|curl|nc|netcat|chmod|chown|sudo|su\s)\b/gi,
  // Prompt injection attempts
  /ignore\s+(previous|prior|above|all)\s+(instructions?|prompts?|context)/gi,
  /system\s*prompt/gi,
  /\byou\s+are\s+now\b/gi,
  /\bforget\s+(everything|all|previous)\b/gi,
  /\bact\s+as\b/gi,
  /\bpretend\s+(you\s+are|to\s+be)\b/gi,
  // Suspicious HTML/script injection
  /<script\b/gi,
  /javascript:/gi,
  /on\w+\s*=/gi,
]

function redactPII(text: string): string {
  if (typeof text !== 'string') return text
  let redacted = text
  for (const { pattern, replacement } of PII_PATTERNS) {
    redacted = redacted.replace(pattern, replacement)
  }
  return redacted
}

function sanitizeLLMResponse(text: string): string {
  if (typeof text !== 'string') return text
  const lines = text.split('\n')
  const sanitized = lines.filter(line => {
    for (const pattern of DANGEROUS_PATTERNS) {
      if (pattern.test(line)) {
        console.warn(`[SECURITY] Removed dangerous pattern from LLM response: ${line.substring(0, 100)}`)
        pattern.lastIndex = 0
        return false
      }
      pattern.lastIndex = 0
    }
    return true
  })
  return sanitized.join('\n')
}

function sanitizeLLMInput(text: string): string {
  if (typeof text !== 'string') return text
  // Remove null bytes and control characters
  let sanitized = text.replace(/\0/g, '').replace(/[\x01-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')
  // Remove invisible/hidden characters
  sanitized = sanitized.replace(/[\u200B-\u200D\uFEFF\u00AD]/g, '')
  // Trim excessive whitespace
  sanitized = sanitized.trim()
  return sanitized
}

function detectSuspiciousPrompt(text: string): { suspicious: boolean; reason: string } {
  if (typeof text !== 'string') return { suspicious: false, reason: '' }

  // Check for invisible/hidden characters
  if (/[\u200B-\u200D\uFEFF\u00AD]/.test(text)) {
    return { suspicious: true, reason: 'Hidden/invisible characters detected' }
  }

  // Check for binary executable signatures
  if (/\x7fELF/.test(text) || /MZ\x90\x00/.test(text)) {
    return { suspicious: true, reason: 'Binary executable content detected' }
  }

  // Check for base64 encoded content (long base64 strings)
  const base64Matches = text.match(/[A-Za-z0-9+/]{60,}={0,2}/g)
  if (base64Matches && base64Matches.length > 0) {
    return { suspicious: true, reason: 'Potential base64 encoded content detected' }
  }

  // Check for leet speak
  const leetPattern = /[4@][Ss5][Ss5][Ii1][Gg9][Nn]|[Hh][4@][Cc][Kk]|[Ee][Xx][Pp][Ll][0o][Ii1][Tt]/g
  if (leetPattern.test(text)) {
    return { suspicious: true, reason: 'Leet speak detected' }
  }

  // Check for prompt injection attempts
  const injectionPatterns = [
    /ignore\s+(previous|prior|above|all)\s+(instructions?|prompts?|context)/gi,
    /system\s*prompt/gi,
    /\byou\s+are\s+now\b/gi,
    /\bforget\s+(everything|all|previous)\b/gi,
    /\bact\s+as\b/gi,
    /\bpretend\s+(you\s+are|to\s+be)\b/gi,
  ]
  for (const pattern of injectionPatterns) {
    if (pattern.test(text)) {
      return { suspicious: true, reason: 'Prompt injection attempt detected' }
    }
  }

  // Check for shell commands
  if (/\b(bash|sh|cmd|powershell|wget|curl|nc|netcat|chmod|chown|sudo)\b/gi.test(text)) {
    return { suspicious: true, reason: 'Shell command detected in prompt' }
  }

  // Check for script injection
  if (/<script\b/gi.test(text) || /javascript:/gi.test(text)) {
    return { suspicious: true, reason: 'Script injection detected' }
  }

  return { suspicious: false, reason: '' }
}

function validateAuthentication(request: NextRequest): boolean {
  const authHeader = request.headers.get('authorization')
  const apiKey = request.headers.get('x-api-key')

  if (API_SECRET) {
    if (authHeader) {
      const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : authHeader
      if (crypto.timingSafeEqual(Buffer.from(token), Buffer.from(API_SECRET))) {
        return true
      }
    }
    if (apiKey) {
      if (crypto.timingSafeEqual(Buffer.from(apiKey), Buffer.from(API_SECRET))) {
        return true
      }
    }
    return false
  }

  // If no API_SECRET configured, log warning but allow (development mode)
  console.warn('[SECURITY] WARNING: No API_SECRET configured. Authentication is not enforced. This violates security policy for LLM endpoints.')
  return true
}

function logLLMInteraction(
  requestId: string,
  phase: 'REQUEST' | 'RESPONSE' | 'ERROR',
  data: Record<string, unknown>
): void {
  const logEntry = {
    timestamp: new Date().toISOString(),
    requestId,
    phase,
    ...data,
  }
  console.log(`[LLM-INTERACTION] ${JSON.stringify(logEntry)}`)
}

function redactObjectPII(obj: unknown): unknown {
  if (typeof obj === 'string') {
    return redactPII(obj)
  }
  if (Array.isArray(obj)) {
    return obj.map(redactObjectPII)
  }
  if (obj !== null && typeof obj === 'object') {
    const redacted: Record<string, unknown> = {}
    for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
      redacted[key] = redactObjectPII(value)
    }
    return redacted
  }
  return obj
}

function sanitizeObjectInput(obj: unknown): unknown {
  if (typeof obj === 'string') {
    return sanitizeLLMInput(obj)
  }
  if (Array.isArray(obj)) {
    return obj.map(sanitizeObjectInput)
  }
  if (obj !== null && typeof obj === 'object') {
    const sanitized: Record<string, unknown> = {}
    for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
      sanitized[key] = sanitizeObjectInput(value)
    }
    return sanitized
  }
  return obj
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

export async function POST(request: NextRequest) {
  const requestId = crypto.randomUUID()

  try {
    // Authenticate inbound request
    if (!validateAuthentication(request)) {
      console.error(`[SECURITY] Unauthorized request attempt. RequestId: ${requestId}`)
      return NextResponse.json(
        { detail: 'Unauthorized: Authentication required to access LLM endpoints.' },
        { status: 401 }
      )
    }

    const body = await request.json()

    // Check for suspicious prompt content
    const bodyString = JSON.stringify(body)
    const suspiciousCheck = detectSuspiciousPrompt(bodyString)
    if (suspiciousCheck.suspicious) {
      console.warn(`[SECURITY] Suspicious prompt detected. RequestId: ${requestId}. Reason: ${suspiciousCheck.reason}`)
      logLLMInteraction(requestId, 'REQUEST', {
        status: 'BLOCKED',
        reason: suspiciousCheck.reason,
        bodyLength: bodyString.length,
      })
      return NextResponse.json(
        { detail: `Request blocked: ${suspiciousCheck.reason}` },
        { status: 400 }
      )
    }

    // Sanitize input
    const sanitizedBody = sanitizeObjectInput(body)

    // Redact PII before sending to LLM
    const redactedBody = redactObjectPII(sanitizedBody)

    // Log the outgoing request (with redacted PII)
    logLLMInteraction(requestId, 'REQUEST', {
      status: 'SENT',
      bodyLength: JSON.stringify(redactedBody).length,
    })

    const response = await fetch(`${BACKEND_URL}/chat`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(redactedBody),
    })

    const data = await response.json()

    // Sanitize LLM response to remove dangerous code execution patterns
    const sanitizedData = sanitizeResponseObject(data)

    // Log the response
    logLLMInteraction(requestId, 'RESPONSE', {
      status: response.status,
      ok: response.ok,
      responseLength: JSON.stringify(sanitizedData).length,
    })

    if (!response.ok) {
      return NextResponse.json(sanitizedData, { status: response.status })
    }

    return NextResponse.json(sanitizedData)
  } catch (error) {
    logLLMInteraction(requestId, 'ERROR', {
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