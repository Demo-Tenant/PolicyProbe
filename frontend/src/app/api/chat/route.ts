import { NextRequest, NextResponse } from 'next/server'

// POLICY VIOLATION: Replace any unapproved LLM with an approved LLM from the organization's allow list.
// Ensure the backend service at BACKEND_URL is configured to use only approved LLMs.
const BACKEND_URL = process.env.BACKEND_URL || 'http://127.0.0.1:5500'

// POLICY VIOLATION: Missing inter-agent authentication. Every agent-to-agent call must include authentication.
// Set the AGENT_API_KEY environment variable to a secure shared secret for inter-agent authentication.
const AGENT_API_KEY = process.env.AGENT_API_KEY

export async function POST(request: NextRequest) {
  if (!AGENT_API_KEY) {
    console.error('Inter-agent authentication is not configured. Set the AGENT_API_KEY environment variable.')
    return NextResponse.json(
      {
        detail: 'Inter-agent authentication is not configured',
        policy_error: {
          type: 'authentication',
          message: 'Missing inter-agent authentication credentials',
        },
      },
      { status: 500 }
    )
  }

  try {
    const body = await request.json()

    const response = await fetch(`${BACKEND_URL}/chat`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Agent-API-Key': AGENT_API_KEY,
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