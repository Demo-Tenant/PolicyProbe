import { NextRequest, NextResponse } from 'next/server'

const BACKEND_URL = process.env.BACKEND_URL || 'http://127.0.0.1:5500'
const AGENT_AUTH_TOKEN = process.env.AGENT_AUTH_TOKEN

export async function POST(request: NextRequest) {
  if (!AGENT_AUTH_TOKEN) {
    console.error('Policy Violation: AGENT_AUTH_TOKEN is not configured. Inter-agent authentication is required for every agent-to-agent call.')
    return NextResponse.json(
      {
        detail: 'Inter-agent authentication is not configured. This is a policy violation — authentication must be implemented for every agent-to-agent call.',
        policy_error: {
          type: 'authentication',
          message: 'Missing inter-agent authentication token (AGENT_AUTH_TOKEN). Configure this environment variable to comply with the Authenticate Agent Interactions policy.',
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
        'Authorization': `Bearer ${AGENT_AUTH_TOKEN}`,
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