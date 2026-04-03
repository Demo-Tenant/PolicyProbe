import { NextRequest, NextResponse } from 'next/server'

const BACKEND_URL = process.env.BACKEND_URL || 'http://127.0.0.1:5500'

// POLICY VIOLATION: Ensure the LLM being used by the backend service is replaced with an approved LLM from the organization's allow list. Unapproved LLMs are not permitted per security policy.

// POLICY VIOLATION: Missing inter-agent authentication. Every agent-to-agent call must include authentication. An API key or token must be provided via the AGENT_API_KEY environment variable and sent in the Authorization header.

export async function POST(request: NextRequest) {
  try {
    const agentApiKey = process.env.AGENT_API_KEY

    if (!agentApiKey) {
      console.error('AGENT_API_KEY is not set. Inter-agent authentication is required by policy.')
      return NextResponse.json(
        {
          detail: 'Inter-agent authentication is not configured',
          policy_error: {
            type: 'authentication',
            message: 'Missing AGENT_API_KEY: authentication is required for every agent-to-agent call',
          },
        },
        { status: 500 }
      )
    }

    const body = await request.json()

    const response = await fetch(`${BACKEND_URL}/chat`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${agentApiKey}`,
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