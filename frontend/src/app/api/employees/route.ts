import { NextRequest, NextResponse } from 'next/server'

const BACKEND_URL = process.env.BACKEND_URL || 'http://127.0.0.1:5500'

export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url)
    const department = searchParams.get('department')

    const backendUrl = department
      ? `${BACKEND_URL}/employees?department=${encodeURIComponent(department)}`
      : `${BACKEND_URL}/employees`

    const response = await fetch(backendUrl)
    const data = await response.json()

    if (!response.ok) {
      return NextResponse.json(data, { status: response.status })
    }

    return NextResponse.json(data)
  } catch (error) {
    console.error('Employee directory proxy error:', error)
    return NextResponse.json(
      { detail: 'Failed to fetch employee directory' },
      { status: 503 }
    )
  }
}
