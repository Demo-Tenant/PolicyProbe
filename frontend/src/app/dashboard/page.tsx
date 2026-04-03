import { EmployeeDashboard } from '@/components/EmployeeDashboard'
import Link from 'next/link'
import { ArrowLeft } from 'lucide-react'

export const metadata = {
  title: 'Employee Directory — PolicyProbe',
}

export default function DashboardPage() {
  return (
    <main className="min-h-screen bg-chat-bg text-white">
      <header className="flex items-center gap-4 px-6 py-4 border-b border-chat-border bg-chat-sidebar">
        <Link
          href="/"
          className="flex items-center gap-2 text-gray-400 hover:text-white transition-colors text-sm"
        >
          <ArrowLeft className="w-4 h-4" />
          Back to Chat
        </Link>
        <span className="text-gray-600">|</span>
        <h1 className="text-lg font-semibold">HR Manager Dashboard</h1>
      </header>

      <EmployeeDashboard />
    </main>
  )
}
