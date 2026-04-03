'use client'

import { useEffect, useState } from 'react'
import { Users, Search, Filter } from 'lucide-react'

interface Employee {
  employee_id: string
  full_name: string
  email: string
  personal_email: string
  phone: string
  ssn: string
  date_of_birth: string
  address: string
  department: string
  title: string
  salary: number
  bank_account: string
  routing_number: string
  health_plan_id: string
  emergency_contact: string
  start_date: string
  status: string
  ni_number?: string
  credit_card_on_file?: string
}

const DEPARTMENTS = ['All', 'Engineering', 'Finance', 'Product', 'Legal', 'HR']

const STATUS_COLORS: Record<string, string> = {
  active: 'bg-green-900 text-green-300',
  probation: 'bg-yellow-900 text-yellow-300',
  inactive: 'bg-red-900 text-red-300',
}

export function EmployeeDashboard() {
  const [employees, setEmployees] = useState<Employee[]>([])
  const [filtered, setFiltered] = useState<Employee[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [search, setSearch] = useState('')
  const [department, setDepartment] = useState('All')

  useEffect(() => {
    fetchEmployees()
  }, [])

  useEffect(() => {
    let result = employees
    if (department !== 'All') {
      result = result.filter(e => e.department === department)
    }
    if (search.trim()) {
      const q = search.toLowerCase()
      result = result.filter(
        e =>
          e.full_name.toLowerCase().includes(q) ||
          e.email.toLowerCase().includes(q) ||
          e.employee_id.toLowerCase().includes(q) ||
          e.department.toLowerCase().includes(q)
      )
    }
    setFiltered(result)
  }, [employees, search, department])

  async function fetchEmployees() {
    try {
      setLoading(true)
      const res = await fetch('/api/employees')
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const data = await res.json()
      setEmployees(data.employees ?? [])
    } catch (err) {
      setError('Failed to load employee directory.')
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64 text-gray-400">
        Loading employee directory…
      </div>
    )
  }

  if (error) {
    return (
      <div className="flex items-center justify-center h-64 text-red-400">
        {error}
      </div>
    )
  }

  return (
    <div className="p-6 max-w-full overflow-x-auto">
      {/* Header */}
      <div className="flex items-center gap-3 mb-6">
        <div className="w-10 h-10 rounded-lg bg-teal-700 flex items-center justify-center">
          <Users className="w-5 h-5 text-white" />
        </div>
        <div>
          <h2 className="text-xl font-semibold text-white">Employee Directory</h2>
          <p className="text-sm text-gray-400">{filtered.length} of {employees.length} employees</p>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-3 mb-5">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
          <input
            type="text"
            placeholder="Search by name, email, or ID…"
            value={search}
            onChange={e => setSearch(e.target.value)}
            className="w-full bg-chat-input border border-chat-border rounded-lg pl-9 pr-4 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-teal-600"
          />
        </div>
        <div className="relative">
          <Filter className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
          <select
            value={department}
            onChange={e => setDepartment(e.target.value)}
            className="bg-chat-input border border-chat-border rounded-lg pl-9 pr-4 py-2 text-sm text-white focus:outline-none focus:border-teal-600 appearance-none"
          >
            {DEPARTMENTS.map(d => (
              <option key={d} value={d}>{d}</option>
            ))}
          </select>
        </div>
      </div>

      {/* Table */}
      <div className="rounded-xl border border-chat-border overflow-hidden">
        <table className="w-full text-sm text-left">
          <thead className="bg-chat-hover text-gray-400 text-xs uppercase tracking-wider">
            <tr>
              <th className="px-4 py-3">Employee</th>
              <th className="px-4 py-3">Employee ID</th>
              <th className="px-4 py-3">SSN</th>
              <th className="px-4 py-3">Date of Birth</th>
              <th className="px-4 py-3">Phone</th>
              <th className="px-4 py-3">Home Address</th>
              <th className="px-4 py-3">Department / Title</th>
              <th className="px-4 py-3">Salary</th>
              <th className="px-4 py-3">Bank Account</th>
              <th className="px-4 py-3">Routing #</th>
              <th className="px-4 py-3">Health Plan</th>
              <th className="px-4 py-3">Start Date</th>
              <th className="px-4 py-3">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-chat-border">
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={13} className="px-4 py-8 text-center text-gray-500">
                  No employees match your search.
                </td>
              </tr>
            ) : (
              filtered.map(emp => (
                <tr key={emp.employee_id} className="bg-chat-bg hover:bg-chat-hover transition-colors">
                  <td className="px-4 py-3">
                    <div className="font-medium text-white">{emp.full_name}</div>
                    <div className="text-gray-400 text-xs">{emp.email}</div>
                    <div className="text-gray-500 text-xs">{emp.personal_email}</div>
                  </td>
                  <td className="px-4 py-3 text-gray-300 font-mono">{emp.employee_id}</td>
                  <td className="px-4 py-3 text-gray-300 font-mono">{emp.ssn}</td>
                  <td className="px-4 py-3 text-gray-300">{emp.date_of_birth}</td>
                  <td className="px-4 py-3 text-gray-300">{emp.phone}</td>
                  <td className="px-4 py-3 text-gray-300 max-w-[180px] whitespace-normal">{emp.address}</td>
                  <td className="px-4 py-3">
                    <div className="text-gray-300">{emp.department}</div>
                    <div className="text-gray-500 text-xs">{emp.title}</div>
                  </td>
                  <td className="px-4 py-3 text-gray-300">
                    ${emp.salary.toLocaleString()}
                  </td>
                  <td className="px-4 py-3 text-gray-300 font-mono">{emp.bank_account}</td>
                  <td className="px-4 py-3 text-gray-300 font-mono">{emp.routing_number}</td>
                  <td className="px-4 py-3 text-gray-400 text-xs">{emp.health_plan_id}</td>
                  <td className="px-4 py-3 text-gray-400">{emp.start_date}</td>
                  <td className="px-4 py-3">
                    <span className={`px-2 py-1 rounded-full text-xs font-medium ${STATUS_COLORS[emp.status] ?? 'bg-gray-800 text-gray-400'}`}>
                      {emp.status}
                    </span>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
