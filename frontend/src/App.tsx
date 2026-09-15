import {
  useEffect,
  useState,
  type FormEvent,
  type ReactNode,
} from "react"

import {
  Activity,
  BarChart3,
  CheckCircle2,
  ExternalLink,
  History,
  LogOut,
  RefreshCw,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  XCircle,
  Zap,
} from "lucide-react"

import {
  scanService,
  type ScanHistoryItem,
  type ScanStatus,
  type ScanStatusResponse,
} from "./services/scanService"

import {
  login,
  register,
  logout,
  isAuthenticated,
} from "./services/authService"


/* ============================================================
   TYPES
============================================================ */

type AuthMode = "login" | "register"

type DashboardView =
  | "dashboard"
  | "scan"
  | "history"
  | "statistics"


/* ============================================================
   HELPER TYPES
============================================================ */

interface ApiError {
  response?: {
    status?: number
    data?: {
      detail?: unknown
    }
  }
  message?: string
}


/* ============================================================
   APP
============================================================ */

function App() {
  const [authenticated, setAuthenticated] =
    useState<boolean>(isAuthenticated())

  const [authMode, setAuthMode] =
    useState<AuthMode>("login")

  const [view, setView] =
    useState<DashboardView>("dashboard")

  const [url, setUrl] =
    useState("")

  const [result, setResult] =
  useState<ScanStatusResponse["result"] | null>(null)

  const [scanStatus, setScanStatus] =
    useState<ScanStatus | "idle">("idle")

  const [scanning, setScanning] =
    useState(false)

  const [scanError, setScanError] =
    useState("")

  const [history, setHistory] =
    useState<ScanHistoryItem[]>([])

  const [historyLoading, setHistoryLoading] =
    useState(false)

  const [historyError, setHistoryError] =
    useState("")

  const [selectedHistory, setSelectedHistory] =
    useState<ScanHistoryItem | null>(null)


  /* ----------------------------------------------------------
     LOGOUT
  ---------------------------------------------------------- */

  const handleLogout = () => {
    logout()

    setAuthenticated(false)
    setResult(null)
    setHistory([])
    setSelectedHistory(null)
    setUrl("")
  }


  /* ----------------------------------------------------------
     LOAD HISTORY
  ---------------------------------------------------------- */

  const loadHistory = async () => {
    setHistoryLoading(true)
    setHistoryError("")

    try {
      const response =
        await scanService.getHistory()

      setHistory(response.results ?? [])
    } catch (error) {
      const apiError = error as ApiError

      if (apiError.response?.status === 401) {
        handleLogout()
        return
      }

      const detail =
        apiError.response?.data?.detail

      setHistoryError(
        typeof detail === "string"
          ? detail
          : apiError.message ||
              "Unable to load scan history.",
      )
    } finally {
      setHistoryLoading(false)
    }
  }


  /* ----------------------------------------------------------
     LOAD HISTORY WHEN DASHBOARD / HISTORY IS OPENED
  ---------------------------------------------------------- */

  useEffect(() => {
    if (!authenticated) {
      return
    }

    if (
      view === "dashboard" ||
      view === "history"
    ) {
      void loadHistory()
    }
  }, [authenticated, view])


  /* ----------------------------------------------------------
     ASYNC SCAN
  ---------------------------------------------------------- */

  const handleScan = async () => {
    const trimmedUrl = url.trim()

    if (!trimmedUrl) {
      setScanError("Please enter a URL.")
      return
    }

    setScanError("")
    setResult(null)
    setScanning(true)
    setScanStatus("queued")

    try {
      const queued =
        await scanService.scanUrlAsync(trimmedUrl)

      const scanId = queued.scan_id

      const pollStatus = async (): Promise<void> => {
        try {
          const status =
            await scanService.getScanStatus(scanId)

          setScanStatus(status.status)
          if (status.status === "completed") {
            setResult(status.result)
            setScanning(false)
            setScanStatus("completed")

            // The worker has completed the scan; reload persisted history.
            await loadHistory()
            return
          }

          if (status.status === "failed") {
            setScanning(false)

            setScanError(
              status.error ||
                "The scan failed.",
            )

            return
          }

          window.setTimeout(() => {
            void pollStatus()
          }, 1000)
        } catch (error) {
          const apiError = error as ApiError

          if (
            apiError.response?.status === 401
          ) {
            handleLogout()
            return
          }

          setScanning(false)

          const detail =
            apiError.response?.data?.detail

          setScanError(
            typeof detail === "string"
              ? detail
              : apiError.message ||
                  "Unable to retrieve scan status.",
          )
        }
      }

      await pollStatus()
    } catch (error) {
      const apiError = error as ApiError

      if (apiError.response?.status === 401) {
        handleLogout()
        return
      }

      setScanning(false)

      const detail =
        apiError.response?.data?.detail

      setScanError(
        typeof detail === "string"
          ? detail
          : apiError.message ||
              "Unable to start scan.",
      )
    }
  }


  /* ----------------------------------------------------------
     NAVIGATION
  ---------------------------------------------------------- */

  const navigate = (
    nextView: DashboardView,
  ) => {
    setView(nextView)

    if (nextView !== "history") {
      setSelectedHistory(null)
    }
  }


  /* ----------------------------------------------------------
     AUTH SCREEN
  ---------------------------------------------------------- */

  if (!authenticated) {
    return (
      <AuthPage
        mode={authMode}
        onModeChange={setAuthMode}
        onAuthenticated={() =>
          setAuthenticated(true)
        }
      />
    )
  }


  /* ----------------------------------------------------------
     MAIN DASHBOARD
  ---------------------------------------------------------- */

  return (
    <div className="min-h-screen bg-slate-950 text-white">
      <div className="flex min-h-screen">

        {/* ====================================================
            SIDEBAR
        ==================================================== */}

        <aside className="hidden w-64 shrink-0 border-r border-slate-800 bg-slate-900 md:flex md:flex-col">

          {/* Logo */}
          <div className="border-b border-slate-800 p-5">
            <div className="flex items-center gap-3">
              <div className="rounded-xl bg-cyan-500/10 p-2">
                <Shield className="h-6 w-6 text-cyan-400" />
              </div>

              <div>
                <h1 className="font-bold text-white">
                  PhishGuard AI
                </h1>

                <p className="text-xs text-slate-500">
                  Security Platform
                </p>
              </div>
            </div>
          </div>


          {/* Navigation */}
          <nav className="flex-1 space-y-2 p-4">

            <SidebarButton
              icon={
                <Activity className="h-4 w-4" />
              }
              label="Dashboard"
              active={view === "dashboard"}
              onClick={() =>
                navigate("dashboard")
              }
            />

            <SidebarButton
              icon={
                <Search className="h-4 w-4" />
              }
              label="Scan URL"
              active={view === "scan"}
              onClick={() =>
                navigate("scan")
              }
            />

            <SidebarButton
              icon={
                <History className="h-4 w-4" />
              }
              label="Scan History"
              active={view === "history"}
              onClick={() =>
                navigate("history")
              }
            />

            <SidebarButton
              icon={
                <BarChart3 className="h-4 w-4" />
              }
              label="Statistics"
              active={view === "statistics"}
              onClick={() =>
                navigate("statistics")
              }
            />

          </nav>


          {/* Logout */}
          <div className="border-t border-slate-800 p-4">
            <button
              onClick={handleLogout}
              className="flex w-full items-center gap-3 rounded-xl px-4 py-3 text-sm text-slate-400 transition hover:bg-red-500/10 hover:text-red-400"
            >
              <LogOut className="h-4 w-4" />

              Logout
            </button>
          </div>

        </aside>


        {/* ====================================================
            MAIN
        ==================================================== */}

        <main className="min-w-0 flex-1">

          {/* Header */}
          <header className="flex h-16 items-center justify-between border-b border-slate-800 bg-slate-900/70 px-4 backdrop-blur md:px-8">

            <div className="flex items-center gap-3 md:hidden">
              <Shield className="h-6 w-6 text-cyan-400" />

              <span className="font-bold">
                PhishGuard AI
              </span>
            </div>


            <div className="hidden md:block">
              <p className="text-sm font-medium text-white">
                {view === "dashboard" &&
                  "Security Dashboard"}

                {view === "scan" &&
                  "URL Scanner"}

                {view === "history" &&
                  "Scan History"}

                {view === "statistics" &&
                  "Statistics"}
              </p>
            </div>


            <button
              onClick={handleLogout}
              className="flex items-center gap-2 rounded-lg px-3 py-2 text-sm text-slate-400 transition hover:bg-slate-800 hover:text-white"
            >
              <LogOut className="h-4 w-4" />

              <span className="hidden sm:inline">
                Logout
              </span>
            </button>

          </header>


          {/* ==================================================
              MOBILE NAVIGATION
          ================================================== */}

          <div className="border-b border-slate-800 bg-slate-900 p-2 md:hidden">

            <div className="grid grid-cols-4 gap-1">

              <MobileNavButton
                label="Dashboard"
                active={view === "dashboard"}
                onClick={() =>
                  navigate("dashboard")
                }
              />

              <MobileNavButton
                label="Scan"
                active={view === "scan"}
                onClick={() =>
                  navigate("scan")
                }
              />

              <MobileNavButton
                label="History"
                active={view === "history"}
                onClick={() =>
                  navigate("history")
                }
              />

              <MobileNavButton
                label="Stats"
                active={view === "statistics"}
                onClick={() =>
                  navigate("statistics")
                }
              />

            </div>

          </div>


          {/* ==================================================
              PAGE CONTENT
          ================================================== */}

          <div className="mx-auto max-w-7xl p-4 md:p-8">

            {view === "dashboard" && (
              <DashboardOverview
                history={history}
                onNavigate={navigate}
              />
            )}


            {view === "scan" && (
              <Scanner
                result={result}
                scanStatus={scanStatus}
                scanning={scanning}
                error={scanError}
                url={url}
                setUrl={setUrl}
                onScan={handleScan}
              />
            )}


            {view === "history" && (
              <HistoryPage
                items={history}
                loading={historyLoading}
                error={historyError}
                onRefresh={loadHistory}
                selected={selectedHistory}
                onSelect={setSelectedHistory}
              />
            )}


            {view === "statistics" && (
              <StatisticsPage />
            )}

          </div>

        </main>

      </div>
    </div>
  )
}


/* ============================================================
   AUTH PAGE
============================================================ */

function AuthPage({
  mode,
  onModeChange,
  onAuthenticated,
}: {
  mode: AuthMode
  onModeChange: (mode: AuthMode) => void
  onAuthenticated: () => void
}) {
  const [email, setEmail] =
    useState("")

  const [password, setPassword] =
    useState("")

  const [loading, setLoading] =
    useState(false)

  const [error, setError] =
    useState("")


  const isLogin = mode === "login"


  const handleSubmit = async (
    event: FormEvent<HTMLFormElement>,
  ) => {
    event.preventDefault()

    setError("")

    const trimmedEmail =
      email.trim()

    if (!trimmedEmail) {
      setError("Email is required.")
      return
    }

    if (!trimmedEmail.includes("@")) {
      setError(
        "Please enter a valid email address.",
      )
      return
    }

    if (password.length < 8) {
      setError(
        "Password must contain at least 8 characters.",
      )
      return
    }

    setLoading(true)

    try {
      if (isLogin) {
        await login(
          trimmedEmail,
          password,
        )
      } else {
        await register(
          trimmedEmail,
          password,
        )
      }

      onAuthenticated()
    } catch (error) {
      const apiError =
        error as ApiError

      const detail =
        apiError.response?.data?.detail

      if (typeof detail === "string") {
        setError(detail)
      } else if (
        Array.isArray(detail)
      ) {
        setError(
          detail
            .map((item) => {
              if (
                typeof item === "object" &&
                item !== null &&
                "msg" in item
              ) {
                return String(
                  (
                    item as {
                      msg: unknown
                    }
                  ).msg,
                )
              }

              return "Validation error"
            })
            .join(", "),
        )
      } else if (
        apiError.response?.status === 401
      ) {
        setError(
          "Invalid email or password.",
        )
      } else if (
        apiError.response?.status === 409
      ) {
        setError(
          "An account with this email already exists.",
        )
      } else {
        setError(
          isLogin
            ? "Login failed. Please check your credentials."
            : "Registration failed. Please try again.",
        )
      }
    } finally {
      setLoading(false)
    }
  }


  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-950 px-4 text-white">

      <div className="w-full max-w-md">

        {/* Branding */}
        <div className="mb-8 text-center">

          <div className="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-2xl border border-cyan-400/20 bg-cyan-500/10">
            <Shield className="h-8 w-8 text-cyan-400" />
          </div>

          <h1 className="text-3xl font-bold">
            PhishGuard AI
          </h1>

          <p className="mt-2 text-sm text-slate-400">
            Real-time phishing and URL threat intelligence
          </p>

        </div>


        {/* Card */}
        <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6 shadow-2xl">

          <h2 className="text-xl font-semibold">
            {isLogin
              ? "Welcome back"
              : "Create account"}
          </h2>

          <p className="mt-1 text-sm text-slate-400">
            {isLogin
              ? "Sign in to access your security dashboard."
              : "Create your PhishGuard account to start scanning."}
          </p>


          <form
            onSubmit={handleSubmit}
            className="mt-6 space-y-4"
          >

            {/* Email */}
            <div>
              <label className="mb-2 block text-sm text-slate-300">
                Email
              </label>

              <input
                type="email"
                value={email}
                onChange={(event) =>
                  setEmail(event.target.value)
                }
                placeholder="you@example.com"
                autoComplete="email"
                className="w-full rounded-xl border border-slate-700 bg-slate-950 px-4 py-3 text-white outline-none transition focus:border-cyan-400"
              />
            </div>


            {/* Password */}
            <div>
              <label className="mb-2 block text-sm text-slate-300">
                Password
              </label>

              <input
                type="password"
                value={password}
                onChange={(event) =>
                  setPassword(event.target.value)
                }
                placeholder="Minimum 8 characters"
                autoComplete={
                  isLogin
                    ? "current-password"
                    : "new-password"
                }
                className="w-full rounded-xl border border-slate-700 bg-slate-950 px-4 py-3 text-white outline-none transition focus:border-cyan-400"
              />
            </div>


            {/* Error */}
            {error && (
              <div className="rounded-xl border border-red-500/20 bg-red-500/10 px-4 py-3 text-sm text-red-300">
                {error}
              </div>
            )}


            {/* Submit */}
            <button
              type="submit"
              disabled={loading}
              className="flex w-full items-center justify-center gap-2 rounded-xl bg-cyan-500 px-4 py-3 font-semibold text-slate-950 transition hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {loading && (
                <RefreshCw className="h-4 w-4 animate-spin" />
              )}

              {loading
                ? "Please wait..."
                : isLogin
                  ? "Sign In"
                  : "Create Account"}
            </button>

          </form>


          {/* Switch mode */}
          <div className="mt-6 text-center text-sm text-slate-400">

            {isLogin
              ? "Don't have an account?"
              : "Already have an account?"}

            <button
              type="button"
              onClick={() =>
                onModeChange(
                  isLogin
                    ? "register"
                    : "login",
                )
              }
              className="ml-2 font-medium text-cyan-400 hover:text-cyan-300"
            >
              {isLogin
                ? "Register"
                : "Sign in"}
            </button>

          </div>

        </div>

      </div>

    </div>
  )
}


/* ============================================================
   SIDEBAR BUTTON
============================================================ */

function SidebarButton({
  icon,
  label,
  active,
  onClick,
}: {
  icon: ReactNode
  label: string
  active: boolean
  onClick: () => void
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`flex w-full items-center gap-3 rounded-xl border px-4 py-3 text-sm font-medium transition ${
        active
          ? "border-cyan-500/20 bg-cyan-500/10 text-cyan-400"
          : "border-transparent text-slate-400 hover:bg-slate-800 hover:text-white"
      }`}
    >
      {icon}
      {label}
    </button>
  )
}


/* ============================================================
   MOBILE NAV BUTTON
============================================================ */

function MobileNavButton({
  label,
  active,
  onClick,
}: {
  label: string
  active: boolean
  onClick: () => void
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`rounded-lg p-2 text-xs transition ${
        active
          ? "bg-cyan-500/10 text-cyan-400"
          : "text-slate-500 hover:bg-slate-800 hover:text-slate-300"
      }`}
    >
      {label}
    </button>
  )
}


/* ============================================================
   RISK BADGE
============================================================ */

function RiskBadge({
  prediction,
}: {
  prediction: string
}) {
  const normalized =
    prediction.toUpperCase()


  if (normalized === "PHISHING") {
    return (
      <span className="inline-flex items-center gap-1 rounded-full border border-red-500/20 bg-red-500/10 px-2.5 py-1 text-xs font-semibold text-red-400">
        <ShieldAlert className="h-3.5 w-3.5" />
        PHISHING
      </span>
    )
  }


  if (normalized === "SUSPICIOUS") {
    return (
      <span className="inline-flex items-center gap-1 rounded-full border border-amber-500/20 bg-amber-500/10 px-2.5 py-1 text-xs font-semibold text-amber-400">
        <ShieldAlert className="h-3.5 w-3.5" />
        SUSPICIOUS
      </span>
    )
  }


  return (
    <span className="inline-flex items-center gap-1 rounded-full border border-emerald-500/20 bg-emerald-500/10 px-2.5 py-1 text-xs font-semibold text-emerald-400">
      <ShieldCheck className="h-3.5 w-3.5" />
      SAFE
    </span>
  )
}


/* ============================================================
   STAT CARD
============================================================ */

function StatCard({
  title,
  value,
  subtitle,
  icon,
}: {
  title: string
  value: string
  subtitle: string
  icon: ReactNode
}) {
  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900 p-5">

      <div className="flex items-start justify-between">

        <div>
          <p className="text-sm text-slate-400">
            {title}
          </p>

          <p className="mt-2 text-2xl font-bold text-white">
            {value}
          </p>

          <p className="mt-1 text-xs text-slate-500">
            {subtitle}
          </p>
        </div>

        <div className="rounded-xl bg-slate-800 p-3 text-cyan-400">
          {icon}
        </div>

      </div>

    </div>
  )
}


/* ============================================================
   DASHBOARD OVERVIEW
============================================================ */

function DashboardOverview({
  history,
  onNavigate,
}: {
  history: ScanHistoryItem[]
  onNavigate: (
    view: DashboardView,
  ) => void
}) {
const recent =
    history.slice(0, 5)

const totalScans = history.length

const safeCount = history.filter(
    (item) =>
      item.prediction.toUpperCase() === "SAFE",
  ).length

const suspiciousCount = history.filter(
    (item) =>
      item.prediction.toUpperCase() === "SUSPICIOUS",
  ).length

const phishingCount = history.filter(
    (item) =>
      item.prediction.toUpperCase() === "PHISHING",
  ).length


  return (
    <div className="space-y-6">

      <div>
        <h2 className="text-2xl font-bold text-white">
          Security Dashboard
        </h2>

        <p className="mt-1 text-sm text-slate-400">
          Monitor URL security scans and threat detection.
        </p>
      </div>


      {/* Scan Summary */}
<div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">

  <StatCard
    title="Total Scans"
    value={String(totalScans)}
    subtitle="URLs analyzed"
    icon={
      <Activity className="h-5 w-5" />
    }
  />

  <StatCard
    title="Safe URLs"
    value={String(safeCount)}
    subtitle="Low-risk results"
    icon={
      <CheckCircle2 className="h-5 w-5" />
    }
  />

  <StatCard
    title="Suspicious"
    value={String(suspiciousCount)}
    subtitle="Requires attention"
    icon={
      <ShieldAlert className="h-5 w-5" />
    }
  />

  <StatCard
    title="Phishing"
    value={String(phishingCount)}
    subtitle="High-risk results"
    icon={
      <ShieldAlert className="h-5 w-5" />
    }
  />

</div>


      {/* Recent scans */}
      <div className="overflow-hidden rounded-2xl border border-slate-800 bg-slate-900">

        <div className="flex items-center justify-between border-b border-slate-800 p-5">

          <div>
            <h3 className="font-semibold text-white">
              Recent Scans
            </h3>

            <p className="mt-1 text-xs text-slate-500">
              Latest URL analysis results
            </p>
          </div>

          <button
            type="button"
            onClick={() =>
              onNavigate("history")
            }
            className="text-sm font-medium text-cyan-400 hover:text-cyan-300"
          >
            View all
          </button>

        </div>


        {recent.length === 0 ? (
          <div className="p-8 text-center text-sm text-slate-500">
            No scans yet.
          </div>
        ) : (
          <div className="divide-y divide-slate-800">

            {recent.map((item) => (
              <div
                key={item.id}
                className="flex flex-col gap-3 p-5 sm:flex-row sm:items-center sm:justify-between"
              >

                <div className="min-w-0">

                  <p className="truncate text-sm font-medium text-white">
                    {item.url}
                  </p>

                  <p className="mt-1 text-xs text-slate-500">
                    {formatDate(
                      item.scanned_at,
                    )}
                  </p>

                </div>


                <div className="flex items-center gap-4">

                  <span className="text-sm text-slate-400">
                    Risk{" "}
                    <strong className="text-white">
                      {formatNumber(
                        item.risk_score,
                      )}
                    </strong>
                  </span>

                  <RiskBadge
                    prediction={
                      item.prediction
                    }
                  />

                </div>

              </div>
            ))}

          </div>
        )}

      </div>

    </div>
  )
}


/* ============================================================
   SCANNER
============================================================ */

function Scanner({
  result,
  scanStatus,
  scanning,
  error,
  url,
  setUrl,
  onScan,
}: {
  result: ScanStatusResponse["result"] | null
  scanStatus: ScanStatus | "idle"
  scanning: boolean
  error: string
  url: string
  setUrl: (value: string) => void
  onScan: () => void
}) {
  return (
    <div className="space-y-6">

      <div>
        <h2 className="text-2xl font-bold text-white">
          Scan URL
        </h2>

        <p className="mt-1 text-sm text-slate-400">
          Analyze a URL using machine learning,
          threat intelligence and security rules.
        </p>
      </div>


      {/* Scanner */}
      <div className="rounded-2xl border border-slate-800 bg-slate-900 p-5">

        <form
          onSubmit={(event) => {
            event.preventDefault()
            onScan()
          }}
        >

          <label className="mb-2 block text-sm font-medium text-slate-300">
            URL to analyze
          </label>


          <div className="flex flex-col gap-3 md:flex-row">

            <div className="relative flex-1">

              <Search className="absolute left-4 top-1/2 h-5 w-5 -translate-y-1/2 text-slate-500" />

              <input
                type="url"
                value={url}
                onChange={(event) =>
                  setUrl(
                    event.target.value,
                  )
                }
                placeholder="https://example.com"
                className="w-full rounded-xl border border-slate-700 bg-slate-950 py-3 pl-12 pr-4 text-white outline-none transition focus:border-cyan-400"
              />

            </div>


            <button
              type="submit"
              disabled={
                scanning ||
                !url.trim()
              }
              className="flex items-center justify-center gap-2 rounded-xl bg-cyan-500 px-6 py-3 font-semibold text-slate-950 transition hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-50"
            >

              {scanning ? (
                <>
                  <RefreshCw className="h-4 w-4 animate-spin" />
                  Scanning...
                </>
              ) : (
                <>
                  <Zap className="h-4 w-4" />
                  Scan URL
                </>
              )}

            </button>

          </div>

        </form>


        {/* Error */}
        {error && (
          <div className="mt-4 flex items-start gap-3 rounded-xl border border-red-500/20 bg-red-500/10 p-4 text-sm text-red-300">

            <XCircle className="mt-0.5 h-5 w-5 shrink-0" />

            <span>
              {error}
            </span>

          </div>
        )}


        {/* Progress */}
        {scanning && (
          <div className="mt-5 rounded-xl border border-cyan-500/20 bg-cyan-500/5 p-4">

            <div className="flex items-center gap-3">

              <RefreshCw className="h-5 w-5 animate-spin text-cyan-400" />

              <div>

                <p className="font-medium text-white">
                  {scanStatus === "queued"
                    ? "Scan queued"
                    : "Analyzing URL"}
                </p>

                <p className="text-sm text-slate-400">
                  PhishGuard is running ML and threat intelligence checks.
                </p>

              </div>

            </div>

          </div>
        )}

      </div>


      {/* Result */}
     {result && (
        <ScanResult result={result} />
)}

    </div>
  )
}


/* ============================================================
   SCAN RESULT
============================================================ */
function ScanResult({
  result,
}: {
  result: NonNullable<ScanStatusResponse["result"]>
}) {
  const scan = result
  const risk = scan.risk ?? {
    score: 0,
    level: "UNKNOWN",
    confidence: 0,
  }

  const riskLevel =
    risk.level?.toUpperCase() || "UNKNOWN"

  return (
    <div className="overflow-hidden rounded-2xl border border-slate-800 bg-slate-900">

      {/* Header */}
      <div className="border-b border-slate-800 p-5">
        <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">

          <div className="min-w-0">
            <p className="text-sm text-slate-400">
              Scan Result
            </p>

            <div className="mt-1 flex items-center gap-2">
              <h3 className="truncate text-lg font-semibold text-white">
                {scan.url}
              </h3>

              <ExternalLink className="h-4 w-4 shrink-0 text-slate-500" />
            </div>
          </div>

          <RiskBadge prediction={riskLevel} />
        </div>
      </div>

      {/* Metrics */}
      <div className="grid gap-4 p-5 sm:grid-cols-2 lg:grid-cols-4">

        <ResultMetric
          label="Risk Score"
          value={`${formatNumber(risk.score)}/100`}
        />

        <ResultMetric
          label="Risk Level"
          value={riskLevel}
        />

        <ResultMetric
          label="Confidence"
          value={`${formatNumber(risk.confidence)}%`}
        />

        <ResultMetric
          label="Scan Duration"
          value={`${formatNumber(scan.scan_duration_ms)} ms`}
        />

      </div>

      {/* Analysis */}
      <div className="grid gap-5 border-t border-slate-800 p-5 lg:grid-cols-2">

        {/* Detection Signals */}
        <div>
          <h4 className="mb-4 font-semibold text-white">
            Detection Signals
          </h4>

          <div className="space-y-3">

            {scan.reasons?.length ? (
              scan.reasons.map(
                (
                  reason: string,
                  index: number,
                ) => (
                  <div
                    key={`${index}-${reason}`}
                    className="flex items-start gap-3 rounded-xl bg-slate-950 p-3"
                  >
                    <AlertIcon />

                    <span className="text-sm text-slate-300">
                      {reason}
                    </span>
                  </div>
                ),
              )
            ) : (
              <div className="rounded-xl bg-slate-950 p-4 text-sm text-slate-500">
                No additional detection signals.
              </div>
            )}

          </div>
        </div>

        {/* Model Analysis */}
        <div>
          <h4 className="mb-4 font-semibold text-white">
            Model Analysis
          </h4>

          <div className="space-y-3">

            <AnalysisRow
              label="URL ML Score"
              value={formatScore(
                scan.models?.url_ml?.score,
              )}
            />

            <AnalysisRow
              label="Hostname ML Score"
              value={formatScore(
                scan.models?.hostname_ml?.score,
              )}
            />

            <AnalysisRow
              label="Model Score"
              value={formatScore(
                scan.models?.fusion_score,
              )}
            />

            <AnalysisRow
              label="Rule Score"
              value={formatScore(
                scan.models?.rule_score,
              )}
            />

          </div>
        </div>

      </div>

      {/* Metadata */}
      <div className="border-t border-slate-800 p-5">

        <div className="flex flex-wrap gap-3">

          <MetadataBadge
            label="Trusted domain"
            value={
              scan.trusted_domain
                ? "Yes"
                : "No"
            }
          />

          <MetadataBadge
            label="Cache"
            value={
              scan.cache?.hit
                ? "Hit"
                : "Miss"
            }
          />

          <MetadataBadge
            label="Cache source"
            value={
              scan.cache?.source || "N/A"
            }
          />

        </div>

      </div>

    </div>
  )
}


/* ============================================================
   HISTORY PAGE
============================================================ */

function HistoryPage({
  items,
  loading,
  error,
  onRefresh,
  selected,
  onSelect,
}: {
  items: ScanHistoryItem[]
  loading: boolean
  error: string
  onRefresh: () => void
  selected: ScanHistoryItem | null
  onSelect: (
    item: ScanHistoryItem | null,
  ) => void
}) {
  return (
    <div className="space-y-6">

      {/* Header */}
      <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">

        <div>
          <h2 className="text-2xl font-bold text-white">
            Scan History
          </h2>

          <p className="mt-1 text-sm text-slate-400">
            Review previously analyzed URLs and their security results.
          </p>
        </div>


        <button
          type="button"
          onClick={onRefresh}
          disabled={loading}
          className="flex items-center justify-center gap-2 rounded-xl border border-slate-700 bg-slate-900 px-4 py-2.5 text-sm font-medium text-slate-300 transition hover:border-slate-600 hover:text-white disabled:opacity-50"
        >
          <RefreshCw
            className={
              loading
                ? "h-4 w-4 animate-spin"
                : "h-4 w-4"
            }
          />

          Refresh
        </button>

      </div>


      {/* Error */}
      {error && (
        <div className="rounded-xl border border-red-500/20 bg-red-500/10 p-4 text-sm text-red-300">
          {error}
        </div>
      )}


      {/* Table */}
      <div className="overflow-hidden rounded-2xl border border-slate-800 bg-slate-900">

        {loading ? (
          <LoadingState />
        ) : items.length === 0 ? (
          <EmptyHistory />
        ) : (
          <>
            {/* Desktop */}
            <div className="hidden overflow-x-auto md:block">

              <table className="w-full">

                <thead className="border-b border-slate-800 bg-slate-950/50">

                  <tr className="text-left text-xs uppercase tracking-wide text-slate-500">

                    <th className="px-5 py-4">
                      URL
                    </th>

                    <th className="px-5 py-4">
                      Result
                    </th>

                    <th className="px-5 py-4">
                      Risk
                    </th>

                    <th className="px-5 py-4">
                      Confidence
                    </th>

                    <th className="px-5 py-4">
                      Scanned
                    </th>

                  </tr>

                </thead>


                <tbody className="divide-y divide-slate-800">

                  {items.map((item) => (
                    <tr
                      key={item.id}
                      onClick={() =>
                        onSelect(item)
                      }
                      className="cursor-pointer transition hover:bg-slate-800/50"
                    >

                      <td className="max-w-sm px-5 py-4">

                        <div className="truncate text-sm font-medium text-white">
                          {item.url}
                        </div>

                        <div className="mt-1 text-xs text-slate-500">
                          Scan #{item.id}
                        </div>

                      </td>


                      <td className="px-5 py-4">
                        <RiskBadge
                          prediction={
                            item.prediction
                          }
                        />
                      </td>


                      <td className="px-5 py-4 text-sm text-slate-300">
                        {formatNumber(
                          item.risk_score,
                        )}
                      </td>


                      <td className="px-5 py-4 text-sm text-slate-300">
                        {formatNumber(
                          item.confidence,
                        )}
                        %
                      </td>


                      <td className="whitespace-nowrap px-5 py-4 text-sm text-slate-400">
                        {formatDate(
                          item.scanned_at,
                        )}
                      </td>

                    </tr>
                  ))}

                </tbody>

              </table>

            </div>


            {/* Mobile */}
            <div className="divide-y divide-slate-800 md:hidden">

              {items.map((item) => (
                <button
                  key={item.id}
                  type="button"
                  onClick={() =>
                    onSelect(item)
                  }
                  className="block w-full p-4 text-left transition hover:bg-slate-800/50"
                >

                  <div className="flex items-start justify-between gap-3">

                    <div className="min-w-0">

                      <p className="truncate text-sm font-medium text-white">
                        {item.url}
                      </p>

                      <p className="mt-1 text-xs text-slate-500">
                        Scan #{item.id}
                      </p>

                    </div>

                    <RiskBadge
                      prediction={
                        item.prediction
                      }
                    />

                  </div>


                  <div className="mt-4 grid grid-cols-2 gap-3">

                    <div>
                      <p className="text-xs text-slate-500">
                        Risk
                      </p>

                      <p className="mt-1 text-sm font-semibold text-white">
                        {formatNumber(
                          item.risk_score,
                        )}
                      </p>
                    </div>


                    <div>
                      <p className="text-xs text-slate-500">
                        Confidence
                      </p>

                      <p className="mt-1 text-sm font-semibold text-white">
                        {formatNumber(
                          item.confidence,
                        )}
                        %
                      </p>
                    </div>

                  </div>

                </button>
              ))}

            </div>
          </>
        )}

      </div>


      {/* Selected details */}
      {selected && (
        <HistoryDetails
          item={selected}
          onClose={() =>
            onSelect(null)
          }
        />
      )}

    </div>
  )
}


/* ============================================================
   HISTORY DETAILS
============================================================ */

function HistoryDetails({
  item,
  onClose,
}: {
  item: ScanHistoryItem
  onClose: () => void
}) {
  return (
    <div className="rounded-2xl border border-cyan-500/20 bg-slate-900 p-5">

      {/* Header */}
      <div className="flex items-start justify-between gap-4">

        <div className="min-w-0">

          <div className="flex flex-wrap items-center gap-3">

            <h3 className="text-lg font-semibold text-white">
              Scan #{item.id}
            </h3>

            <RiskBadge
              prediction={
                item.prediction
              }
            />

          </div>

          <p className="mt-2 break-all text-sm text-slate-400">
            {item.url}
          </p>

        </div>


        <button
          type="button"
          onClick={onClose}
          className="rounded-lg p-2 text-slate-500 transition hover:bg-slate-800 hover:text-white"
        >
          <XCircle className="h-5 w-5" />
        </button>

      </div>


      {/* Metrics */}
      <div className="mt-6 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">

        <ResultMetric
          label="Risk Score"
          value={`${formatNumber(
            item.risk_score,
          )}/100`}
        />

        <ResultMetric
          label="Risk Level"
          value={item.risk_level}
        />

        <ResultMetric
          label="Confidence"
          value={`${formatNumber(
            item.confidence,
          )}%`}
        />

        <ResultMetric
          label="Duration"
          value={`${formatNumber(
            item.scan_duration_ms,
          )} ms`}
        />

      </div>


      {/* Analysis */}
      <div className="mt-6 grid gap-5 lg:grid-cols-2">

        {/* ML */}
        <div className="rounded-xl bg-slate-950 p-4">

          <h4 className="mb-4 font-semibold text-white">
            ML Analysis
          </h4>

          <div className="space-y-3 text-sm">

            <DetailRow
              label="URL ML Score"
              value={formatScore(
                item.url_ml_score,
              )}
            />

            <DetailRow
              label="Hostname ML Score"
              value={formatScore(
                item.hostname_ml_score,
              )}
            />

            <DetailRow
              label="Model Score"
              value={formatScore(
                item.model_score,
              )}
            />

            <DetailRow
              label="Rule Score"
              value={formatScore(
                item.rule_score,
              )}
            />

          </div>

        </div>


        {/* Threat Intelligence */}
        <div className="rounded-xl bg-slate-950 p-4">

          <h4 className="mb-4 font-semibold text-white">
            Threat Intelligence
          </h4>

          <div className="space-y-3 text-sm">

            <DetailRow
              label="Provider"
              value={
                item.threat_intel_provider ||
                "N/A"
              }
            />

            <DetailRow
              label="Status"
              value={
                item.threat_intel_status ||
                "N/A"
              }
            />

            <DetailRow
              label="Malicious"
              value={String(
                item.vt_malicious,
              )}
            />

            <DetailRow
              label="Suspicious"
              value={String(
                item.vt_suspicious,
              )}
            />

            <DetailRow
              label="Harmless"
              value={String(
                item.vt_harmless,
              )}
            />

            <DetailRow
              label="Undetected"
              value={String(
                item.vt_undetected,
              )}
            />

            <DetailRow
              label="Threat Score"
              value={formatScore(
                item.threat_score,
              )}
            />

          </div>

        </div>

      </div>


      {/* Footer metadata */}
      <div className="mt-5 flex flex-wrap gap-3">

        <MetadataBadge
          label="Trusted domain"
          value={
            item.trusted_domain
              ? "Yes"
              : "No"
          }
        />

        <MetadataBadge
          label="VT engines"
          value={String(
            item.vt_total_engines,
          )}
        />

        <MetadataBadge
          label="Scanned"
          value={formatDate(
            item.scanned_at,
          )}
        />

      </div>

    </div>
  )
}


/* ============================================================
   STATISTICS
============================================================ */

function StatisticsPage() {
  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900 p-8 text-center">

      <BarChart3 className="mx-auto h-12 w-12 text-slate-600" />

      <h2 className="mt-4 text-xl font-semibold text-white">
        Statistics
      </h2>

      <p className="mx-auto mt-2 max-w-md text-sm text-slate-400">
        Statistics are currently parked.
        The existing statistics endpoint will
        be addressed separately.
      </p>

    </div>
  )
}


/* ============================================================
   SMALL COMPONENTS
============================================================ */

function ResultMetric({
  label,
  value,
}: {
  label: string
  value: string
}) {
  return (
    <div className="rounded-xl bg-slate-950 p-4">

      <p className="text-xs uppercase tracking-wide text-slate-500">
        {label}
      </p>

      <p className="mt-2 text-lg font-bold text-white">
        {value}
      </p>

    </div>
  )
}


function AnalysisRow({
  label,
  value,
}: {
  label: string
  value: string
}) {
  return (
    <div className="rounded-xl bg-slate-950 p-4">

      <div className="flex justify-between gap-4 text-sm">

        <span className="text-slate-400">
          {label}
        </span>

        <span className="font-medium text-white">
          {value}
        </span>

      </div>

    </div>
  )
}


function DetailRow({
  label,
  value,
}: {
  label: string
  value: string
}) {
  return (
    <div className="flex items-center justify-between gap-4">

      <span className="text-slate-500">
        {label}
      </span>

      <span className="text-right font-medium text-slate-200">
        {value}
      </span>

    </div>
  )
}


function MetadataBadge({
  label,
  value,
}: {
  label: string
  value: string
}) {
  return (
    <div className="rounded-lg bg-slate-950 px-3 py-2 text-sm text-slate-300">

      {label}:{" "}

      <strong className="text-white">
        {value}
      </strong>

    </div>
  )
}


function AlertIcon() {
  return (
    <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-amber-400" />
  )
}


function LoadingState() {
  return (
    <div className="flex items-center justify-center py-20 text-slate-400">

      <RefreshCw className="mr-3 h-5 w-5 animate-spin" />

      Loading scan history...

    </div>
  )
}


function EmptyHistory() {
  return (
    <div className="flex flex-col items-center justify-center py-20 text-center">

      <History className="h-10 w-10 text-slate-600" />

      <h3 className="mt-4 font-semibold text-white">
        No scan history
      </h3>

      <p className="mt-1 text-sm text-slate-500">
        URLs you scan will appear here.
      </p>

    </div>
  )
}


/* ============================================================
   FORMATTERS
============================================================ */

function formatNumber(
  value: number | null | undefined,
): string {
  const number =
    Number(value ?? 0)

  if (!Number.isFinite(number)) {
    return "0.00"
  }

  return number.toFixed(2)
}


function formatScore(
  value: number | null | undefined,
): string {
  return formatNumber(value)
}


function formatDate(
  value: string,
): string {
  if (!value) {
    return "Unknown"
  }

  const date =
    new Date(value)

  if (
    Number.isNaN(
      date.getTime(),
    )
  ) {
    return value
  }

  return date.toLocaleString()
}


export default App