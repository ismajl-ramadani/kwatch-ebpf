import { useState, useMemo, useRef, useEffect } from "react"
import {
  Activity,
  Pause,
  Play,
  Trash2,
  Settings2,
  Circle,
  Search,
  X,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { cn } from "@/lib/utils"
import { useStream } from "@/hooks/useStream"

const DEFAULT_URL = "http://localhost:8080/stream"

function formatTime(d: Date) {
  const hms = d.toLocaleTimeString("en-US", {
    hour12: false,
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  })
  return `${hms}.${String(d.getMilliseconds()).padStart(3, "0")}`
}

function formatUptime(seconds: number) {
  const h = Math.floor(seconds / 3600)
  const m = Math.floor((seconds % 3600) / 60)
  const s = seconds % 60
  return [h, m, s].map((n) => String(n).padStart(2, "0")).join(":")
}

function Sparkline({ buckets }: { buckets: number[] }) {
  const max = Math.max(...buckets, 1)
  return (
    <div className="flex items-end gap-px h-5 mt-1">
      {buckets.map((count, i) => (
        <div
          key={i}
          className="w-[3px] rounded-sm bg-primary/50 transition-all duration-500"
          style={{ height: `${Math.max(8, (count / max) * 100)}%` }}
        />
      ))}
    </div>
  )
}

export default function App() {
  const [url, setUrl] = useState(
    () => localStorage.getItem("kwatch-url") ?? DEFAULT_URL,
  )
  const [urlInput, setUrlInput] = useState(url)
  const [showSettings, setShowSettings] = useState(false)
  const [filter, setFilter] = useState("")
  const [uptimeSecs, setUptimeSecs] = useState(0)
  const uptimeStartRef = useRef<number | null>(null)

  const { events, status, paused, togglePause, clear, reconnect } =
    useStream(url)

  useEffect(() => {
    if (status === "live" && uptimeStartRef.current === null) {
      uptimeStartRef.current = Date.now()
    } else if (status !== "live") {
      uptimeStartRef.current = null
      setUptimeSecs(0)
    }
  }, [status])

  useEffect(() => {
    const timer = setInterval(() => {
      if (uptimeStartRef.current !== null) {
        setUptimeSecs(Math.floor((Date.now() - uptimeStartRef.current) / 1000))
      }
    }, 1000)
    return () => clearInterval(timer)
  }, [])

  const filtered = useMemo(
    () =>
      filter
        ? events.filter((e) =>
            e.command.toLowerCase().includes(filter.toLowerCase()),
          )
        : events,
    [events, filter],
  )

  const uniqueCommands = useMemo(
    () => new Set(events.map((e) => e.command)).size,
    [events],
  )

  const rate = useMemo(() => {
    const cutoff = Date.now() - 5000
    const recent = events.filter((e) => e.ts.getTime() > cutoff).length
    return (recent / 5).toFixed(1)
  }, [events])

  const sparkline = useMemo(() => {
    const now = Date.now()
    return Array.from({ length: 30 }, (_, i) => {
      const start = now - (30 - i) * 1000
      return events.filter((e) => {
        const t = e.ts.getTime()
        return t >= start && t < start + 1000
      }).length
    })
  }, [events])

  const handleUrlSave = () => {
    const trimmed = urlInput.trim()
    if (!trimmed) return
    localStorage.setItem("kwatch-url", trimmed)
    setUrl(trimmed)
    setShowSettings(false)
    reconnect()
  }

  return (
    <div className="min-h-screen bg-background text-foreground flex flex-col font-mono">
      {/* Header */}
      <header className="border-b border-border px-4 py-2.5 flex items-center justify-between shrink-0">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <Activity className="size-3.5 text-primary" />
            <span className="font-semibold text-sm tracking-tight">kwatch</span>
          </div>
          <span className="text-muted-foreground text-xs hidden sm:block">
            eBPF kernel process monitor
          </span>
        </div>

        <div className="flex items-center gap-1.5">
          {/* Status badge */}
          <div
            className={cn(
              "flex items-center gap-1.5 text-[10px] px-2 py-1 rounded border tracking-widest",
              status === "live" &&
                "border-primary/30 bg-primary/10 text-primary",
              status === "connecting" &&
                "border-yellow-500/30 bg-yellow-500/10 text-yellow-500",
              status === "disconnected" &&
                "border-destructive/30 bg-destructive/10 text-destructive",
            )}
          >
            <Circle
              className={cn(
                "size-1.5 fill-current",
                status === "live" && "animate-pulse",
              )}
            />
            {status === "live"
              ? "LIVE"
              : status === "connecting"
                ? "CONNECTING"
                : "DISCONNECTED"}
          </div>

          <Button
            variant="ghost"
            size="icon"
            onClick={togglePause}
            title={paused ? "Resume stream" : "Pause stream"}
          >
            {paused ? <Play /> : <Pause />}
          </Button>
          <Button
            variant="ghost"
            size="icon"
            onClick={clear}
            title="Clear all events"
          >
            <Trash2 />
          </Button>
          <Button
            variant={showSettings ? "secondary" : "ghost"}
            size="icon"
            onClick={() => setShowSettings((v) => !v)}
            title="Configure stream URL"
          >
            <Settings2 />
          </Button>
        </div>
      </header>

      {/* Settings panel */}
      {showSettings && (
        <div className="border-b border-border bg-muted/20 px-4 py-2.5 flex items-center gap-2 animate-in slide-in-from-top-1 fade-in duration-150">
          <span className="text-xs text-muted-foreground shrink-0">
            Stream URL
          </span>
          <input
            type="text"
            value={urlInput}
            onChange={(e) => setUrlInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleUrlSave()}
            autoFocus
            className="flex-1 bg-input/40 border border-border rounded-md px-2.5 py-1 text-xs focus:outline-none focus:ring-2 focus:ring-ring/30 focus:border-ring"
            placeholder="http://192.168.64.x:8080/stream"
          />
          <Button size="sm" onClick={handleUrlSave}>
            Apply
          </Button>
          <Button
            variant="ghost"
            size="icon-sm"
            onClick={() => setShowSettings(false)}
          >
            <X />
          </Button>
        </div>
      )}

      {/* Stats row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-px bg-border shrink-0">
        {(
          [
            {
              label: "TOTAL EVENTS",
              value: events.length.toLocaleString(),
              sub: null,
            },
            {
              label: "RATE",
              value: `${rate}/s`,
              sub: <Sparkline buckets={sparkline} />,
            },
            {
              label: "UNIQUE COMMANDS",
              value: uniqueCommands.toLocaleString(),
              sub: null,
            },
            {
              label: "UPTIME",
              value: status === "live" ? formatUptime(uptimeSecs) : "--:--:--",
              sub: null,
            },
          ] as const
        ).map(({ label, value, sub }) => (
          <div key={label} className="bg-background px-4 py-3 flex flex-col">
            <span className="text-[9px] text-muted-foreground tracking-widest mb-1">
              {label}
            </span>
            <span className="text-2xl font-semibold tabular-nums leading-none">
              {value}
            </span>
            {sub}
          </div>
        ))}
      </div>

      {/* Filter bar */}
      <div className="border-b border-border px-4 py-2 flex items-center gap-2 shrink-0">
        <Search className="size-3 text-muted-foreground shrink-0" />
        <input
          type="text"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          className="flex-1 bg-transparent text-xs focus:outline-none placeholder:text-muted-foreground"
          placeholder="Filter by command..."
        />
        {filter && (
          <>
            <span className="text-xs text-muted-foreground tabular-nums">
              {filtered.length.toLocaleString()} match
              {filtered.length !== 1 ? "es" : ""}
            </span>
            <button
              onClick={() => setFilter("")}
              className="text-muted-foreground hover:text-foreground transition-colors"
            >
              <X className="size-3" />
            </button>
          </>
        )}
      </div>

      {/* Event feed */}
      <div className="flex-1 overflow-auto">
        {paused && (
          <div className="sticky top-0 z-10 text-center text-[10px] tracking-widest py-1.5 bg-yellow-500/10 text-yellow-500 border-b border-yellow-500/20">
            PAUSED — {events.length.toLocaleString()} events buffered
          </div>
        )}

        <table className="w-full text-xs border-collapse">
          <thead className="sticky top-0 z-10 bg-background">
            <tr className="border-b border-border">
              <th className="px-4 py-2 text-left font-medium text-muted-foreground text-[9px] tracking-widest w-36">
                TIME
              </th>
              <th className="px-4 py-2 text-left font-medium text-muted-foreground text-[9px] tracking-widest w-20">
                PID
              </th>
              <th className="px-4 py-2 text-left font-medium text-muted-foreground text-[9px] tracking-widest">
                COMMAND
              </th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr>
                <td
                  colSpan={3}
                  className="text-center text-muted-foreground py-20 text-xs"
                >
                  {status === "connecting"
                    ? "Connecting to stream..."
                    : status === "disconnected"
                      ? "Not connected — check the stream URL in settings"
                      : events.length === 0
                        ? "Waiting for kernel events..."
                        : "No events match filter"}
                </td>
              </tr>
            ) : (
              filtered.map((event, i) => (
                <tr
                  key={event.id}
                  className={cn(
                    "border-b border-border/40 hover:bg-muted/20 transition-colors",
                    i === 0 &&
                      !paused &&
                      "animate-in slide-in-from-top-1 fade-in duration-150",
                  )}
                >
                  <td className="px-4 py-1.5 tabular-nums text-muted-foreground">
                    {formatTime(event.ts)}
                  </td>
                  <td className="px-4 py-1.5 tabular-nums text-muted-foreground">
                    {event.pid}
                  </td>
                  <td className="px-4 py-1.5 text-foreground font-medium">
                    {event.command}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Footer */}
      <footer className="border-t border-border px-4 py-2 flex items-center justify-between text-[10px] text-muted-foreground shrink-0 tracking-wide">
        <span>
          {filter
            ? `${filtered.length.toLocaleString()} of ${events.length.toLocaleString()} events`
            : `${events.length.toLocaleString()} events · max ${(2000).toLocaleString()} buffered`}
        </span>
        <span className="opacity-60">{url}</span>
      </footer>
    </div>
  )
}
