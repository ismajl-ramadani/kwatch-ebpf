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
import { useStream, type KernelEvent } from "@/hooks/useStream"

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

type TypeFilter = "all" | "exec" | "network" | "exit" | "open"

const TYPE_CONFIG = {
  exec:    { label: "EXEC",    cls: "text-emerald-400 bg-emerald-400/10 border-emerald-400/20" },
  exit:    { label: "EXIT",    cls: "text-slate-400   bg-slate-400/10   border-slate-400/20"   },
  connect: { label: "CONNECT", cls: "text-blue-400    bg-blue-400/10    border-blue-400/20"    },
  accept:  { label: "ACCEPT",  cls: "text-amber-400   bg-amber-400/10   border-amber-400/20"   },
  open:    { label: "OPEN",    cls: "text-rose-400    bg-rose-400/10    border-rose-400/20"     },
} as const

function getDetail(ev: KernelEvent): string | null {
  switch (ev.type) {
    case "exec": {
      const bin = ev.path || ev.exe || ""
      if (bin && ev.args) return `${bin} ${ev.args}`
      return bin || ev.args || null
    }
    case "exit":    return ev.duration ? `lived ${ev.duration}` : null
    case "connect": return ev.dst_addr ? `→ ${ev.dst_addr}` : null
    case "accept":  return ev.dst_addr ? `← ${ev.dst_addr}` : null
    case "open":    return ev.path || null
  }
}

export default function App() {
  const [url, setUrl] = useState(
    () => localStorage.getItem("kwatch-url") ?? DEFAULT_URL,
  )
  const [urlInput, setUrlInput] = useState(url)
  const [showSettings, setShowSettings] = useState(false)
  const [filter, setFilter] = useState("")
  const [typeFilter, setTypeFilter] = useState<TypeFilter>("all")
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

  const filtered = useMemo(() => {
    return events.filter((e) => {
      if (typeFilter === "exec"    && e.type !== "exec")    return false
      if (typeFilter === "exit"    && e.type !== "exit")    return false
      if (typeFilter === "open"    && e.type !== "open")    return false
      if (typeFilter === "network" && e.type !== "connect" && e.type !== "accept") return false
      if (filter && !e.command.toLowerCase().includes(filter.toLowerCase())) return false
      return true
    })
  }, [events, filter, typeFilter])

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

      {/* Type filter pills */}
      <div className="border-b border-border px-4 py-2 flex items-center gap-1.5 shrink-0">
        {(["all", "exec", "network", "exit", "open"] as const).map((t) => {
          const active = typeFilter === t
          const pillCls =
            t === "all"     ? "text-primary      bg-primary/10      border-primary/30"       :
            t === "exec"    ? "text-emerald-400  bg-emerald-400/10  border-emerald-400/30"   :
            t === "network" ? "text-blue-400     bg-blue-400/10     border-blue-400/30"      :
            t === "open"    ? "text-rose-400     bg-rose-400/10     border-rose-400/30"      :
                              "text-slate-400    bg-slate-400/10    border-slate-400/30"
          return (
            <button
              key={t}
              onClick={() => setTypeFilter(t)}
              className={cn(
                "text-[9px] tracking-widest px-2 py-0.5 rounded border transition-colors",
                active ? pillCls : "border-border text-muted-foreground hover:text-foreground hover:border-border/80",
              )}
            >
              {t.toUpperCase()}
            </button>
          )
        })}
        <div className="flex-1" />
        <Search className="size-3 text-muted-foreground shrink-0" />
        <input
          type="text"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          className="bg-transparent text-xs focus:outline-none placeholder:text-muted-foreground w-40"
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
              <th className="px-4 py-2 text-left font-medium text-muted-foreground text-[9px] tracking-widest w-24">
                TYPE
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
                  colSpan={4}
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
              filtered.map((event, i) => {
                const cfg = TYPE_CONFIG[event.type]
                const detail = getDetail(event)
                return (
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
                    <td className="px-4 py-1.5">
                      <span className={cn("text-[9px] tracking-widest px-1.5 py-0.5 rounded border", cfg.cls)}>
                        {cfg.label}
                      </span>
                    </td>
                    <td className="px-4 py-1.5 tabular-nums text-muted-foreground">
                      {event.pid}
                    </td>
                    <td className="px-4 py-1.5">
                      <div className="font-medium text-foreground">{event.command}</div>
                      {detail && (
                        <div className="text-[10px] text-muted-foreground/70 mt-0.5 truncate max-w-md">
                          {detail}
                        </div>
                      )}
                    </td>
                  </tr>
                )
              })
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
