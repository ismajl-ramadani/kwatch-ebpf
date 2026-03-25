import { useState, useEffect, useRef, useCallback } from "react"

export type KernelEvent = {
  id: string
  ts: Date
  type: "exec" | "exit" | "connect" | "accept" | "open"
  pid: number
  ppid?: number
  uid: number
  gid: number
  command: string
  path?: string
  exe?: string
  cwd?: string
  memory_kb?: number
  fd_count?: number
  duration?: string  // exit only
  dst_addr?: string  // connect/accept only
  args?: string      // exec only: space-joined argv[1..]
}

export type ConnectionStatus = "connecting" | "live" | "disconnected"

const MAX_EVENTS = 2000
const RECONNECT_DELAY = 3000

export function useStream(url: string) {
  const [events, setEvents] = useState<KernelEvent[]>([])
  const [status, setStatus] = useState<ConnectionStatus>("disconnected")
  const [paused, setPaused] = useState(false)
  const esRef = useRef<EventSource | null>(null)
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const pausedRef = useRef(false)
  const seqRef = useRef(0)

  const connect = useCallback(() => {
    esRef.current?.close()
    if (timerRef.current) clearTimeout(timerRef.current)

    setStatus("connecting")
    const es = new EventSource(url)
    esRef.current = es

    es.onopen = () => setStatus("live")

    es.onmessage = (e) => {
      if (pausedRef.current) return
      try {
        const raw = JSON.parse(e.data) as Record<string, unknown>
        const ev: KernelEvent = {
          id: `${Date.now()}-${++seqRef.current}`,
          ts: new Date(),
          type: (raw.type as KernelEvent["type"]) ?? "exec",
          pid: (raw.pid as number) ?? 0,
          ppid: raw.ppid as number | undefined,
          uid: (raw.uid as number) ?? 0,
          gid: (raw.gid as number) ?? 0,
          command: (raw.command as string) ?? "",
          path: raw.path as string | undefined,
          exe: raw.exe as string | undefined,
          cwd: raw.cwd as string | undefined,
          memory_kb: raw.memory_kb as number | undefined,
          fd_count: raw.fd_count as number | undefined,
          duration: raw.duration as string | undefined,
          dst_addr: raw.dst_addr as string | undefined,
          args: raw.args as string | undefined,
        }
        setEvents((prev) => {
          const next = [ev, ...prev]
          return next.length > MAX_EVENTS ? next.slice(0, MAX_EVENTS) : next
        })
      } catch {
        /* ignore malformed frames */
      }
    }

    es.onerror = () => {
      setStatus("disconnected")
      es.close()
      esRef.current = null
      timerRef.current = setTimeout(connect, RECONNECT_DELAY)
    }
  }, [url])

  useEffect(() => {
    connect()
    return () => {
      esRef.current?.close()
      if (timerRef.current) clearTimeout(timerRef.current)
    }
  }, [connect])

  const togglePause = useCallback(() => {
    setPaused((p) => {
      pausedRef.current = !p
      return !p
    })
  }, [])

  const clear = useCallback(() => setEvents([]), [])

  return { events, status, paused, togglePause, clear, reconnect: connect }
}
