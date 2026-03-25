import { useState, useEffect, useRef, useCallback } from "react"

export type KernelEvent = {
  id: string
  pid: number
  command: string
  ts: Date
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
        const raw = JSON.parse(e.data) as { pid: number; command: string }
        const ev: KernelEvent = {
          id: `${Date.now()}-${++seqRef.current}`,
          pid: raw.pid,
          command: raw.command,
          ts: new Date(),
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
