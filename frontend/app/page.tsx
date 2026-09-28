"use client";

import * as React from "react";
import {
  API_BASE,
  RawEvent,
  DisplayEvent,
  Decision,
  normalize,
  isSecurityEvent,
  computeCounters,
  deriveStatus,
  SessionStatus,
} from "@/lib/tripwire";
import {
  Button,
  Card,
  CardHeader,
  CardTitle,
  CardContent,
  Badge,
  Textarea,
  Separator,
  Dialog,
} from "@/components/ui";
import { cn } from "@/lib/utils";

type RunState = "idle" | "running" | "completed" | "error";
type Filter = "ALL" | "ALLOWED" | "BLOCKED" | "SECURITY";

function decisionTone(d: Decision) {
  switch (d) {
    case "ALLOWED":
      return { tone: "ok" as const, symbol: "✓" };
    case "BLOCKED":
      return { tone: "block" as const, symbol: "✕" };
    case "QUARANTINED":
      return { tone: "poison" as const, symbol: "⚠" };
    case "FROZEN":
    case "TRIGGERED":
      return { tone: "freeze" as const, symbol: "❄" };
    case "LOCKED OUT":
      return { tone: "freeze" as const, symbol: "⛔" };
    default:
      return { tone: "muted" as const, symbol: "•" };
  }
}

function statusTone(s: SessionStatus) {
  if (s === "FROZEN" || s === "QUARANTINED" || s === "BLOCKED" || s === "ERROR")
    return "text-rose-400";
  if (s === "RUNNING") return "text-amber-400";
  if (s === "COMPLETED") return "text-emerald-400";
  return "text-slate-400";
}

export default function Page() {
  const [task, setTask] = React.useState("");
  const [sessionId, setSessionId] = React.useState<string | null>(null);
  const [runState, setRunState] = React.useState<RunState>("idle");
  const [events, setEvents] = React.useState<DisplayEvent[]>([]);
  const [filter, setFilter] = React.useState<Filter>("ALL");
  const [selected, setSelected] = React.useState<DisplayEvent | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  const [agentResponse, setAgentResponse] = React.useState<string | null>(null);

  const esRef = React.useRef<EventSource | null>(null);
  const pollRef = React.useRef<ReturnType<typeof setInterval> | null>(null);
  const idRef = React.useRef(0);
  const sessionRef = React.useRef<string | null>(null);

  const cleanup = React.useCallback(() => {
    esRef.current?.close();
    esRef.current = null;
    if (pollRef.current) clearInterval(pollRef.current);
    pollRef.current = null;
  }, []);

  React.useEffect(() => () => cleanup(), [cleanup]);

  const runAgent = async () => {
    if (!task.trim() || runState === "running") return;
    cleanup();
    setEvents([]);
    setSelected(null);
    setError(null);
    setAgentResponse(null);
    setRunState("running");
    idRef.current = 0;
    try {
      const res = await fetch(`${API_BASE}/run`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ task }),
      });
      if (!res.ok) throw new Error(`Backend returned ${res.status}`);
      const data = await res.json();
      const sid: string = data.session_id;
      setSessionId(sid);
      sessionRef.current = sid;

      // Live events: reuse the EXISTING global SSE stream, filtered to this run.
      const es = new EventSource(`${API_BASE}/dashboard/stream`);
      es.addEventListener("tripwire", (ev: MessageEvent) => {
        try {
          const raw: RawEvent = JSON.parse(ev.data);
          if (raw.session_id !== sessionRef.current) return; // only this run
          setEvents((prev) => [...prev, normalize(raw, idRef.current++)]);
        } catch {
          /* ignore malformed frame */
        }
      });
      es.onerror = () => {
        /* browser auto-reconnects; nothing to do */
      };
      esRef.current = es;

      // Run status: the agent runs in the background; poll for completion.
      pollRef.current = setInterval(async () => {
        try {
          const r = await fetch(`${API_BASE}/run/status?session_id=${sid}`);
          const s = await r.json();
          if (s.status === "completed") {
            setRunState("completed");
            setAgentResponse(typeof s.response === "string" ? s.response : null);
            cleanup();
          } else if (s.status === "error") {
            setRunState("error");
            setError(s.error || "Agent error");
            cleanup();
          }
        } catch {
          /* transient; keep polling */
        }
      }, 1500);
    } catch (e: unknown) {
      setRunState("error");
      setError(e instanceof Error ? e.message : "Failed to reach backend");
      cleanup();
    }
  };

  const counters = computeCounters(events);
  const status = deriveStatus(runState, events);
  const latestSecurity = [...events].reverse().find(isSecurityEvent) || null;

  const filtered = events.filter((e) => {
    if (filter === "ALL") return true;
    if (filter === "ALLOWED") return e.decision === "ALLOWED";
    if (filter === "BLOCKED")
      return ["BLOCKED", "QUARANTINED", "LOCKED OUT"].includes(e.decision);
    if (filter === "SECURITY") return isSecurityEvent(e);
    return true;
  });

  return (
    <main className="mx-auto max-w-[1400px] px-4 py-6 md:px-8">
      {/* Header */}
      <header className="mb-6 flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-3">
            <span className="text-2xl">🪤</span>
            <h1 className="text-xl font-bold tracking-tight">TRIPWIRE</h1>
            <span className="text-xs uppercase tracking-widest text-slate-500">
              Autonomous Agent Security Runtime
            </span>
          </div>
        </div>
        <div className="flex items-center gap-2 text-xs text-slate-400">
          <span className="h-2 w-2 rounded-full bg-emerald-500" />
          SYSTEM ONLINE
          <span className="ml-3 text-slate-600">session</span>
          <span className="font-mono text-slate-300">
            {sessionId ? sessionId.slice(0, 8) : "—"}
          </span>
          <span className={cn("ml-3 font-semibold", statusTone(status))}>{status}</span>
        </div>
      </header>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-[minmax(0,420px)_1fr]">
        {/* LEFT — Playground */}
        <div className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Adversarial Agent Playground</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <p className="text-sm text-slate-400">
                Give the agent an instruction. Tripwire will inspect the actions it
                attempts to take at runtime.
              </p>
              <Textarea
                rows={7}
                placeholder="Type any instruction here…"
                value={task}
                onChange={(e) => setTask(e.target.value)}
                disabled={runState === "running"}
              />
              <div className="flex items-center justify-between">
                <StatusPill runState={runState} />
                <div className="flex gap-2">
                  <Button
                    variant="outline"
                    onClick={() => setTask("")}
                    disabled={runState === "running"}
                  >
                    Clear
                  </Button>
                  <Button onClick={runAgent} disabled={runState === "running" || !task.trim()}>
                    ▶ RUN AGENT
                  </Button>
                </div>
              </div>
              {error && <p className="text-sm text-rose-400">{error}</p>}
            </CardContent>
          </Card>

          <AgentResponse text={agentResponse} runState={runState} />
          <LatestDecision event={latestSecurity} />
          <Timeline latest={events[events.length - 1] || null} status={status} />
        </div>

        {/* RIGHT — Live Security Monitor */}
        <div className="space-y-4">
          <Overview counters={counters} />

          <Card>
            <CardHeader className="flex items-center justify-between gap-2">
              <CardTitle>Live Security Monitor</CardTitle>
              <div className="flex flex-wrap gap-1">
                {(["ALL", "ALLOWED", "BLOCKED", "SECURITY"] as Filter[]).map((f) => (
                  <button
                    key={f}
                    onClick={() => setFilter(f)}
                    className={cn(
                      "rounded-md px-2.5 py-1 text-[11px] font-semibold uppercase tracking-wider transition-colors",
                      filter === f
                        ? "bg-emerald-500/20 text-emerald-300"
                        : "text-slate-500 hover:text-slate-300"
                    )}
                  >
                    {f === "SECURITY" ? "Security" : f}
                  </button>
                ))}
              </div>
            </CardHeader>
            <CardContent className="p-0">
              {filtered.length === 0 ? (
                <p className="p-6 text-sm text-slate-500">
                  {runState === "running"
                    ? "Waiting for the agent's first tool call…"
                    : "No activity yet. Enter an instruction and run the agent."}
                </p>
              ) : (
                <ul className="divide-y divide-edge">
                  {[...filtered].reverse().map((e) => {
                    const { tone, symbol } = decisionTone(e.decision);
                    return (
                      <li key={e.id}>
                        <button
                          onClick={() => setSelected(e)}
                          className="flex w-full items-center justify-between gap-3 px-4 py-3 text-left hover:bg-white/5"
                        >
                          <div className="min-w-0">
                            <div className="truncate font-mono text-sm text-slate-200">
                              {e.toolName}
                            </div>
                            <div className="truncate text-xs text-slate-500">
                              {e.layer}
                              {e.destination ? ` · ${e.destination}` : ""}
                              {e.riskScore !== undefined ? ` · risk ${e.riskScore}` : ""}
                            </div>
                          </div>
                          <Badge tone={tone}>
                            {symbol} {e.decision}
                          </Badge>
                        </button>
                      </li>
                    );
                  })}
                </ul>
              )}
            </CardContent>
          </Card>
        </div>
      </div>

      <EventDetail event={selected} onClose={() => setSelected(null)} />
    </main>
  );
}

function StatusPill({ runState }: { runState: RunState }) {
  const map = {
    idle: { c: "text-slate-400", t: "● Ready" },
    running: { c: "text-amber-400", t: "● Agent running" },
    completed: { c: "text-emerald-400", t: "✓ Completed" },
    error: { c: "text-rose-400", t: "✕ Error" },
  } as const;
  const s = map[runState];
  return <span className={cn("text-sm font-medium", s.c)}>{s.t}</span>;
}

function Overview({ counters }: { counters: ReturnType<typeof computeCounters> }) {
  const tiles = [
    { label: "Total Tool Calls", value: counters.totalToolCalls, c: "text-slate-100" },
    { label: "Allowed", value: counters.allowed, c: "text-emerald-400" },
    { label: "Blocked", value: counters.blocked, c: "text-orange-400" },
    { label: "Quarantined", value: counters.quarantined, c: "text-lime-400" },
    {
      label: "Current Risk",
      value: counters.risk,
      c:
        counters.risk === "HIGH"
          ? "text-rose-400"
          : counters.risk === "ELEVATED"
          ? "text-amber-400"
          : "text-emerald-400",
    },
  ];
  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
      {tiles.map((t) => (
        <Card key={t.label}>
          <CardContent className="py-3">
            <div className="text-[11px] uppercase tracking-wider text-slate-500">{t.label}</div>
            <div className={cn("mt-1 text-2xl font-bold tabular-nums", t.c)}>{t.value}</div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

function AgentResponse({ text, runState }: { text: string | null; runState: RunState }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Agent Response</CardTitle>
      </CardHeader>
      <CardContent>
        {runState === "running" ? (
          <p className="text-sm text-slate-500">Agent is working…</p>
        ) : text ? (
          <p className="whitespace-pre-wrap text-sm text-slate-200">{text}</p>
        ) : runState === "completed" ? (
          <p className="text-sm text-slate-500">
            The agent finished without a final text response (e.g. the session was
            frozen or blocked before it answered).
          </p>
        ) : (
          <p className="text-sm text-slate-500">
            The agent&apos;s final response will appear here after a run.
          </p>
        )}
      </CardContent>
    </Card>
  );
}

function LatestDecision({ event }: { event: DisplayEvent | null }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Latest Security Decision</CardTitle>
      </CardHeader>
      <CardContent>
        {!event ? (
          <p className="text-sm text-slate-500">No security action yet.</p>
        ) : (
          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <span className="text-lg">🔴</span>
              <span className="text-sm font-bold uppercase tracking-wide text-rose-300">
                {event.layer}
              </span>
            </div>
            <Field label="Tool" value={event.toolName} mono />
            <Field label="Decision" value={event.decision} />
            {event.destination && <Field label="Destination" value={event.destination} mono />}
            {event.riskScore !== undefined && (
              <Field label="Risk score" value={String(event.riskScore)} />
            )}
            {event.reason && <Field label="Reason" value={event.reason} />}
            <Field label="Action" value={event.action || event.decision} />
            <Field label="Backend execution" value={event.backendReached ? "REACHED" : "NOT REACHED"} />
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function Timeline({ latest, status }: { latest: DisplayEvent | null; status: SessionStatus }) {
  const denied =
    latest && ["BLOCKED", "QUARANTINED", "FROZEN", "TRIGGERED", "LOCKED OUT"].includes(latest.decision);
  const stages = [
    { k: "USER REQUEST", on: !!latest || status !== "READY" },
    { k: "AI AGENT", on: !!latest || status === "RUNNING" },
    { k: "MCP TOOL CALL", on: !!latest },
    { k: "TRIPWIRE INSPECTION", on: !!latest },
    {
      k: denied ? "SECURITY BLOCK" : "SECURITY DECISION",
      on: !!latest,
      danger: !!denied,
    },
    { k: denied ? "BACKEND — NOT REACHED" : "BACKEND", on: !!latest && !denied },
  ];
  return (
    <Card>
      <CardHeader>
        <CardTitle>Runtime Timeline</CardTitle>
      </CardHeader>
      <CardContent className="space-y-1.5">
        {stages.map((s, i) => (
          <div key={i} className="flex items-center gap-2">
            <span
              className={cn(
                "h-2 w-2 shrink-0 rounded-full",
                s.danger ? "bg-rose-500" : s.on ? "bg-emerald-500" : "bg-slate-700"
              )}
            />
            <span
              className={cn(
                "text-xs font-medium tracking-wide",
                s.danger ? "text-rose-300" : s.on ? "text-slate-200" : "text-slate-600"
              )}
            >
              {s.k}
            </span>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}

function Field({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="grid grid-cols-[130px_1fr] gap-2 text-sm">
      <span className="text-slate-500">{label}</span>
      <span className={cn("text-slate-200", mono && "font-mono break-all")}>{value}</span>
    </div>
  );
}

function EventDetail({ event, onClose }: { event: DisplayEvent | null; onClose: () => void }) {
  return (
    <Dialog open={!!event} onClose={onClose}>
      {event && (
        <>
          <div className="flex items-center justify-between border-b border-edge px-4 py-3">
            <h3 className="text-sm font-bold uppercase tracking-wide text-slate-200">
              {event.eventType.replace(/_/g, " ")}
            </h3>
            <button onClick={onClose} className="text-slate-500 hover:text-slate-200">
              ✕
            </button>
          </div>
          <div className="space-y-2 p-4">
            <Field label="Tool" value={event.toolName} mono />
            <Field label="Timestamp" value={new Date(event.ts).toLocaleTimeString()} />
            <Field label="Session ID" value={event.sessionId} mono />
            <Field label="Decision" value={event.decision} />
            <Field label="Security layer" value={event.layer} />
            {event.reason && <Field label="Reason" value={event.reason} />}
            <Field label="Action" value={event.action || event.decision} />
            {event.destination && <Field label="Destination" value={event.destination} mono />}
            {event.riskScore !== undefined && (
              <Field label="Risk score" value={String(event.riskScore)} />
            )}
            {event.severity && <Field label="Severity" value={event.severity} />}
            <Field label="Backend execution" value={event.backendReached ? "REACHED" : "NOT REACHED"} />
            {event.raw.arguments && Object.keys(event.raw.arguments).length > 0 && (
              <div className="pt-1">
                <div className="mb-1 text-slate-500">Arguments</div>
                <pre className="max-h-40 overflow-auto rounded-md border border-edge bg-black/40 p-2 text-xs text-slate-300">
                  {JSON.stringify(event.raw.arguments, null, 2)}
                </pre>
              </div>
            )}
          </div>
        </>
      )}
    </Dialog>
  );
}
