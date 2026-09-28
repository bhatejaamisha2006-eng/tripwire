"use client";

import * as React from "react";
import {
  API_BASE,
  RawEvent,
  DisplayEvent,
  Scenario,
  normalize,
  groupCalls,
  finalDecision,
  pipelineFor,
  agentPhase,
  sessionState,
  layerActivity,
  riskSeries,
  timelineItems,
  caughtBy,
  THREAT_TYPES,
  FREEZING_TYPES,
} from "@/lib/tripwire";
import { Dialog } from "@/components/ui";
import { StatusBar } from "@/components/status-bar";
import { AttackConsole } from "@/components/attack-console";
import { PipelineHero } from "@/components/pipeline-hero";
import { ToolCallPanel } from "@/components/tool-call-panel";
import { LayerStatus } from "@/components/layer-status";
import { RiskChart } from "@/components/risk-chart";
import { EventTimeline } from "@/components/event-timeline";

type RunState = "idle" | "running" | "completed" | "error";
type Health = { online: boolean; poisonedTool: boolean; accessKeyRequired: boolean } | null;

const MAX_BUFFERED_SESSIONS = 20;

/** Re-render every `ms` while `on` — drives the elapsed display. */
function useTicker(on: boolean, ms = 1000) {
  const [, setN] = React.useState(0);
  React.useEffect(() => {
    if (!on) return;
    const t = setInterval(() => setN((n) => n + 1), ms);
    return () => clearInterval(t);
  }, [on, ms]);
}

export default function Page() {
  const [task, setTask] = React.useState("");
  const [scenarioId, setScenarioId] = React.useState<string | null>(null);
  const [runScenarioId, setRunScenarioId] = React.useState<string | null>(null);
  const [sessionId, setSessionId] = React.useState<string | null>(null);
  const [runState, setRunState] = React.useState<RunState>("idle");
  const [events, setEvents] = React.useState<DisplayEvent[]>([]);
  const [selected, setSelected] = React.useState<DisplayEvent | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  const [agentResponse, setAgentResponse] = React.useState<string | null>(null);
  const [streamUp, setStreamUp] = React.useState(false);
  const [health, setHealth] = React.useState<Health>(null);
  const [accessCode, setAccessCode] = React.useState("");

  // Every session's events, buffered from the moment the page opens the
  // stream — so events broadcast before POST /run returns are not lost.
  const bufferRef = React.useRef(new Map<string, DisplayEvent[]>());
  const seenRef = React.useRef(new Set<string>());
  const sessionRef = React.useRef<string | null>(null);
  const pollRef = React.useRef<ReturnType<typeof setInterval> | null>(null);

  React.useEffect(() => {
    try {
      setAccessCode(localStorage.getItem("tripwire-access-code") || "");
    } catch {
      /* storage unavailable */
    }
  }, []);
  const updateAccessCode = (value: string) => {
    setAccessCode(value);
    try {
      localStorage.setItem("tripwire-access-code", value);
    } catch {
      /* storage unavailable */
    }
  };

  // Backend health: liveness, the S7 flag, and whether an access code is needed.
  React.useEffect(() => {
    let alive = true;
    const check = async () => {
      try {
        const r = await fetch(`${API_BASE}/healthz`);
        const j = await r.json();
        if (alive)
          setHealth({ online: r.ok, poisonedTool: !!j.poisoned_tool_enabled, accessKeyRequired: !!j.access_key_required });
      } catch {
        if (alive) setHealth({ online: false, poisonedTool: false, accessKeyRequired: false });
      }
    };
    check();
    const t = setInterval(check, 30000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, []);

  const stopPolling = () => {
    if (pollRef.current) clearInterval(pollRef.current);
    pollRef.current = null;
  };
  React.useEffect(() => stopPolling, []);

  // Completion + final answer. SSE's session_completed triggers this; polling
  // is the fallback if the stream is down.
  const refreshStatus = React.useCallback(async (sid: string) => {
    try {
      const r = await fetch(`${API_BASE}/run/status?session_id=${sid}`);
      const s = await r.json();
      if (sid !== sessionRef.current) return;
      if (s.status === "completed") {
        setRunState("completed");
        setAgentResponse(typeof s.response === "string" ? s.response : null);
        stopPolling();
      } else if (s.status === "error") {
        setRunState("error");
        setError(s.error || "Agent error");
        stopPolling();
      }
    } catch {
      /* transient; keep polling */
    }
  }, []);

  // One long-lived SSE subscription. The server replays recent persisted
  // history on every (re)connect; event_id makes replays idempotent.
  React.useEffect(() => {
    const es = new EventSource(`${API_BASE}/dashboard/stream`);
    es.onopen = () => setStreamUp(true);
    es.onerror = () => setStreamUp(false); // the browser reconnects on its own
    es.addEventListener("tripwire", (ev: MessageEvent) => {
      let raw: RawEvent;
      try {
        raw = JSON.parse(ev.data);
      } catch {
        return;
      }
      if (raw.event_id == null || !raw.session_id) return;
      const id = String(raw.event_id);
      if (seenRef.current.has(id)) return;
      seenRef.current.add(id);
      const e = normalize(raw);
      const buf = bufferRef.current;
      if (!buf.has(raw.session_id)) {
        buf.set(raw.session_id, []);
        if (buf.size > MAX_BUFFERED_SESSIONS) buf.delete(buf.keys().next().value as string);
      }
      buf.get(raw.session_id)!.push(e);
      if (raw.session_id === sessionRef.current) {
        setEvents((prev) => [...prev, e]);
        if (raw.event_type === "session_completed") void refreshStatus(raw.session_id);
      }
    });
    return () => es.close();
  }, [refreshStatus]);

  const selectScenario = (s: Scenario) => {
    setScenarioId(s.id);
    setTask(s.task);
  };

  const runAgent = async () => {
    if (!task.trim() || runState === "running") return;
    stopPolling();
    sessionRef.current = null;
    setEvents([]);
    setSelected(null);
    setError(null);
    setAgentResponse(null);
    setRunState("running");
    setRunScenarioId(scenarioId);
    try {
      const res = await fetch(`${API_BASE}/run`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(accessCode.trim() ? { "X-Tripwire-Key": accessCode.trim() } : {}),
        },
        body: JSON.stringify({ task }),
      });
      if (!res.ok) {
        const detail = await res.json().catch(() => null);
        throw new Error(detail?.error || `Backend returned ${res.status}`);
      }
      const sid: string = (await res.json()).session_id;
      sessionRef.current = sid;
      setSessionId(sid);
      setEvents([...(bufferRef.current.get(sid) || [])]);
      pollRef.current = setInterval(() => refreshStatus(sid), 3000);
    } catch (e: unknown) {
      setRunState("error");
      setError(e instanceof Error ? e.message : "Failed to reach backend");
    }
  };

  // ------------------------------------------------------------ derived view

  const running = runState === "running";
  const calls = groupCalls(events);
  const phase = agentPhase(events, running);
  useTicker(running && phase.state === "thinking");
  const lastCall = calls[calls.length - 1];
  const stages = pipelineFor(lastCall, phase);
  const state = sessionState(runState, events);
  const activity = layerActivity(events);
  const risk = riskSeries(calls);
  const items = timelineItems(events);
  const last = finalDecision(lastCall);
  const hotLayer =
    last && THREAT_TYPES.has(last.type) ? (FREEZING_TYPES.has(last.type) && last.type !== "frozen_block" ? caughtBy(lastCall) : last.layer) : undefined;
  const callNumber = calls.filter((c) => !c.discovery).length;
  const planningMs = phase.state === "thinking" && phase.since ? Date.now() - phase.since : 0;

  return (
    <>
      <StatusBar state={state} sessionId={sessionId} backendOnline={health ? health.online : null} streamLive={streamUp} />

      <main className="mx-auto max-w-[1680px] px-4 pb-10 pt-5 md:px-6">
        <div className="grid grid-cols-1 gap-5 lg:grid-cols-[280px_minmax(0,1fr)] xl:grid-cols-[270px_minmax(0,1fr)_340px] 2xl:grid-cols-[300px_minmax(0,1fr)_400px]">
          {/* LEFT — attack console */}
          <div className="order-2 min-w-0 space-y-5 lg:order-1 xl:col-start-1 xl:row-start-1">
            <AttackConsole
              selectedId={scenarioId}
              runningId={runScenarioId}
              running={running}
              poisonedToolEnabled={health ? health.poisonedTool : null}
              accessKeyRequired={!!health?.accessKeyRequired}
              task={task}
              accessCode={accessCode}
              error={error}
              onSelect={selectScenario}
              onTaskChange={(t) => {
                setTask(t);
                setScenarioId(null);
              }}
              onAccessCodeChange={updateAccessCode}
              onRun={runAgent}
            />
            <AgentAnswer text={agentResponse} runState={runState} />
          </div>

          {/* CENTER — hero pipeline */}
          <div className="order-1 min-w-0 lg:order-2 xl:col-start-2 xl:row-start-1">
            <PipelineHero
              stages={stages}
              call={lastCall}
              phase={phase}
              sessionFrozen={state === "FROZEN"}
              callNumber={callNumber}
              elapsedMs={planningMs}
            />
          </div>

          {/* RIGHT — current tool call + layers (spans both rows on desktop) */}
          <div className="order-3 grid min-w-0 grid-cols-1 gap-5 md:grid-cols-2 lg:col-span-2 xl:col-span-1 xl:col-start-3 xl:row-span-2 xl:row-start-1 xl:grid-cols-1 xl:content-start">
            <ToolCallPanel call={lastCall} />
            <LayerStatus activity={activity} hotLayer={hotLayer} />
          </div>

          {/* BELOW — behavioral analysis + timeline */}
          <div className="order-4 grid min-w-0 grid-cols-1 gap-5 lg:col-span-2 lg:grid-cols-[minmax(0,2fr)_minmax(0,3fr)] xl:col-start-1 xl:row-start-2">
            <RiskChart points={risk.points} threshold={risk.threshold} />
            <EventTimeline items={items} onSelect={(key) => setSelected(events.find((e) => e.key === key) || null)} />
          </div>
        </div>
      </main>

      <EventDetail event={selected} onClose={() => setSelected(null)} />
    </>
  );
}

function AgentAnswer({ text, runState }: { text: string | null; runState: RunState }) {
  if (runState === "idle") return null;
  return (
    <details className="tw-panel group p-4" open={!!text}>
      <summary className="tw-label flex cursor-pointer list-none items-center justify-between !text-slate-300">
        Agent final answer
        <span className="text-slate-500 group-open:rotate-90">▸</span>
      </summary>
      <div className="mt-3 max-h-72 overflow-y-auto whitespace-pre-wrap text-[13px] leading-relaxed text-slate-300">
        {runState === "running"
          ? "The agent is still working…"
          : text || "No final answer — Tripwire froze the session before the agent could reply."}
      </div>
    </details>
  );
}

function EventDetail({ event, onClose }: { event: DisplayEvent | null; onClose: () => void }) {
  return (
    <Dialog open={!!event} onClose={onClose}>
      {event && (
        <>
          <div className="flex items-center justify-between border-b border-edge px-4 py-3">
            <h3 className="font-mono text-sm font-bold uppercase tracking-[0.15em] text-slate-200">{event.type.replace(/_/g, " ")}</h3>
            <button onClick={onClose} className="text-slate-500 hover:text-slate-200" aria-label="Close">
              ✕
            </button>
          </div>
          <div className="space-y-2 p-4 text-sm">
            <Row label="Tool" value={event.toolName} />
            <Row label="Time" value={new Date(event.ts).toLocaleTimeString([], { hour12: false })} />
            <Row label="Event ID" value={String(event.raw.event_id)} />
            <Row label="Decision" value={event.decision} />
            <Row label="Layer" value={event.layer} />
            {event.raw.reason && <Row label="Reason" value={event.raw.reason} />}
            {event.raw.destination && <Row label="Destination" value={event.raw.destination} />}
            {event.raw.risk_score !== undefined && <Row label="Risk" value={String(event.raw.risk_score)} />}
            {event.raw.checks && event.raw.checks.length > 0 && (
              <div className="pt-1">
                <div className="tw-label mb-1.5">Checks evaluated, in order</div>
                <ul className="space-y-1 font-mono text-xs">
                  {event.raw.checks.map((c) => (
                    <li key={c.layer} className="flex justify-between rounded border border-edge bg-black/30 px-2 py-1">
                      <span className="text-slate-300">{c.layer}</span>
                      <span className={c.verdict === "pass" || c.verdict === "n/a" ? "text-slate-500" : "font-bold text-rose-300"}>
                        {c.verdict.toUpperCase()}
                        {c.risk_score != null ? ` · ${c.risk_score}` : ""}
                      </span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
            {event.raw.arguments && Object.keys(event.raw.arguments).length > 0 && (
              <div className="pt-1">
                <div className="tw-label mb-1.5">Arguments · redacted by Tripwire</div>
                <pre className="max-h-40 overflow-auto whitespace-pre-wrap break-all rounded-md border border-edge bg-black/40 p-2 font-mono text-xs text-slate-300">
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

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="grid grid-cols-[92px_1fr] gap-2">
      <span className="text-slate-500">{label}</span>
      <span className="break-all font-mono text-xs leading-5 text-slate-200">{value}</span>
    </div>
  );
}
