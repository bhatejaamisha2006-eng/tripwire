"use client";
// HERO — the live security pipeline for the current tool call.
//
// Every node's state comes from pipelineFor(), i.e. from the backend's own
// check trace for the call. Tripwire evaluates those checks in milliseconds,
// so the packet replays the trace stage by stage at a readable pace; it never
// shows a stage the backend did not reach, and never implies a duration.
import * as React from "react";
import type { AgentPhase, CallRecord, Stage, StageState, Verdict } from "@/lib/tripwire";
import { caughtBy, finalDecision, primaryArg, verdictOf } from "@/lib/tripwire";
import { cn } from "@/lib/utils";

const STEP_MS = 260;

const COLOR: Record<StageState, string> = {
  idle: "#334155",
  planning: "var(--tw-plan)",
  active: "var(--tw-proc)",
  done: "#2fae84",
  allowed: "var(--tw-ok)",
  threat: "var(--tw-threat)",
  frozen: "var(--tw-threat)",
  quarantined: "var(--tw-poison)",
  skipped: "#334155",
};

function stageColor(s: Stage) {
  // Behavioral intelligence reads violet whenever it has a real score.
  if (s.key === "behavior" && s.state === "done") return "var(--tw-behavior)";
  return COLOR[s.state];
}

function usePrefersReducedMotion() {
  const [reduced, setReduced] = React.useState(false);
  React.useEffect(() => {
    const m = window.matchMedia("(prefers-reduced-motion: reduce)");
    setReduced(m.matches);
    const on = () => setReduced(m.matches);
    m.addEventListener("change", on);
    return () => m.removeEventListener("change", on);
  }, []);
  return reduced;
}

/** How many stages of the current call to show. Time-based, not a timer
 *  chain: background tabs throttle timers, so the stage is derived from the
 *  time since this call first appeared and jumps to the right place on the
 *  first frame after throttling ends. */
function useReveal(callKey: string, target: number, reduced: boolean) {
  const startRef = React.useRef<{ key: string; at: number }>({ key: callKey, at: 0 });
  if (startRef.current.key !== callKey) startRef.current = { key: callKey, at: performance.now() };
  const [, frame] = React.useState(0);
  const elapsed = performance.now() - startRef.current.at;
  const revealed = reduced ? target : Math.min(target, Math.floor(elapsed / STEP_MS));
  React.useEffect(() => {
    if (revealed >= target) return;
    const id = requestAnimationFrame(() => frame((n) => n + 1));
    return () => cancelAnimationFrame(id);
  });
  return revealed;
}

export function PipelineHero({
  stages,
  call,
  phase,
  sessionFrozen,
  callNumber,
  elapsedMs,
}: {
  stages: Stage[];
  call?: CallRecord;
  phase: AgentPhase;
  sessionFrozen: boolean;
  callNumber: number;
  elapsedMs: number;
}) {
  const reduced = usePrefersReducedMotion();
  const planning = phase.state === "thinking" || stages[0].state === "planning";
  const final = finalDecision(call);
  const target = Math.max(
    0,
    stages.reduce((max, s, i) => (s.state !== "idle" ? i : max), 0)
  );
  const callKey = call ? `${call.id}` : "none";
  const revealed = useReveal(callKey, target, reduced);
  const settled = revealed >= target;

  // Measure orb centers so the packet can ride the spine.
  const orbRefs = React.useRef<(HTMLSpanElement | null)[]>([]);
  const trackRef = React.useRef<HTMLDivElement>(null);
  const [centers, setCenters] = React.useState<number[]>([]);
  React.useLayoutEffect(() => {
    const measure = () => {
      const top = trackRef.current?.getBoundingClientRect().top ?? 0;
      setCenters(
        orbRefs.current.map((el) => {
          const r = el?.getBoundingClientRect();
          return r ? r.top - top + r.height / 2 : 0;
        })
      );
    };
    measure();
    window.addEventListener("resize", measure);
    return () => window.removeEventListener("resize", measure);
  }, [stages.length]);

  const verdict = settled ? verdictOf(final) : undefined;
  const packetStage = stages[Math.min(revealed, stages.length - 1)];
  const packetColor = packetStage ? stageColor(packetStage) : "var(--tw-proc)";
  const showPacket = !!call && !planning && centers.length > 0;

  return (
    <section
      className={cn(
        "tw-panel relative overflow-hidden",
        sessionFrozen && "border-rose-500/60 tw-threat"
      )}
      style={sessionFrozen ? ({ "--c": "rgba(251,113,133,0.55)" } as React.CSSProperties) : undefined}
      aria-label="Live agent execution"
    >
      {sessionFrozen && <div className="tw-lockdown pointer-events-none absolute inset-0 z-0" aria-hidden />}

      <header className="relative flex flex-wrap items-center justify-between gap-2 border-b border-edge px-5 py-3.5">
        <div className="flex items-center gap-2.5">
          <span className="relative flex h-2.5 w-2.5">
            <span
              className={cn(
                "absolute inline-flex h-full w-full rounded-full opacity-60",
                planning ? "bg-amber-400 tw-blink" : call && !settled ? "bg-cyan-400 tw-blink" : "bg-slate-600"
              )}
            />
            <span className={cn("relative inline-flex h-2.5 w-2.5 rounded-full", planning ? "bg-amber-400" : call && !settled ? "bg-cyan-400" : "bg-slate-600")} />
          </span>
          <h2 className="tw-label !text-slate-300">Live Agent Execution</h2>
        </div>
        <span className="font-mono text-[11px] text-slate-500">
          {call ? `tool call #${callNumber}` : "no tool calls yet"}
        </span>
        {sessionFrozen && (
          <span className="absolute right-4 top-12 z-10 rotate-[-4deg] rounded-md border-2 border-rose-400/80 bg-rose-500/10 px-3 py-1 font-mono text-sm font-black tracking-[0.2em] text-rose-200 shadow-[0_0_30px_-6px_rgba(251,113,133,0.8)] md:top-3.5 md:right-40">
            ❄ SESSION FROZEN
          </span>
        )}
      </header>

      {planning && <PlanningStrip phase={phase} elapsedMs={elapsedMs} />}

      <div className="relative z-10 px-4 py-5 sm:px-6">
        <div ref={trackRef} className="relative">
          {/* Packet: a halo carrying the real tool call down the spine, parked at the
              furthest stage revealed so far. */}
          {showPacket && (
            <div
              className="tw-packet pointer-events-none absolute left-[-6px] top-0 z-20"
              style={{ transform: `translateY(${(centers[Math.min(revealed, centers.length - 1)] ?? 0) - 26}px)` }}
              aria-hidden
            >
              <span
                className="tw-bob block h-[52px] w-[52px] rounded-full border-2"
                style={{ borderColor: packetColor, "--c": packetColor, background: `radial-gradient(circle, transparent 55%, color-mix(in srgb, ${packetColor} 22%, transparent))` } as React.CSSProperties}
              />
            </div>
          )}

          <ol className="relative">
            {stages.map((s, i) => {
              const shown = i <= revealed || (planning && i === 0);
              const st: StageState = shown ? s.state : "idle";
              const color = shown ? stageColor(s) : COLOR.idle;
              const dim = planning && i > 0;
              const next = stages[i + 1];
              const nextShown = i + 1 <= revealed;
              const flowing = shown && next && !nextShown && (st === "active" || st === "done" || st === "planning");
              const connColor = nextShown ? (next && (next.state === "threat" || next.state === "frozen") ? COLOR.threat : color) : COLOR.idle;
              const lit = st !== "idle" && st !== "skipped";
              const pulsing = st === "active" || st === "planning";
              const threat = st === "threat" || st === "frozen";
              return (
                <li key={s.key} className={cn("relative flex gap-4 sm:gap-5", dim && "opacity-45 transition-opacity")}>
                  {/* Spine: orb + connector */}
                  <div className="flex w-10 shrink-0 flex-col items-center">
                    <span
                      ref={(el) => {
                        orbRefs.current[i] = el;
                      }}
                      className={cn(
                        "relative z-10 grid h-10 w-10 place-items-center rounded-full border-2 bg-[#0a0f16] text-lg transition-all duration-500",
                        pulsing && "tw-pulse",
                        threat && "tw-threat",
                        st === "skipped" && "border-dashed"
                      )}
                      style={{ borderColor: color, "--c": color } as React.CSSProperties}
                      aria-hidden
                    >
                      <span className={cn(!lit && "opacity-40 grayscale")}>{s.icon}</span>
                    </span>
                    {next && (
                      <span
                        className={cn("my-1 w-0.5 flex-1 rounded-full transition-colors duration-500", flowing && "tw-flow")}
                        style={
                          flowing
                            ? ({ "--c": st === "planning" ? COLOR.planning : COLOR.active } as React.CSSProperties)
                            : { background: connColor, opacity: nextShown ? 0.7 : 0.35 }
                        }
                      />
                    )}
                  </div>

                  {/* Node card */}
                  <div
                    key={`${callKey}-${s.key}-${shown ? st : "pending"}`}
                    className={cn(
                      "mb-2.5 flex min-w-0 flex-1 items-center justify-between gap-3 rounded-xl border px-4 py-2.5 transition-colors duration-500",
                      lit ? "tw-pop" : "",
                      st === "skipped" && "border-dashed"
                    )}
                    style={{
                      borderColor: lit ? `color-mix(in srgb, ${color} 55%, transparent)` : "#1a2331",
                      background: lit ? `color-mix(in srgb, ${color} 9%, rgba(10,15,22,0.6))` : "rgba(10,15,22,0.45)",
                    }}
                  >
                    <div className="min-w-0">
                      <div className={cn("tw-label", lit && "!text-slate-200")}>{s.title}</div>
                      <div className={cn("mt-0.5 truncate font-mono text-[13px]", lit ? "text-slate-100" : "text-slate-600")} title={shown ? s.detail : undefined}>
                        {shown ? s.detail : "—"}
                      </div>
                    </div>
                    <span
                      className="shrink-0 rounded-md px-2 py-1 font-mono text-[10.5px] font-bold tracking-[0.14em]"
                      style={{
                        color: lit ? color : "#475569",
                        background: lit ? `color-mix(in srgb, ${color} 14%, transparent)` : "transparent",
                      }}
                    >
                      {shown ? s.status : "STANDBY"}
                    </span>
                  </div>
                </li>
              );
            })}
          </ol>
        </div>

        <VerdictBand verdict={verdict} call={call} planning={planning} settled={settled} />
      </div>
    </section>
  );
}

function PlanningStrip({ phase, elapsedMs }: { phase: AgentPhase; elapsedMs: number }) {
  return (
    <div className="relative z-10 border-b border-amber-400/20 bg-amber-400/[0.05] px-5 py-3">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <span className="text-xl" aria-hidden>
            🧠
          </span>
          <div>
            <div className="font-mono text-xs font-bold tracking-[0.2em] text-amber-200">AGENT PLANNING NEXT ACTION</div>
            <div className="text-xs text-slate-400">
              {phase.model ?? "Local model"} · step {phase.step}
              {phase.maxSteps ? ` of ${phase.maxSteps}` : ""} — Tripwire inspects whatever it does next
            </div>
          </div>
        </div>
        <div className="text-right">
          <div className="tw-label">Elapsed</div>
          <div className="font-mono text-xl tabular-nums text-amber-100">{fmt(elapsedMs)}</div>
        </div>
      </div>
      <div className="mt-2.5 h-[3px] overflow-hidden rounded-full bg-white/5" aria-hidden>
        <div className="tw-sweep h-full w-1/5 rounded-full bg-gradient-to-r from-transparent via-amber-300 to-transparent" />
      </div>
    </div>
  );
}

function fmt(ms: number) {
  const s = Math.max(0, Math.floor(ms / 1000));
  return `${String(Math.floor(s / 60)).padStart(2, "0")}:${String(s % 60).padStart(2, "0")}`;
}

const VERDICT_LOOK: Record<Verdict, { icon: string; title: string; cls: string }> = {
  allowed: { icon: "✓", title: "ACTION ALLOWED", cls: "border-emerald-400/50 bg-emerald-400/[0.07] text-emerald-200" },
  blocked: { icon: "⚠", title: "THREAT DETECTED · ACTION BLOCKED", cls: "border-rose-400/60 bg-rose-500/[0.09] text-rose-100" },
  frozen: { icon: "⚠", title: "THREAT DETECTED · SESSION FROZEN", cls: "border-rose-400/70 bg-rose-500/[0.12] text-rose-100" },
  quarantined: { icon: "☣", title: "TOOL QUARANTINED", cls: "border-fuchsia-400/60 bg-fuchsia-500/[0.08] text-fuchsia-100" },
};

function VerdictBand({
  verdict,
  call,
  planning,
  settled,
}: {
  verdict?: Verdict;
  call?: CallRecord;
  planning: boolean;
  settled: boolean;
}) {
  if (!call) {
    return (
      <div className="mt-2 rounded-xl border border-dashed border-edge px-5 py-4 text-center font-mono text-xs tracking-[0.2em] text-slate-500">
        AWAITING AGENT ACTIVITY
      </div>
    );
  }
  if (!verdict) {
    return (
      <div className="mt-2 rounded-xl border border-cyan-400/40 bg-cyan-400/[0.05] px-5 py-4 font-mono text-sm font-bold tracking-[0.2em] text-cyan-200">
        ◌ INSPECTING {call.toolName.toUpperCase()}
      </div>
    );
  }
  const look = VERDICT_LOOK[verdict];
  const layer = caughtBy(call);
  const final = finalDecision(call);
  const sub =
    verdict === "allowed"
      ? "Passed every Tripwire layer · the backend executed it"
      : `${final?.type === "frozen_block" ? "Refused by" : "Caught by"} ${layer} · ${
          verdict === "frozen" ? "every further call is refused" : verdict === "quarantined" ? "the tool can never run" : "the backend was never reached"
        }`;
  return (
    <div
      key={`${call.id}-${verdict}`}
      className={cn("tw-rise mt-2 flex items-center gap-4 rounded-xl border px-5 py-4", look.cls, planning && settled && "opacity-60")}
      role="status"
    >
      <span className="text-3xl leading-none" aria-hidden>
        {look.icon}
      </span>
      <div className="min-w-0">
        <div className="font-mono text-base font-black tracking-[0.14em] sm:text-lg">{look.title}</div>
        <div className="truncate text-sm opacity-80">
          <span className="font-mono">
            {call.toolName}({primaryArg(call.args) ?? ""})
          </span>{" "}
          — {sub}
        </div>
      </div>
    </div>
  );
}
