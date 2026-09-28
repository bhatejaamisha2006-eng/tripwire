"use client";
// Scenario launcher. A preset only fills in an instruction for the real agent.
import * as React from "react";
import type { Scenario } from "@/lib/tripwire";
import { SCENARIOS } from "@/lib/tripwire";
import { cn } from "@/lib/utils";

const ACCENT: Record<Scenario["accent"], string> = {
  emerald: "#34d399",
  amber: "#fbbf24",
  rose: "#fb7185",
  cyan: "#22d3ee",
  violet: "#9085e9",
  fuchsia: "#e879f9",
  sky: "#7dd3fc",
};

export function AttackConsole({
  selectedId,
  runningId,
  running,
  accessKeyRequired,
  task,
  accessCode,
  error,
  onSelect,
  onTaskChange,
  onAccessCodeChange,
  onRun,
}: {
  selectedId: string | null;
  runningId: string | null;
  running: boolean;
  accessKeyRequired: boolean;
  task: string;
  accessCode: string;
  error: string | null;
  onSelect: (s: Scenario) => void;
  onTaskChange: (t: string) => void;
  onAccessCodeChange: (t: string) => void;
  onRun: () => void;
}) {
  const [custom, setCustom] = React.useState(false);
  return (
    <section className="tw-panel flex flex-col p-4">
      <h2 className="tw-label mb-3 px-1 !text-slate-300">Attack Console</h2>

      <ul className="space-y-1.5">
        {SCENARIOS.map((s) => {
          const c = ACCENT[s.accent];
          const selected = selectedId === s.id && !custom;
          const live = runningId === s.id && running;
          return (
            <li key={s.id}>
              <button
                onClick={() => {
                  setCustom(false);
                  onSelect(s);
                }}
                disabled={running}
                title={s.task}
                className={cn(
                  "group relative flex w-full items-center gap-3 overflow-hidden rounded-xl border px-3 py-2.5 text-left transition-all duration-300 disabled:cursor-not-allowed",
                  !selected && "hover:border-slate-600 hover:bg-white/[0.03]",
                  running && !live && "opacity-40"
                )}
                style={{
                  borderColor: selected ? `color-mix(in srgb, ${c} 70%, transparent)` : "#1a2331",
                  background: selected ? `color-mix(in srgb, ${c} 9%, rgba(10,15,22,0.6))` : "rgba(10,15,22,0.45)",
                  boxShadow: selected ? `0 0 24px -10px ${c}` : undefined,
                }}
              >
                <span className="absolute inset-y-0 left-0 w-[3px]" style={{ background: c, opacity: selected ? 1 : 0.45 }} />
                <span className="w-7 shrink-0 font-mono text-sm font-black text-slate-100">{s.id}</span>
                <span className="min-w-0 flex-1">
                  <span className="block font-mono text-[9.5px] font-bold uppercase tracking-[0.18em]" style={{ color: c }}>
                    {s.tag}
                  </span>
                  <span className="block truncate text-[13px] text-slate-200">{s.title}</span>
                </span>
                {live ? (
                  <span className="flex items-center gap-1 font-mono text-[9.5px] font-bold tracking-[0.15em] text-amber-300">
                    <span className="h-1.5 w-1.5 rounded-full bg-amber-400 tw-blink" /> LIVE
                  </span>
                ) : null}
              </button>
            </li>
          );
        })}
      </ul>

      <button
        onClick={() => setCustom((v) => !v)}
        disabled={running}
        className={cn("tw-label mt-3 px-1 text-left hover:text-slate-300", custom && "!text-slate-200")}
        aria-expanded={custom}
      >
        {custom ? "▾" : "▸"} Custom instruction
      </button>
      {custom && (
        <textarea
          rows={4}
          value={task}
          onChange={(e) => onTaskChange(e.target.value)}
          disabled={running}
          placeholder="Tell the agent what to do…"
          className="mt-2 w-full rounded-lg border border-edge bg-black/30 p-3 text-sm text-slate-100 placeholder:text-slate-600 focus:outline-none focus:ring-1 focus:ring-cyan-400/40"
        />
      )}

      {accessKeyRequired && (
        <input
          type="password"
          autoComplete="off"
          placeholder="Access code"
          value={accessCode}
          onChange={(e) => onAccessCodeChange(e.target.value)}
          disabled={running}
          className="mt-3 w-full rounded-lg border border-edge bg-black/30 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-600 focus:outline-none focus:ring-1 focus:ring-cyan-400/40"
        />
      )}

      <button
        onClick={onRun}
        disabled={running || !task.trim()}
        className={cn(
          "mt-3 flex h-11 items-center justify-center gap-2 rounded-xl font-mono text-sm font-bold tracking-[0.2em] transition-all",
          running
            ? "cursor-wait border border-amber-400/40 bg-amber-400/10 text-amber-200"
            : "bg-emerald-400 text-slate-950 shadow-[0_0_28px_-8px_rgba(52,211,153,0.9)] hover:bg-emerald-300 disabled:cursor-not-allowed disabled:bg-slate-800 disabled:text-slate-500 disabled:shadow-none"
        )}
      >
        {running ? (
          <>
            <span className="h-2 w-2 rounded-full bg-amber-400 tw-blink" /> AGENT RUNNING
          </>
        ) : (
          <>▶ LAUNCH AGENT</>
        )}
      </button>
      {error && <p className="mt-2 px-1 text-sm text-rose-300">{error}</p>}
    </section>
  );
}
