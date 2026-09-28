"use client";
// Top console bar: product identity + live system indicators.
import * as React from "react";
import type { SessionState } from "@/lib/tripwire";
import { cn } from "@/lib/utils";

const STATE: Record<SessionState, { label: string; cls: string; dot: string }> = {
  READY: { label: "STANDBY", cls: "border-slate-600/60 text-slate-300", dot: "bg-slate-400" },
  RUNNING: { label: "MONITORING", cls: "border-cyan-400/50 bg-cyan-400/10 text-cyan-100", dot: "bg-cyan-400 tw-blink" },
  SECURE: { label: "SECURE", cls: "border-emerald-400/50 bg-emerald-400/10 text-emerald-100", dot: "bg-emerald-400" },
  BLOCKED: { label: "THREAT BLOCKED", cls: "border-rose-400/60 bg-rose-500/15 text-rose-100", dot: "bg-rose-400 tw-blink" },
  QUARANTINED: { label: "QUARANTINE", cls: "border-fuchsia-400/60 bg-fuchsia-500/15 text-fuchsia-100", dot: "bg-fuchsia-400" },
  FROZEN: { label: "SESSION FROZEN", cls: "border-rose-400/80 bg-rose-500/25 text-rose-50 shadow-[0_0_24px_-6px_rgba(251,113,133,0.9)]", dot: "bg-rose-300 tw-blink" },
  ERROR: { label: "RUN ERROR", cls: "border-rose-400/60 text-rose-200", dot: "bg-rose-400" },
};

function Indicator({ label, value, ok }: { label: string; value: string; ok: boolean | null }) {
  return (
    <div className="flex items-center gap-2 rounded-lg border border-edge bg-black/30 px-3 py-1.5">
      <span
        className={cn(
          "h-2 w-2 rounded-full",
          ok === null ? "bg-slate-500" : ok ? "bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.9)]" : "bg-rose-400 tw-blink"
        )}
      />
      <span className="tw-label !text-[9.5px]">{label}</span>
      <span className={cn("font-mono text-[11px] font-bold tracking-[0.12em]", ok === false ? "text-rose-300" : "text-slate-100")}>
        {value}
      </span>
    </div>
  );
}

export function StatusBar({
  state,
  sessionId,
  backendOnline,
  streamLive,
}: {
  state: SessionState;
  sessionId: string | null;
  backendOnline: boolean | null;
  streamLive: boolean;
}) {
  const s = STATE[state];
  return (
    <header className="sticky top-0 z-30 border-b border-edge bg-[#05080d]/85 backdrop-blur-md">
      <div className="mx-auto flex max-w-[1680px] flex-wrap items-center justify-between gap-3 px-4 py-3 md:px-6">
        <div className="flex items-center gap-3">
          <span className="relative grid h-10 w-10 place-items-center rounded-xl border border-cyan-400/30 bg-cyan-400/[0.06] text-lg shadow-[0_0_20px_-8px_rgba(34,211,238,0.8)]">
            🪤
          </span>
          <div className="leading-tight">
            <div className="font-mono text-lg font-black tracking-[0.32em] text-slate-50">TRIPWIRE</div>
            <div className="tw-label !text-[9.5px] !text-cyan-300/70">Runtime Agent Security</div>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Indicator label="Backend" value={backendOnline === null ? "…" : backendOnline ? "ONLINE" : "OFFLINE"} ok={backendOnline} />
          <Indicator label="Event stream" value={streamLive ? "LIVE" : "RECONNECTING"} ok={streamLive} />
          <div className="hidden items-center gap-2 rounded-lg border border-edge bg-black/30 px-3 py-1.5 sm:flex">
            <span className="tw-label !text-[9.5px]">Session</span>
            <span className="font-mono text-[11px] text-slate-200">{sessionId ? sessionId.slice(0, 8) : "—"}</span>
          </div>
          <div className={cn("flex items-center gap-2 rounded-lg border px-3 py-1.5 font-mono text-xs font-black tracking-[0.18em]", s.cls)}>
            <span className={cn("h-2 w-2 rounded-full", s.dot)} />
            {s.label}
          </div>
        </div>
      </div>
    </header>
  );
}
