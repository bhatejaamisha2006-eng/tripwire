"use client";
// The current tool call, as intercepted and judged by the backend.
import * as React from "react";
import type { CallRecord, Verdict } from "@/lib/tripwire";
import { caughtBy, finalDecision, primaryArg, verdictOf } from "@/lib/tripwire";
import { cn } from "@/lib/utils";

const HEAD: Record<Verdict | "pending", { label: string; cls: string; dot: string }> = {
  pending: { label: "TOOL CALL INTERCEPTED", cls: "text-cyan-200 bg-cyan-400/[0.08] border-cyan-400/30", dot: "bg-cyan-400 tw-blink" },
  allowed: { label: "TOOL CALL ALLOWED", cls: "text-emerald-200 bg-emerald-400/[0.08] border-emerald-400/30", dot: "bg-emerald-400" },
  blocked: { label: "TOOL CALL BLOCKED", cls: "text-rose-100 bg-rose-500/[0.12] border-rose-400/40", dot: "bg-rose-400 tw-blink" },
  frozen: { label: "SESSION FROZEN", cls: "text-rose-100 bg-rose-500/[0.14] border-rose-400/50", dot: "bg-rose-400 tw-blink" },
  quarantined: { label: "TOOL QUARANTINED", cls: "text-fuchsia-100 bg-fuchsia-500/[0.1] border-fuchsia-400/40", dot: "bg-fuchsia-400" },
};

const DECISION_TEXT: Record<Verdict, { word: string; cls: string }> = {
  allowed: { word: "ALLOWED", cls: "text-emerald-300" },
  blocked: { word: "BLOCKED", cls: "text-rose-300" },
  frozen: { word: "BLOCKED · FROZEN", cls: "text-rose-300" },
  quarantined: { word: "QUARANTINED", cls: "text-fuchsia-300" },
};

export function ToolCallPanel({ call }: { call?: CallRecord }) {
  const final = finalDecision(call);
  const verdict = verdictOf(final);
  const head = HEAD[verdict ?? "pending"];
  const arg = primaryArg(call?.args);
  const risk = typeof final?.raw.risk_score === "number" ? final.raw.risk_score : undefined;
  const threshold = final?.raw.risk_threshold;
  const [showArgs, setShowArgs] = React.useState(false);

  if (!call) {
    return (
      <section className="tw-panel p-5">
        <div className="tw-label">Current Tool Call</div>
        <div className="mt-6 grid place-items-center pb-4 text-center">
          <div className="grid h-14 w-14 place-items-center rounded-full border border-dashed border-slate-700 text-2xl text-slate-600">
            🔧
          </div>
          <p className="mt-3 font-mono text-xs tracking-[0.15em] text-slate-500">NO TOOL CALL YET</p>
        </div>
      </section>
    );
  }

  return (
    <section className="tw-panel overflow-hidden" key={call.id}>
      <div className={cn("flex items-center gap-2 border-b px-5 py-2.5 font-mono text-[11px] font-bold tracking-[0.2em]", head.cls)}>
        <span className={cn("h-2 w-2 rounded-full", head.dot)} />
        {call.discovery ? "TOOL DISCOVERY SCAN" : head.label}
      </div>
      <div className="tw-rise space-y-4 p-5">
        <div>
          <div className="break-all font-mono text-2xl font-semibold text-slate-50">{call.toolName}</div>
          {arg && (
            <div className="mt-2 break-all rounded-lg border border-edge bg-black/40 px-3 py-2 font-mono text-sm text-cyan-100">
              {arg}
            </div>
          )}
        </div>

        <dl className="grid grid-cols-2 gap-2.5">
          <Cell label="Layer" value={verdict === "allowed" ? "All passed" : caughtBy(call) ?? "Evaluating"} strong={verdict !== "allowed" && !!verdict} />
          <Cell
            label="Decision"
            value={verdict ? DECISION_TEXT[verdict].word : "PENDING"}
            valueCls={verdict ? DECISION_TEXT[verdict].cls : "text-cyan-300"}
          />
          <div className="col-span-2 rounded-lg border border-edge bg-black/25 px-3 py-2.5">
            <div className="flex items-baseline justify-between">
              <dt className="tw-label">Behavioral risk</dt>
              <dd className="font-mono text-lg font-semibold tabular-nums text-slate-100">
                {risk ?? "—"}
                {threshold ? <span className="text-sm text-slate-500"> / {threshold}</span> : null}
              </dd>
            </div>
            {risk != null && threshold ? (
              <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-violet-400/10" aria-hidden>
                <div
                  className="h-full rounded-full transition-[width] duration-700"
                  style={{
                    width: `${Math.min(100, (risk / threshold) * 100)}%`,
                    background: risk >= threshold ? "var(--tw-threat)" : "var(--tw-behavior)",
                  }}
                />
              </div>
            ) : null}
          </div>
        </dl>

        {final?.raw.reason && (
          <p className="rounded-lg border-l-2 border-rose-400/60 bg-rose-500/[0.05] px-3 py-2 text-[13px] leading-snug text-slate-300">
            {final.raw.reason}
          </p>
        )}

        {call.args && Object.keys(call.args).length > 0 && (
          <div>
            <button
              onClick={() => setShowArgs((v) => !v)}
              className="tw-label flex items-center gap-1.5 hover:text-slate-300"
              aria-expanded={showArgs}
            >
              {showArgs ? "▾" : "▸"} Arguments · redacted by Tripwire
            </button>
            {showArgs && (
              <pre className="mt-2 max-h-40 overflow-auto whitespace-pre-wrap break-all rounded-lg border border-edge bg-black/40 p-3 font-mono text-xs text-slate-300">
                {JSON.stringify(call.args, null, 2)}
              </pre>
            )}
          </div>
        )}
      </div>
    </section>
  );
}

function Cell({ label, value, valueCls, strong }: { label: string; value: string; valueCls?: string; strong?: boolean }) {
  return (
    <div className="rounded-lg border border-edge bg-black/25 px-3 py-2.5">
      <dt className="tw-label">{label}</dt>
      <dd className={cn("mt-1 font-mono text-sm font-bold tracking-wide", valueCls ?? (strong ? "text-rose-200" : "text-slate-100"))}>
        {value}
      </dd>
    </div>
  );
}
