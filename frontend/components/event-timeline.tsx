"use client";
// Vertical timeline of real backend events, in arrival order.
import * as React from "react";
import type { TimelineItem, Tone } from "@/lib/tripwire";
import { cn } from "@/lib/utils";

const TONE: Record<Tone, { dot: string; text: string; badge: string }> = {
  muted: { dot: "bg-slate-500", text: "text-slate-300", badge: "" },
  planning: { dot: "bg-amber-400", text: "text-amber-100", badge: "" },
  active: { dot: "bg-cyan-400", text: "text-cyan-100", badge: "" },
  ok: { dot: "bg-emerald-400", text: "text-emerald-100", badge: "text-emerald-200 border-emerald-400/40 bg-emerald-400/10" },
  threat: { dot: "bg-rose-400", text: "text-rose-100", badge: "text-rose-200 border-rose-400/50 bg-rose-500/10" },
  frozen: { dot: "bg-rose-400", text: "text-rose-100", badge: "text-rose-100 border-rose-400/60 bg-rose-500/15" },
  poison: { dot: "bg-fuchsia-400", text: "text-fuchsia-100", badge: "text-fuchsia-200 border-fuchsia-400/50 bg-fuchsia-500/10" },
  behavior: { dot: "bg-violet-400", text: "text-violet-100", badge: "" },
};

function time(ms: number) {
  const d = new Date(ms);
  return `${d.toLocaleTimeString([], { hour12: false })}.${String(d.getMilliseconds()).padStart(3, "0")}`;
}

export function EventTimeline({ items, onSelect }: { items: TimelineItem[]; onSelect?: (key: string) => void }) {
  const ref = React.useRef<HTMLDivElement>(null);
  React.useEffect(() => {
    ref.current?.scrollTo({ top: ref.current.scrollHeight, behavior: "smooth" });
  }, [items.length]);
  return (
    <section className="tw-panel flex min-h-0 flex-col">
      <div className="flex items-center justify-between border-b border-edge px-5 py-3.5">
        <h2 className="tw-label !text-slate-300">Live Event Timeline</h2>
        <span className="font-mono text-[10.5px] text-slate-500">{items.length} events · backend stream</span>
      </div>
      {items.length === 0 ? (
        <p className="p-6 text-center font-mono text-xs tracking-[0.15em] text-slate-500">WAITING FOR EVENTS</p>
      ) : (
        <div ref={ref} className="max-h-[360px] overflow-y-auto px-5 py-4">
          <ol className="relative">
            <span className="absolute bottom-2 left-[5px] top-2 w-px bg-gradient-to-b from-slate-700 via-slate-800 to-transparent" aria-hidden />
            {items.map((it, i) => {
              const t = TONE[it.tone];
              const last = i === items.length - 1;
              return (
                <li key={it.key} className={cn("relative pb-3 pl-7", last && "tw-rise")}>
                  <span
                    className={cn(
                      "absolute left-0 top-1 h-[11px] w-[11px] rounded-full ring-4 ring-[#0b1017]",
                      t.dot,
                      last && (it.tone === "planning" || it.tone === "active") && "tw-blink"
                    )}
                    aria-hidden
                  />
                  <button
                    onClick={() => onSelect?.(it.key)}
                    className="group block w-full text-left"
                    disabled={!onSelect}
                  >
                    <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                      <span className="font-mono text-[11px] tabular-nums text-slate-500">{time(it.ts)}</span>
                      <span className={cn("font-mono text-[12px] font-bold uppercase tracking-[0.12em] group-hover:underline", t.text)}>
                        {it.title}
                      </span>
                      {it.badge && (
                        <span className={cn("rounded border px-1.5 py-0.5 font-mono text-[9.5px] font-bold tracking-[0.15em]", t.badge)}>
                          {it.badge}
                        </span>
                      )}
                    </div>
                    {it.detail && <div className="mt-0.5 break-all font-mono text-[11.5px] text-slate-400">{it.detail}</div>}
                  </button>
                </li>
              );
            })}
          </ol>
        </div>
      )}
    </section>
  );
}
