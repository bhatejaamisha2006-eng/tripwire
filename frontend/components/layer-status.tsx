"use client";
// Tripwire's security layers and what each has actually done this session.
import * as React from "react";
import type { Accent, LayerActivity } from "@/lib/tripwire";
import { LAYERS } from "@/lib/tripwire";
import { cn } from "@/lib/utils";

const ACCENT: Record<Accent, string> = {
  amber: "#fbbf24",
  rose: "#fb7185",
  cyan: "#22d3ee",
  violet: "#9085e9",
  fuchsia: "#e879f9",
  sky: "#7dd3fc",
};

function time(ms: number) {
  return new Date(ms).toLocaleTimeString([], { hour12: false });
}

export function LayerStatus({ activity, hotLayer }: { activity: Record<string, LayerActivity>; hotLayer?: string }) {
  return (
    <section className="tw-panel p-5">
      <div className="mb-3 flex items-center justify-between">
        <h2 className="tw-label !text-slate-300">Security Layers</h2>
        <span className="font-mono text-[10.5px] text-slate-500">
          {LAYERS.filter((l) => activity[l.key]?.count).length}/{LAYERS.length} fired
        </span>
      </div>
      <ul className="grid grid-cols-1 gap-2 sm:grid-cols-2 md:grid-cols-1 lg:grid-cols-2 xl:grid-cols-1">
        {LAYERS.map((l) => {
          const a = activity[l.key] || { count: 0 };
          const fired = a.count > 0;
          const hot = hotLayer === l.key;
          const c = ACCENT[l.accent];
          return (
            <li
              key={`${l.key}-${a.count}`}
              className={cn(
                "relative flex items-center gap-3 overflow-hidden rounded-xl border px-3 py-2.5 transition-colors duration-500",
                fired && "tw-pop",
                hot && "tw-threat"
              )}
              style={
                {
                  "--c": c,
                  borderColor: fired ? `color-mix(in srgb, ${c} 55%, transparent)` : "#1a2331",
                  background: fired ? `color-mix(in srgb, ${c} 8%, rgba(10,15,22,0.6))` : "rgba(10,15,22,0.45)",
                } as React.CSSProperties
              }
            >
              <span
                className="grid h-9 w-9 shrink-0 place-items-center rounded-lg border text-base"
                style={{ borderColor: fired ? c : "#1f2937", background: fired ? `color-mix(in srgb, ${c} 15%, transparent)` : "transparent" }}
                aria-hidden
              >
                <span className={cn(!fired && "opacity-50 grayscale")}>{l.icon}</span>
              </span>
              <div className="min-w-0 flex-1">
                <div className={cn("truncate text-[13px] font-semibold", fired ? "text-slate-100" : "text-slate-400")}>{l.label}</div>
                <div className="truncate font-mono text-[10.5px] text-slate-500">
                  {fired && a.last ? `${time(a.last.ts)} · ${a.last.toolName}` : "armed · no trigger"}
                </div>
              </div>
              <div className="text-right">
                <div className="font-mono text-lg font-bold leading-none tabular-nums" style={{ color: fired ? c : "#475569" }}>
                  {a.count}
                </div>
                <div className="mt-0.5 font-mono text-[9px] font-bold tracking-[0.15em]" style={{ color: fired ? c : "#475569" }}>
                  {fired ? "FIRED" : "ARMED"}
                </div>
              </div>
            </li>
          );
        })}
      </ul>
    </section>
  );
}
