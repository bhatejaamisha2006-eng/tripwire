"use client";
// Behavioral risk score after each tool call, exactly as the backend reported
// it, against the backend's own freeze threshold. Single series: the title
// names it, so there is no legend box.
import * as React from "react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  ReferenceArea,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import type { RiskPoint } from "@/lib/tripwire";

const SERIES = "#9085e9"; // violet — behavioral intelligence; validated on the dark surface
const CRITICAL = "#d03b3b"; // status: critical (freeze threshold)
const SURFACE = "#0b1017";
const GRID = "#1a2331";
const TEXT_MUTED = "#7c8699";

function Dot(props: { cx?: number; cy?: number; payload?: RiskPoint }) {
  const { cx, cy, payload } = props;
  if (cx == null || cy == null) return null;
  const froze = payload?.froze;
  return <circle cx={cx} cy={cy} r={froze ? 6 : 4} fill={froze ? CRITICAL : SERIES} stroke={SURFACE} strokeWidth={2} />;
}

function Tip({ active, payload }: { active?: boolean; payload?: Array<{ payload: RiskPoint }> }) {
  if (!active || !payload?.length) return null;
  const p = payload[0].payload;
  return (
    <div className="rounded-lg border border-edge bg-[#0b1017] px-3 py-2 text-xs shadow-xl">
      <div className="font-mono text-slate-200">
        call #{p.n} · {p.tool}
      </div>
      <div className="mt-0.5 text-slate-400">
        risk <span className="font-semibold tabular-nums text-slate-100">{p.risk}</span> · {p.decision}
        {p.froze ? " · anomaly" : ""}
      </div>
    </div>
  );
}

export function RiskChart({ points, threshold }: { points: RiskPoint[]; threshold?: number }) {
  // Recharts animates in JS, so honour prefers-reduced-motion explicitly.
  const [animate, setAnimate] = React.useState(false);
  React.useEffect(() => {
    setAnimate(!window.matchMedia("(prefers-reduced-motion: reduce)").matches);
  }, []);
  const last = points[points.length - 1];
  const max = Math.max(threshold ?? 0, ...points.map((p) => p.risk));
  const top = Math.max(5, Math.ceil((max + 3) / 5) * 5);
  return (
    <section className="tw-panel p-5">
      <div className="mb-2 flex items-start justify-between">
        <div>
          <h2 className="tw-label !text-slate-300">Behavioral Analysis</h2>
          <p className="mt-1 text-xs text-slate-500">Risk score after each tool call</p>
        </div>
        <div className="text-right">
          <div className="font-mono text-2xl font-bold tabular-nums" style={{ color: last && threshold && last.risk >= threshold ? "var(--tw-threat)" : SERIES }}>
            {last ? last.risk : 0}
          </div>
          <div className="font-mono text-[10px] tracking-wider text-slate-500">freeze at {threshold ?? "—"}</div>
        </div>
      </div>
      {!points.length ? (
        <div className="grid h-56 place-items-center font-mono text-xs tracking-[0.15em] text-slate-600">NO SCORED CALLS YET</div>
      ) : (
        <div
          className="h-56 w-full lg:h-64"
          role="img"
          aria-label={`Behavioral risk score per tool call: ${points.map((p) => p.risk).join(", ")}; freeze threshold ${threshold ?? "unknown"}`}
        >
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={points} margin={{ top: 8, right: 8, bottom: 0, left: -22 }}>
              <defs>
                <linearGradient id="riskFill" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={SERIES} stopOpacity={0.22} />
                  <stop offset="100%" stopColor={SERIES} stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid stroke={GRID} strokeWidth={1} vertical={false} />
              {threshold != null && <ReferenceArea y1={threshold} y2={top} fill={CRITICAL} fillOpacity={0.06} />}
              <XAxis dataKey="n" tick={{ fill: TEXT_MUTED, fontSize: 11 }} tickLine={false} axisLine={{ stroke: GRID }} allowDecimals={false} />
              <YAxis domain={[0, top]} tick={{ fill: TEXT_MUTED, fontSize: 11 }} tickLine={false} axisLine={false} allowDecimals={false} />
              {threshold != null && (
                <ReferenceLine
                  y={threshold}
                  stroke={CRITICAL}
                  strokeWidth={1.5}
                  label={{ value: `FREEZE ${threshold}`, position: "insideTopLeft", fill: TEXT_MUTED, fontSize: 10 }}
                />
              )}
              <Tooltip content={<Tip />} cursor={{ stroke: TEXT_MUTED, strokeWidth: 1 }} isAnimationActive={false} />
              {/* Straight segments: risk is a per-call value, nothing happens between calls. */}
              <Area
                type="linear"
                dataKey="risk"
                stroke={SERIES}
                strokeWidth={2}
                fill="url(#riskFill)"
                dot={<Dot />}
                activeDot={{ r: 6, fill: SERIES, stroke: SURFACE, strokeWidth: 2 }}
                isAnimationActive={animate}
                animationDuration={700}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      )}
    </section>
  );
}
