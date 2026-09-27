// Tripwire frontend — visualization + input only. It NEVER makes a security
// decision; it renders decisions that Tripwire already made and streamed.

export const API_BASE =
  process.env.NEXT_PUBLIC_TRIPWIRE_API?.replace(/\/$/, "") || "http://127.0.0.1:8000";

// Raw event shape as broadcast by the proxy over /dashboard/stream.
export interface RawEvent {
  session_id: string;
  event_type: string;
  tool_name?: string | null;
  arguments?: Record<string, unknown>;
  is_canary?: boolean;
  reason?: string;
  action?: string;
  destination?: string;
  risk_score?: number | string;
  severity?: string;
  security_layer?: string;
}

export type Decision =
  | "ALLOWED"
  | "BLOCKED"
  | "QUARANTINED"
  | "FROZEN"
  | "TRIGGERED"
  | "LOCKED OUT"
  | "INFO";

export interface DisplayEvent {
  id: number;
  ts: number;
  sessionId: string;
  eventType: string;
  toolName: string;
  decision: Decision;
  layer: string;
  reason?: string;
  action?: string;
  destination?: string;
  riskScore?: number | string;
  severity?: string;
  isCanary?: boolean;
  backendReached: boolean;
  raw: RawEvent;
}

// Map a raw Tripwire event to how it should be displayed. All classification
// here is descriptive of what Tripwire already decided — not a new decision.
export function normalize(raw: RawEvent, id: number): DisplayEvent {
  const base = {
    id,
    ts: Date.now(),
    sessionId: raw.session_id,
    eventType: raw.event_type,
    toolName: raw.tool_name || "—",
    reason: raw.reason,
    action: raw.action,
    destination: raw.destination,
    riskScore: raw.risk_score,
    severity: raw.severity,
    isCanary: raw.is_canary,
    raw,
  };
  switch (raw.event_type) {
    case "tool_call":
      return { ...base, decision: "ALLOWED", layer: "Passed all checks", backendReached: true };
    case "canary_trigger":
      return {
        ...base,
        decision: "TRIGGERED",
        layer: "Deception / Canary",
        action: base.action || "SESSION FROZEN",
        backendReached: false,
      };
    case "policy_block":
      return { ...base, decision: "BLOCKED", layer: "Action Policy", backendReached: false };
    case "network_block":
      return { ...base, decision: "BLOCKED", layer: "Network Policy", backendReached: false };
    case "behavior_anomaly":
      return {
        ...base,
        decision: "FROZEN",
        layer: "Behavioral Engine",
        action: base.action || "SESSION FROZEN",
        backendReached: false,
      };
    case "tool_poisoning":
      return {
        ...base,
        decision: "QUARANTINED",
        layer: "Tool Integrity",
        action: base.action || "TOOL QUARANTINED",
        backendReached: false,
      };
    case "frozen_block":
      return { ...base, decision: "LOCKED OUT", layer: "Session Freeze", backendReached: false };
    default:
      return { ...base, decision: "INFO", layer: raw.security_layer || "—", backendReached: true };
  }
}

export const SECURITY_EVENT_TYPES = new Set([
  "canary_trigger",
  "policy_block",
  "network_block",
  "behavior_anomaly",
  "tool_poisoning",
  "frozen_block",
]);

export function isSecurityEvent(e: DisplayEvent): boolean {
  return SECURITY_EVENT_TYPES.has(e.eventType);
}

export interface Counters {
  totalToolCalls: number;
  allowed: number;
  blocked: number;
  quarantined: number;
  risk: "LOW" | "ELEVATED" | "HIGH";
}

export function computeCounters(events: DisplayEvent[]): Counters {
  const count = (t: string) => events.filter((e) => e.eventType === t).length;
  const toolCalls = count("tool_call");
  const policy = count("policy_block");
  const canary = count("canary_trigger");
  const behavior = count("behavior_anomaly");
  const network = count("network_block");
  const frozen = count("frozen_block");
  const quarantined = count("tool_poisoning");
  // tool_call is logged before the policy/canary/behavior checks, so subtract
  // those to count only genuinely allowed executions. network_block and
  // tool_poisoning never emit a tool_call.
  const allowed = Math.max(0, toolCalls - policy - canary - behavior);
  const blocked = policy + network + frozen;
  const security = policy + canary + behavior + network + frozen + quarantined;
  const risk: Counters["risk"] =
    canary + behavior + frozen > 0 ? "HIGH" : security > 0 ? "ELEVATED" : "LOW";
  return { totalToolCalls: toolCalls, allowed, blocked, quarantined, risk };
}

export type SessionStatus =
  | "READY"
  | "RUNNING"
  | "COMPLETED"
  | "BLOCKED"
  | "FROZEN"
  | "QUARANTINED"
  | "ERROR";

export function deriveStatus(
  runStatus: "idle" | "running" | "completed" | "error",
  events: DisplayEvent[]
): SessionStatus {
  const has = (t: string) => events.some((e) => e.eventType === t);
  if (has("canary_trigger") || has("behavior_anomaly") || has("frozen_block")) return "FROZEN";
  if (has("tool_poisoning")) return "QUARANTINED";
  if (has("policy_block") || has("network_block")) return "BLOCKED";
  if (runStatus === "running") return "RUNNING";
  if (runStatus === "completed") return "COMPLETED";
  if (runStatus === "error") return "ERROR";
  return "READY";
}
