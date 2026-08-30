import type { AgentRun, SafetyEvent } from "../types";

export function SafetyStatus({
  run,
  events,
}: {
  run: AgentRun | null;
  events: SafetyEvent[];
}) {
  const latest = events.at(-1);
  const blocked = run?.status === "blocked" || latest?.decision === "BLOCK";
  const stopped = run?.status === "cancelled" || latest?.decision === "CANCELLED";
  const label = blocked ? "Safety: Blocked" : stopped ? "Safety: Run stopped" : "Safety: Protected";
  const tone = blocked ? "blocked" : stopped ? "stopped" : "protected";

  return <span className={"safety-status safety-status-" + tone}>{label}</span>;
}
