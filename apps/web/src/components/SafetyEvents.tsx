import type { SafetyEvent } from "../types";

function formatEventTime(value: string): string {
  return new Intl.DateTimeFormat(undefined, {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).format(new Date(value));
}

export function SafetyEvents({ events }: { events: SafetyEvent[] }) {
  return (
    <section className="safety-events" aria-label="Safety event timeline">
      <div className="safety-events-heading">
        <div>
          <span className="eyebrow">Safety events</span>
          <h3>Runtime decision timeline</h3>
        </div>
        <span>{events.length}</span>
      </div>
      {events.length === 0 ? (
        <p className="safety-events-empty">No safety events recorded for this run yet.</p>
      ) : (
        <ol className="safety-events-list">
          {events.map((event) => (
            <li key={event.id} className={"safety-event safety-event-" + event.decision.toLowerCase()}>
              <strong>{event.decision === "ALLOW" ? "✓" : event.decision === "BLOCK" ? "⛔" : "■"}</strong>
              <div>
                <span>{event.decision} · {event.boundary}</span>
                <p>{event.reason}</p>
              </div>
              <time dateTime={event.timestamp}>{formatEventTime(event.timestamp)}</time>
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}
