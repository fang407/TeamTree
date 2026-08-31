import { useEffect, useState } from "react";
import { api } from "../api";
import type { AvailablePiiPattern, ComplianceFramework, RedactionConfig } from "../types";

const FRAMEWORK_OPTIONS: { id: ComplianceFramework; label: string; hint: string }[] = [
  { id: "GDPR", label: "GDPR", hint: "EU personal data" },
  { id: "HIPAA", label: "HIPAA", hint: "US health data" },
  { id: "CCPA", label: "CCPA", hint: "California consumer privacy" },
  { id: "PCI_DSS", label: "PCI DSS", hint: "Payment card data" },
];

function isPatternActive(pattern: AvailablePiiPattern, config: RedactionConfig): boolean {
  if (config.disabledPatternIds.includes(pattern.id)) return false;
  if (config.enabledPatternIds.includes(pattern.id)) return true;
  if (pattern.frameworks.length === 0) return true; // baseline, on by default
  return pattern.frameworks.some((framework) => config.complianceFrameworks.includes(framework));
}

export function RedactionSettings() {
  const [open, setOpen] = useState(false);
  const [config, setConfig] = useState<RedactionConfig | null>(null);
  const [status, setStatus] = useState<"idle" | "loading" | "saving" | "error">("idle");

  useEffect(() => {
    if (!open || config) return;
    setStatus("loading");
    api
      .redactionConfig()
      .then((result) => {
        setConfig(result);
        setStatus("idle");
      })
      .catch(() => setStatus("error"));
  }, [open, config]);

  useEffect(() => {
    if (!open) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") setOpen(false);
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [open]);

  async function apply(update: {
    redactionEnabled?: boolean;
    complianceFrameworks?: ComplianceFramework[];
    enabledPatternIds?: string[];
    disabledPatternIds?: string[];
  }) {
    if (!config) return;
    const previous = config;
    setConfig({ ...config, ...update });
    setStatus("saving");
    try {
      const result = await api.updateRedactionConfig(update);
      setConfig(result);
      setStatus("idle");
    } catch {
      setConfig(previous);
      setStatus("error");
    }
  }

  function toggleFramework(framework: ComplianceFramework) {
    if (!config) return;
    const active = config.complianceFrameworks.includes(framework);
    const next = active
      ? config.complianceFrameworks.filter((item) => item !== framework)
      : [...config.complianceFrameworks, framework];
    void apply({ complianceFrameworks: next });
  }

  function togglePattern(pattern: AvailablePiiPattern) {
    if (!config) return;
    if (isPatternActive(pattern, config)) {
      void apply({
        disabledPatternIds: [...config.disabledPatternIds, pattern.id],
        enabledPatternIds: config.enabledPatternIds.filter((id) => id !== pattern.id),
      });
    } else {
      void apply({
        enabledPatternIds: [...config.enabledPatternIds, pattern.id],
        disabledPatternIds: config.disabledPatternIds.filter((id) => id !== pattern.id),
      });
    }
  }

  return (
    <>
      <button
        type="button"
        className="redaction-settings-trigger"
        onClick={() => setOpen(true)}
        title="Redaction settings"
        aria-label="Redaction settings"
      >
        ⚙
      </button>

      {open && (
        <div className="modal-backdrop" onClick={() => setOpen(false)}>
          <div
            className="modal-panel redaction-settings-panel"
            onClick={(event) => event.stopPropagation()}
            role="dialog"
            aria-modal="true"
            aria-label="Redaction settings"
          >
            <div className="modal-panel-heading">
              <strong>Safety Filter settings</strong>
              <button
                type="button"
                className="modal-close"
                onClick={() => setOpen(false)}
                aria-label="Close"
              >
                ×
              </button>
            </div>

            {status === "loading" || !config ? (
              <p className="redaction-settings-loading">Loading…</p>
            ) : (
              <>
                <label className="redaction-toggle-row">
                  <input
                    type="checkbox"
                    checked={config.redactionEnabled}
                    onChange={(event) => void apply({ redactionEnabled: event.target.checked })}
                  />
                  Redaction enabled
                </label>

                <p className="redaction-settings-subhead">Compliance frameworks</p>

                <p className="redaction-settings-note">
                  This is a detection aid, not a compliance guarantee — actual complying also needs legal, contractual, and organizational
                  measures this tool can't provide on its own.
                </p>

                <div className="redaction-frameworks">
                  {FRAMEWORK_OPTIONS.map((option) => (
                    <label key={option.id} className="redaction-framework-row">
                      <input
                        type="checkbox"
                        disabled={!config.redactionEnabled}
                        checked={config.complianceFrameworks.includes(option.id)}
                        onChange={() => toggleFramework(option.id)}
                      />
                      <span>
                        <strong>{option.label}</strong>
                        <br />
                        {option.hint}
                      </span>
                    </label>
                  ))}
                </div>

                {config.availablePatterns.length > 0 && (
                  <details className="redaction-advanced">
                    <summary>Customize individual identifiers</summary>
                    <p className="redaction-settings-note">
                      Overrides the framework selection above for one identifier at a time — e.g.
                      turn on SSN detection without enabling all of HIPAA, or turn off IP address
                      detection while keeping the rest of GDPR active.
                    </p>
                    <div className="redaction-frameworks">
                      {config.availablePatterns.map((pattern) => (
                        <label key={pattern.id} className="redaction-framework-row">
                          <input
                            type="checkbox"
                            disabled={!config.redactionEnabled}
                            checked={isPatternActive(pattern, config)}
                            onChange={() => togglePattern(pattern)}
                          />
                          <span>
                            <strong>{pattern.description}</strong>
                            <br />
                            {pattern.frameworks.length > 0
                              ? pattern.frameworks.join(", ")
                              : "Baseline — always available"}
                          </span>
                        </label>
                      ))}
                    </div>
                  </details>
                )}

                {status === "error" && (
                  <p className="redaction-settings-error">Couldn't save — try again.</p>
                )}
              </>
            )}
          </div>
        </div>
      )}
    </>
  );
}
