import { memo } from "react";
import { ShieldAlert, ShieldCheck, ShieldQuestion, Minus } from "lucide-react";

// Verdicts possibles (miroir de app/domain/intel.py + client.py)
const VERDICT_META = {
  malicious: { label: "Malicious", cls: "intel-badge intel-malicious", Icon: ShieldAlert },
  suspicious: { label: "Suspicious", cls: "intel-badge intel-suspicious", Icon: ShieldQuestion },
  clean: { label: "Clean", cls: "intel-badge intel-clean", Icon: ShieldCheck },
};

// Lit les champs intel_* quelle que soit la casse renvoyée par l'API.
const pick = (alert, title, snake) =>
  alert?.[title] ?? alert?.[snake] ?? alert?.[snake.replace(/_([a-z])/g, (_, c) => c.toUpperCase())] ?? null;

const IntelBadge = memo(({ alert }) => {
  const verdict = pick(alert, "Intel Verdict", "intel_verdict");
  const score = pick(alert, "Intel Score", "intel_score");
  const source = pick(alert, "Intel Source", "intel_source");
  const checked = pick(alert, "Intel Checked At", "intel_checked_at");

  const meta = VERDICT_META[verdict];
  if (!meta) {
    // Non enrichi / ancienne ligne -> état neutre
    return (
      <span className="intel-badge intel-unknown" title="Aucun enrichissement intel">
        <Minus size={12} /> —
      </span>
    );
  }

  const Icon = meta.Icon;
  const title = `${meta.label}${source ? ` · ${source}` : ""}${checked ? ` · ${checked}` : ""}`;
  return (
    <span className={meta.cls} title={title}>
      <Icon size={12} />
      {meta.label}
      {score != null ? ` · ${score}` : ""}
    </span>
  );
});

export default IntelBadge;