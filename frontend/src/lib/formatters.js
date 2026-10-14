// src/lib/formatters.js
// Presentation helpers shared by the SOC pages.
//
// Written with React.createElement (no JSX) so the module stays a plain `.js`
// file — Vite/esbuild only transform JSX inside `.jsx` by default.

import { createElement as h, Fragment } from "react";

// ─────────────────────────────────────────────────────────────────────────────
// Severity classification — ONE convention for the whole app.
//
// Wazuh-style rule levels 0..15. These are the buckets already used by
// TerminalAlertsPage's severity filter (12 / 8 / 4 / 0), promoted here so the
// dashboard chart, the tables and the topology stop disagreeing with each other.
// Today "critical" means >=12 in AlertRow.jsx, >=10 in RemediationPage.jsx and
// AlertHistoryModal.jsx, >=8 in Layout.jsx and DashboardPage.jsx, >=7 in
// TopologyView.jsx — five answers to the same question.
// ─────────────────────────────────────────────────────────────────────────────
export const SEVERITY_CRITICAL = 12;
export const SEVERITY_HIGH = 8;
export const SEVERITY_MEDIUM = 4;

export function severityOf(alert) {
  if (!alert) return 0;
  const raw =
    alert.Severity ??
    alert.severity ??
    alert.level ??
    alert.rule_level ??
    (alert.rule && (alert.rule.level ?? alert.rule.severity)) ??
    0;
  const n = parseInt(raw, 10);
  return Number.isFinite(n) ? n : 0;
}

export function severityBucket(alert) {
  const sev = severityOf(alert);
  if (sev >= SEVERITY_CRITICAL) return "Critical";
  if (sev >= SEVERITY_HIGH) return "High";
  if (sev >= SEVERITY_MEDIUM) return "Medium";
  return "Low";
}

function timestampOf(alert) {
  const raw =
    alert.Timestamp ??
    alert.timestamp ??
    alert["@timestamp"] ??
    alert.datetime ??
    alert.time ??
    null;
  if (!raw) return null;
  const d = raw instanceof Date ? raw : new Date(raw);
  return Number.isNaN(d.getTime()) ? null : d;
}

/**
 * Bucket alerts per hour of day for the dashboard's stacked BarChart.
 * Returns [{ time: "14:00", Critical, High, Medium, Low, total }] for the last
 * `hours` hours (oldest first), including empty hours so the X axis is stable.
 *
 * @param {Array<object>} alerts
 * @param {number} hours  window size, default 24
 */
export function getHourlyAlertsData(alerts, hours = 24) {
  const buckets = new Map();
  const now = new Date();

  for (let i = hours - 1; i >= 0; i -= 1) {
    const d = new Date(now.getTime() - i * 3600 * 1000);
    d.setMinutes(0, 0, 0);
    buckets.set(d.getTime(), {
      time: `${String(d.getHours()).padStart(2, "0")}:00`,
      Critical: 0,
      High: 0,
      Medium: 0,
      Low: 0,
      total: 0,
    });
  }

  (Array.isArray(alerts) ? alerts : []).forEach((alert) => {
    const d = timestampOf(alert);
    if (!d) return;
    const slot = new Date(d);
    slot.setMinutes(0, 0, 0);
    const row = buckets.get(slot.getTime());
    if (!row) return; // outside the displayed window
    row[severityBucket(alert)] += 1;
    row.total += 1;
  });

  return [...buckets.values()];
}

// ─────────────────────────────────────────────────────────────────────────────
// formatReport — render an LLM/SOC report (markdown-ish plain text) as React
// elements. Deliberately does NOT use dangerouslySetInnerHTML: report text comes
// from a model and must never be able to inject markup.
// ─────────────────────────────────────────────────────────────────────────────
const INLINE_RE = /(\*\*[^*]+\*\*|`[^`]+`)/g;

function renderInline(text, keyPrefix) {
  const parts = String(text).split(INLINE_RE).filter((p) => p !== "");
  return parts.map((part, i) => {
    const key = `${keyPrefix}-i${i}`;
    if (part.startsWith("**") && part.endsWith("**") && part.length > 4) {
      return h("strong", { key, style: { color: "var(--text-1, #e2e8f0)" } }, part.slice(2, -2));
    }
    if (part.startsWith("`") && part.endsWith("`") && part.length > 2) {
      return h(
        "code",
        {
          key,
          style: {
            fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
            fontSize: "0.92em",
            padding: "1px 5px",
            borderRadius: 4,
            background: "rgba(255,255,255,0.07)",
            color: "#7dd3fc",
          },
        },
        part.slice(1, -1),
      );
    }
    return h(Fragment, { key }, part);
  });
}

export function formatReport(content) {
  if (content === null || content === undefined) return null;
  if (typeof content !== "string") return String(content);

  const text = content.replace(/\r\n/g, "\n").trim();
  if (!text) return null;

  const lines = text.split("\n");
  const blocks = [];
  let list = null; // { ordered: bool, items: string[] }
  let key = 0;

  const flushList = () => {
    if (!list) return;
    const tag = list.ordered ? "ol" : "ul";
    blocks.push(
      h(
        tag,
        { key: `b${key++}`, style: { margin: "6px 0 12px", paddingLeft: 22, lineHeight: 1.65 } },
        list.items.map((item, i) => h("li", { key: `li${i}` }, renderInline(item, `li${i}`))),
      ),
    );
    list = null;
  };

  lines.forEach((rawLine, idx) => {
    const trimmed = rawLine.trim();

    if (!trimmed) {
      flushList();
      return;
    }

    if (/^(-{3,}|\*{3,}|_{3,})$/.test(trimmed)) {
      flushList();
      blocks.push(
        h("hr", {
          key: `b${key++}`,
          style: { border: "none", borderTop: "1px solid rgba(255,255,255,0.1)", margin: "14px 0" },
        }),
      );
      return;
    }

    const heading = /^(#{1,4})\s+(.*)$/.exec(trimmed);
    if (heading) {
      flushList();
      const level = heading[1].length;
      const sizes = { 1: "18px", 2: "16px", 3: "14px", 4: "13px" };
      blocks.push(
        h(
          `h${Math.min(level + 1, 6)}`,
          {
            key: `b${key++}`,
            style: {
              margin: level === 1 ? "4px 0 10px" : "14px 0 6px",
              fontSize: sizes[level],
              letterSpacing: "0.02em",
              color: "var(--text-1, #e2e8f0)",
            },
          },
          renderInline(heading[2], `h${idx}`),
        ),
      );
      return;
    }

    const bullet = /^[-*•]\s+(.*)$/.exec(trimmed);
    if (bullet) {
      if (!list || list.ordered) {
        flushList();
        list = { ordered: false, items: [] };
      }
      list.items.push(bullet[1]);
      return;
    }

    const ordered = /^\d+[.)]\s+(.*)$/.exec(trimmed);
    if (ordered) {
      if (!list || !list.ordered) {
        flushList();
        list = { ordered: true, items: [] };
      }
      list.items.push(ordered[1]);
      return;
    }

    flushList();
    blocks.push(
      h(
        "p",
        { key: `b${key++}`, style: { margin: "0 0 10px", lineHeight: 1.65 } },
        renderInline(trimmed, `p${idx}`),
      ),
    );
  });

  flushList();
  return h("div", { className: "report-body" }, blocks);
}

// ─────────────────────────────────────────────────────────────────────────────
// formatSuricataDetails — one-line human summary of a raw EVE event payload.
// `payload` is the JSON string stored on the alert; `eventType` is
// alert | http | dns | flow | netflow | tls | ssh | stats | ...
// Must never throw: a malformed payload falls back to a truncated raw string.
// ─────────────────────────────────────────────────────────────────────────────
function parsePayload(payload) {
  if (!payload) return null;
  if (typeof payload === "object") return payload;
  try {
    return JSON.parse(payload);
  } catch {
    return null;
  }
}

function bytes(n) {
  const v = Number(n);
  if (!Number.isFinite(v) || v <= 0) return null;
  if (v < 1024) return `${v} B`;
  if (v < 1024 * 1024) return `${(v / 1024).toFixed(1)} KB`;
  return `${(v / (1024 * 1024)).toFixed(1)} MB`;
}

export function formatSuricataDetails(payload, eventType) {
  const type = String(eventType || "").toLowerCase();
  const data = parsePayload(payload);

  if (!data) {
    const raw = typeof payload === "string" ? payload : "";
    return raw ? `${raw.slice(0, 160)}${raw.length > 160 ? "…" : ""}` : "—";
  }

  try {
    switch (type) {
      case "alert": {
        const a = data.alert || {};
        const sid = a.signature_id ? ` [sid:${a.signature_id}]` : "";
        const action = a.action ? ` (${a.action})` : "";
        return `${a.signature || a.category || "Suricata alert"}${sid}${action}`;
      }
      case "http": {
        const http = data.http || {};
        const host = http.hostname || data.dest_ip || "";
        const url = http.url || http.uri || "";
        const method = http.http_method || "";
        const status = http.status ? ` → ${http.status}` : "";
        const ua = http.http_user_agent ? ` | ${http.http_user_agent}` : "";
        return [method, `${host}${url}`].filter(Boolean).join(" ") + status + ua;
      }
      case "dns": {
        const dns = data.dns || {};
        const name = dns.rrname || (dns.query && dns.query.name) || "";
        const answers = (dns.answers || [])
          .map((x) => x.rdata)
          .filter(Boolean)
          .slice(0, 3)
          .join(", ");
        const qtype = dns.rrtype ? ` ${dns.rrtype}` : "";
        return `${name}${qtype}${answers ? ` → ${answers}` : ""}`;
      }
      case "flow":
      case "netflow": {
        const f = data.flow || {};
        const up = bytes(f.bytes_toserver);
        const down = bytes(f.bytes_toclient);
        const proto = data.app_proto || f.app_proto || data.proto || "";
        const traffic = up || down ? ` ${up || "0 B"}↑ / ${down || "0 B"}↓` : "";
        const state = f.state ? ` (${f.state})` : "";
        return `${proto || "flow"}${traffic}${state}`;
      }
      case "tls": {
        const t = data.tls || {};
        return `${t.subject || t.sni || t.issuerdn || "TLS session"}${
          t.version ? ` ${t.version}` : ""
        }${t.fingerprint ? ` | ${t.fingerprint.slice(0, 24)}…` : ""}`;
      }
      case "ssh": {
        const s = data.ssh || {};
        const client = s.client && s.client.software_version ? `client ${s.client.software_version}` : "";
        const server = s.server && s.server.software_version ? `server ${s.server.software_version}` : "";
        return [client, server].filter(Boolean).join(" | ") || "SSH session";
      }
      case "stats": {
        const st = data.stats || {};
        const cap = st.capture || {};
        return `capture ${cap.kernel_packets ?? 0} pkts | drop ${cap.kernel_drops ?? 0}`;
      }
      default: {
        const interesting = [
          data.app_proto,
          data.proto,
          data.event_type,
          data.dest_port && `:${data.dest_port}`,
          data.alert && data.alert.signature,
          data.http && data.http.url,
          data.dns && data.dns.rrname,
        ].filter(Boolean);
        if (interesting.length) return interesting.join(" ");
        const flat = Object.entries(data)
          .filter(([, v]) => typeof v === "string" || typeof v === "number")
          .slice(0, 4)
          .map(([k, v]) => `${k}=${v}`)
          .join(" ");
        return flat || type || "event";
      }
    }
  } catch {
    return type || "event";
  }
}

export default {
  formatReport,
  formatSuricataDetails,
  getHourlyAlertsData,
  severityBucket,
  severityOf,
};
