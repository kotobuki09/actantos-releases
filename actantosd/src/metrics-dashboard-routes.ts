import type { FastifyInstance } from "fastify"
import { z } from "zod"

import type { Database } from "./database.ts"
import { listUsageMetrics } from "./usage-metrics-routes.ts"

const metricsDashboardQuerySchema = z.object({
  tenant_id: z.string().min(1).optional().default("t_demo"),
  api_key: z.string().min(1).optional(),
})

const escapeHtml = (value: string): string =>
  value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;")

export const registerMetricsDashboardRoutes = (
  server: FastifyInstance,
  options: { readonly database: Database },
): void => {
  server.get("/dashboard/metrics", async (request, reply) => {
    const query = metricsDashboardQuerySchema.parse(request.query)
    const metrics = await listUsageMetrics(options.database, query.tenant_id)
    const toolKindRows = metrics.tool_kinds
      .map((row) => `<tr><td>${escapeHtml(row.tool_kind)}</td><td>${String(row.count)}</td></tr>`)
      .join("")

    return reply
      .code(200)
      .type("text/html; charset=utf-8")
      .send(`<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>ActantOS Usage Metrics</title>
    <style>
      :root { color-scheme: dark; --bg:#0b1017; --panel:#121926; --border:#273247; --text:#eef2ff; --muted:#9ca9c4; --accent:#6ee7b7; }
      body { margin:0; background:var(--bg); color:var(--text); font:16px/1.5 ui-sans-serif,system-ui,sans-serif; }
      main { max-width:1080px; margin:0 auto; padding:48px 20px 72px; }
      .hero { display:flex; justify-content:space-between; gap:24px; align-items:end; margin-bottom:28px; }
      .eyebrow { text-transform:uppercase; letter-spacing:.12em; color:var(--accent); font-size:12px; }
      .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:14px; margin-bottom:24px; }
      .card, .panel { background:var(--panel); border:1px solid var(--border); border-radius:18px; padding:18px; }
      .label { color:var(--muted); font-size:13px; margin-bottom:8px; }
      .value { font-size:30px; font-weight:700; }
      table { width:100%; border-collapse:collapse; }
      th, td { text-align:left; padding:12px 10px; border-bottom:1px solid var(--border); }
      th { color:var(--muted); font-weight:600; font-size:13px; }
      code { color:var(--accent); }
    </style>
  </head>
  <body>
    <main>
      <section class="hero">
        <div>
          <div class="eyebrow">ActantOS Metrics</div>
          <h1>Usage totals for <code>${escapeHtml(metrics.tenant_id)}</code></h1>
          <p>Operator-facing pilot metrics for decisions, approvals, tool results, and active controls.</p>
        </div>
        <div class="panel">Backed by <code>/v1/metrics/usage</code></div>
      </section>
      <section class="grid">
        <article class="card"><div class="label">Sessions</div><div class="value">${String(metrics.summary.session_count)}</div></article>
        <article class="card"><div class="label">Decisions</div><div class="value">${String(metrics.summary.decision_count)}</div></article>
        <article class="card"><div class="label">Allows</div><div class="value">${String(metrics.summary.allow_count)}</div></article>
        <article class="card"><div class="label">Denies</div><div class="value">${String(metrics.summary.deny_count)}</div></article>
        <article class="card"><div class="label">Approvals required</div><div class="value">${String(metrics.summary.approval_required_count)}</div></article>
        <article class="card"><div class="label">Executed results</div><div class="value">${String(metrics.summary.executed_tool_result_count)}</div></article>
      </section>
      <section class="panel">
        <h2>Tool mix</h2>
        <table>
          <thead><tr><th>Tool kind</th><th>Count</th></tr></thead>
          <tbody>${toolKindRows}</tbody>
        </table>
      </section>
    </main>
  </body>
</html>`)
  })
}
