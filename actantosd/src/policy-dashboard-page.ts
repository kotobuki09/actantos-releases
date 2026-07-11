type PolicyBundleRow = { readonly id: string; readonly tenant_id: string; readonly version: string; readonly engine: string; readonly source_hash: string; readonly source_text: string; readonly active: boolean; readonly created_at: string | Date }

const escapeHtml = (value: string | number | boolean | null | undefined): string =>
  String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll("\"", "&quot;")

const buildPolicyDashboardHref = (tenantId: string, apiKey?: string): string =>
  escapeHtml(`/dashboard/policy?tenant_id=${encodeURIComponent(tenantId)}${apiKey === undefined ? "" : `&api_key=${encodeURIComponent(apiKey)}`}`)

const renderBundleRows = (rows: readonly PolicyBundleRow[]): string =>
  rows.map((row) => `
    <tr data-policy-bundle-id="${escapeHtml(row.id)}">
      <td>
        <div class="primary">${escapeHtml(row.version)}</div>
        <div class="secondary">${escapeHtml(row.id)}</div>
      </td>
      <td>${escapeHtml(row.engine)}</td>
      <td><code>${escapeHtml(row.source_hash)}</code></td>
      <td><span class="status-badge ${row.active ? "status-active" : "status-inactive"}">${row.active ? "active" : "stored"}</span></td>
      <td><code>${escapeHtml(new Date(row.created_at).toISOString())}</code></td>
      <td>
        ${row.active
          ? `<span class="secondary">Current active bundle</span>`
          : `<button class="action-button" type="button" data-policy-activate="${escapeHtml(row.id)}">Activate</button>`}
      </td>
    </tr>
  `).join("")

export const renderPolicyDashboardPage = (options: { readonly tenantId: string; readonly apiKey?: string; readonly bundles: readonly PolicyBundleRow[] }): string => {
  const activeBundle = options.bundles.find((row) => row.active) ?? options.bundles[0]

  return `
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>ActantOS Policy Dashboard</title>
  <style>
    :root { color-scheme: dark; --bg:#0b1017; --panel:#131b27; --panel-alt:#0f1520; --border:#243244; --text:#ebf1fa; --muted:#9eacc0; --accent:#7fb3ff; --good:#3ddc97; --warn:#ffd166; --danger:#ff8b8b; }
    * { box-sizing: border-box; }
    body { margin:0; font-family:Inter,"Segoe UI",system-ui,sans-serif; background:linear-gradient(180deg,#0e1520 0%,var(--bg) 220px); color:var(--text); }
    header { border-bottom:1px solid var(--border); background:rgba(11,16,23,0.92); backdrop-filter:blur(12px); }
    .header-inner, main { max-width:1200px; margin:0 auto; padding:20px 24px; }
    .eyebrow { color:var(--accent); font-size:12px; text-transform:uppercase; font-weight:700; }
    h1, h2, h3 { margin:0; }
    h1 { font-size:30px; margin-top:6px; }
    h2 { font-size:18px; }
    p { margin:0; color:var(--muted); line-height:1.5; }
    .hero, .panel-header, .form-grid, .bundle-grid { display:grid; gap:16px; }
    .hero { grid-template-columns:minmax(0,1fr) auto; align-items:end; margin-bottom:18px; }
    .tenant { font-size:12px; color:var(--muted); }
    .panel { background:linear-gradient(180deg,var(--panel),var(--panel-alt)); border:1px solid var(--border); border-radius:8px; padding:18px; margin-bottom:18px; }
    .panel-header { grid-template-columns:minmax(0,1fr) auto; align-items:start; margin-bottom:14px; }
    .bundle-grid { grid-template-columns:minmax(0,1.15fr) minmax(320px,0.85fr); }
    .preview { border:1px solid var(--border); border-radius:8px; background:rgba(11,16,23,0.45); padding:14px; }
    .preview pre { margin:0; white-space:pre-wrap; word-break:break-word; color:var(--text); font:13px/1.5 ui-monospace,SFMono-Regular,Consolas,monospace; }
    .primary { font-weight:650; }
    .secondary, code, label, .feedback { color:var(--muted); font-size:13px; }
    code { font-family:ui-monospace,SFMono-Regular,Consolas,monospace; }
    table { width:100%; border-collapse:collapse; }
    th, td { text-align:left; padding:12px 10px; border-top:1px solid var(--border); vertical-align:top; }
    th { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:0.03em; font-weight:700; }
    .status-badge { display:inline-flex; border:1px solid var(--border); border-radius:999px; padding:3px 8px; font-size:12px; text-transform:capitalize; }
    .status-active { color:var(--good); }
    .status-inactive { color:var(--muted); }
    .action-button { border:1px solid var(--border); border-radius:8px; padding:8px 10px; color:var(--text); background:var(--panel-alt); cursor:pointer; font:inherit; }
    .action-button:disabled { opacity:0.6; cursor:default; }
    .field-group { display:grid; gap:8px; }
    input[type="text"], select, textarea { width:100%; border:1px solid var(--border); border-radius:8px; background:var(--panel-alt); color:var(--text); padding:10px 12px; font:inherit; }
    textarea { min-height:240px; resize:vertical; font-family:ui-monospace,SFMono-Regular,Consolas,monospace; font-size:13px; }
    #policy-test-request { min-height:280px; }
    .inline-option { display:flex; align-items:center; gap:8px; }
    .form-actions { display:flex; gap:10px; align-items:center; flex-wrap:wrap; }
    .feedback[data-state="success"] { color:var(--good); }
    .feedback[data-state="error"] { color:var(--warn); }
    .feedback[data-state="pending"] { color:var(--accent); }
    .back-link { display:inline-flex; margin-top:18px; color:var(--accent); text-decoration:none; font-weight:600; }
    @media (max-width: 900px) { .hero, .panel-header, .bundle-grid { grid-template-columns:1fr; } }
    @media (max-width: 800px) { table, thead, tbody, th, td, tr { display:block; } thead { display:none; } td { padding:8px 0; } tr { border-top:1px solid var(--border); padding:12px 0; } }
  </style>
</head>
<body>
  <header>
    <div class="header-inner">
      <div class="eyebrow">ActantOS Policy</div>
      <h1>Policy bundles</h1>
      <p>Review the active Cedar bundle, upload a candidate, and promote a stored version without leaving the operator plane.</p>
    </div>
  </header>
  <main>
    <section class="hero">
      <div>
        <div class="tenant">Tenant: <code>${escapeHtml(options.tenantId)}</code></div>
        <h2>Active policy</h2>
        <p>${activeBundle === undefined ? "No policy bundles stored for this tenant yet." : `Currently enforcing bundle ${escapeHtml(activeBundle.version)}.`}</p>
      </div>
      <div class="secondary">${String(options.bundles.length)} bundle${options.bundles.length === 1 ? "" : "s"} stored</div>
    </section>
    <section class="panel">
      <div class="panel-header">
        <div>
          <h2>Bundle inventory</h2>
          <p>Stored versions remain available for rollback; inactive bundles can be promoted immediately.</p>
        </div>
        <div class="secondary">Backed by <code>/v1/policy-bundles</code></div>
      </div>
      <div class="bundle-grid">
        <div>
          <table aria-label="Policy bundles">
            <thead>
              <tr><th>Version</th><th>Engine</th><th>Source Hash</th><th>Status</th><th>Created</th><th>Action</th></tr>
            </thead>
            <tbody>${renderBundleRows(options.bundles)}</tbody>
          </table>
        </div>
        <div class="preview">
          <div class="primary">${activeBundle === undefined ? "No active bundle" : `Bundle ${escapeHtml(activeBundle.version)}`}</div>
          <div class="secondary">${activeBundle === undefined ? "Upload a bundle to start policy review." : escapeHtml(activeBundle.id)}</div>
          <pre data-active-policy-source="true">${escapeHtml(activeBundle?.source_text ?? "No Cedar source stored yet.")}</pre>
        </div>
      </div>
    </section>
    <section class="panel">
      <div class="panel-header">
        <div>
          <h2>Upload bundle</h2>
          <p>Store a Cedar candidate, optionally promote it immediately, and keep the previous version available for rollback.</p>
        </div>
        <div class="secondary">Backed by <code>/v1/policy-bundles</code></div>
      </div>
      <form data-policy-create-form="true">
        <div class="form-grid">
          <div class="field-group">
            <label for="policy-version">Version</label>
            <input id="policy-version" name="version" type="text" value="" placeholder="0.2.0" />
          </div>
          <div class="field-group">
            <label for="policy-source">Cedar source</label>
            <textarea id="policy-source" name="source_text" spellcheck="false">permit (
  principal,
  action,
  resource
)
when {
  resource.credential_access == false
};</textarea>
          </div>
          <label class="inline-option"><input type="checkbox" name="active" /> Promote immediately</label>
          <div class="form-actions">
            <button class="action-button" type="submit">Store bundle</button>
            <span class="feedback" data-policy-feedback="true" data-state="idle">Ready to validate and store a candidate bundle.</span>
          </div>
        </div>
      </form>
      <a class="back-link" href="${buildPolicyDashboardHref(options.tenantId, options.apiKey)}">Refresh this policy view</a>
    </section>
    <section class="panel">
      <div class="panel-header">
        <div>
          <h2>Dry-run against a stored bundle</h2>
          <p>Evaluate a candidate tool call with <code>dry_run=true</code> against a stored bundle without activating it.</p>
        </div>
        <div class="secondary">Backed by <code>/v1/policy-bundles/:id/test</code></div>
      </div>
      <form data-policy-test-form="true">
        <div class="form-grid">
          <div class="field-group">
            <label for="policy-test-bundle">Bundle</label>
            <select id="policy-test-bundle" name="bundle_id" aria-label="Bundle to dry-run">
              ${options.bundles.map((row) => `
                <option value="${escapeHtml(row.id)}"${row.active ? " selected" : ""}>
                  ${escapeHtml(row.version)}${row.active ? " (active)" : ""}
                </option>
              `).join("")}
            </select>
          </div>
          <div class="field-group">
            <label for="policy-test-request">Intercept request JSON</label>
            <textarea id="policy-test-request" name="request_json" spellcheck="false">{escapeHtml(JSON.stringify({
  request_id: "req_policy_dry_run_demo",
  tenant_id: options.tenantId,
  agent: { id: "pi_demo", runtime_type: "pi", environment: "dev", risk_tier: "low" },
  subject: { user_id: "u_demo", role: "developer" },
  session: { id: "s_demo", cwd: "/workspace", purpose: "policy dry-run" },
  tool: { kind: "file", name: "guarded_read", operation: "ReadFile" },
  resource: { id: "/workspace/README.md", kind: "file", path: "/workspace/README.md" },
  action: { operation: "ReadFile", args: { path: "/workspace/README.md" } },
  normalized: { verb: "read", mutation: false, destructive: false, network: false, credential_access: false, risk_class: "low" }
}, null, 2))}</textarea>
          </div>
          <div class="form-actions">
            <button class="action-button" type="submit">Run dry-run</button>
            <span class="feedback" data-policy-test-feedback="true" data-state="idle">Pick a bundle and evaluate without promotion.</span>
          </div>
          <pre class="preview" data-policy-test-result="true">No dry-run result yet.</pre>
        </div>
      </form>
    </section>
    <script>
      const tenantId = ${JSON.stringify(options.tenantId)};
      const dashboardApiKey = ${JSON.stringify(options.apiKey ?? "")};
      const appendApiKey = (url) => {
        if (dashboardApiKey.length === 0) {
          return url;
        }
        const targetUrl = new URL(url, window.location.origin);
        targetUrl.searchParams.set("api_key", dashboardApiKey);
        return targetUrl.toString();
      };
      const feedback = document.querySelector("[data-policy-feedback='true']");
      const setFeedback = (state, message) => {
        if (!(feedback instanceof HTMLElement)) {
          return;
        }
        feedback.dataset.state = state;
        feedback.textContent = message;
      };
      const testFeedback = document.querySelector("[data-policy-test-feedback='true']");
      const setTestFeedback = (state, message) => {
        if (!(testFeedback instanceof HTMLElement)) {
          return;
        }
        testFeedback.dataset.state = state;
        testFeedback.textContent = message;
      };
      document.addEventListener("click", async (event) => {
        const target = event.target;
        if (!(target instanceof HTMLButtonElement)) {
          return;
        }
        const bundleId = target.dataset.policyActivate;
        if (bundleId === undefined) {
          return;
        }
        target.disabled = true;
        setFeedback("pending", "Promoting stored policy bundle...");
        try {
          const response = await fetch(appendApiKey("/v1/policy-bundles/" + encodeURIComponent(bundleId) + "/activate"), { method: "POST" });
          if (!response.ok) {
            setFeedback("error", "Activation failed. Review the API response and retry.");
            target.disabled = false;
            return;
          }
          setFeedback("success", "Policy bundle activated. Refresh to review the updated active source.");
          window.location.reload();
        } catch {
          setFeedback("error", "Activation failed. Retry when the dashboard can reach the API.");
          target.disabled = false;
        }
      });
      const form = document.querySelector("[data-policy-create-form='true']");
      form?.addEventListener("submit", async (event) => {
        event.preventDefault();
        if (!(form instanceof HTMLFormElement)) {
          return;
        }
        const submitButton = form.querySelector("button[type='submit']");
        if (!(submitButton instanceof HTMLButtonElement)) {
          return;
        }
        submitButton.disabled = true;
        setFeedback("pending", "Validating and storing policy bundle...");
        const formData = new FormData(form);
        const payload = {
          tenant_id: tenantId,
          version: String(formData.get("version") ?? ""),
          source_text: String(formData.get("source_text") ?? ""),
          active: formData.get("active") === "on",
        };
        try {
          const response = await fetch(appendApiKey("/v1/policy-bundles"), {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify(payload),
          });
          if (!response.ok) {
            const body = await response.json().catch(() => null);
            const detail = typeof body?.detail === "string" ? body.detail : "Upload failed. Check the request and try again.";
            setFeedback("error", detail);
            submitButton.disabled = false;
            return;
          }
          setFeedback("success", "Policy bundle stored. Refreshing the inventory...");
          window.location.reload();
        } catch {
          setFeedback("error", "Upload failed. Retry when the dashboard can reach the API.");
          submitButton.disabled = false;
        }
      });
      const testForm = document.querySelector("[data-policy-test-form='true']");
      testForm?.addEventListener("submit", async (event) => {
        event.preventDefault();
        if (!(testForm instanceof HTMLFormElement)) {
          return;
        }
        const submitButton = testForm.querySelector("button[type='submit']");
        const resultNode = document.querySelector("[data-policy-test-result='true']");
        if (!(submitButton instanceof HTMLButtonElement) || !(resultNode instanceof HTMLElement)) {
          return;
        }
        submitButton.disabled = true;
        setTestFeedback("pending", "Running dry-run against selected bundle...");
        const formData = new FormData(testForm);
        const bundleId = String(formData.get("bundle_id") ?? "");
        let requestPayload;
        try {
          requestPayload = JSON.parse(String(formData.get("request_json") ?? "{}"));
        } catch {
          setTestFeedback("error", "Request JSON is invalid.");
          submitButton.disabled = false;
          return;
        }
        try {
          const response = await fetch(appendApiKey("/v1/policy-bundles/" + encodeURIComponent(bundleId) + "/test"), {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ request: requestPayload }),
          });
          const body = await response.json().catch(() => null);
          resultNode.textContent = JSON.stringify(body, null, 2);
          if (!response.ok) {
            setTestFeedback("error", "Dry-run failed. Inspect the result payload.");
            submitButton.disabled = false;
            return;
          }
          setTestFeedback("success", "Dry-run complete: " + String(body?.decision ?? "unknown") + " (" + String(body?.reason_code ?? "n/a") + ")");
          submitButton.disabled = false;
        } catch {
          setTestFeedback("error", "Dry-run failed. Retry when the dashboard can reach the API.");
          submitButton.disabled = false;
        }
      });
    </script>
  </main>
</body>
</html>
`
}

export type { PolicyBundleRow }
