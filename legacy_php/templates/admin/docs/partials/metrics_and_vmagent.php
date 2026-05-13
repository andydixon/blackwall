<h4>Metrics Surfaces</h4>
<ul>
    <li>In-application dashboard metrics under <code>/admin/dashboard</code>.</li>
    <li>JSON metrics endpoint at <code>/metrics</code> (token-gated if configured).</li>
    <li>Optional per-event push to vmagent in Prometheus exposition format.</li>
</ul>

<h4>Event Push to vmagent</h4>
<p>
    When enabled, each audit event emits a single metric sample with value <code>1</code>.
    The <code>event_name</code> label carries the event identifier.
</p>

<h4>Configuration</h4>
<pre><code>EVENT_METRICS_PUSH_ENABLED=true
EVENT_METRICS_PUSH_URL=http://127.0.0.1:8429/api/v1/import/prometheus
EVENT_METRICS_PUSH_METRIC_NAME=blackwall_event
EVENT_METRICS_PUSH_TIMEOUT_MS=250
EVENT_METRICS_PUSH_INCLUDE_OUTCOME=true
EVENT_METRICS_PUSH_STATIC_LABELS=environment=production,instance=blackwall-1</code></pre>

<h4>Example Line Sent</h4>
<pre><code>blackwall_event{event_name="admin.login.success",outcome="success",environment="production"} 1</code></pre>

<h4>Validation Steps</h4>
<ol>
    <li>Enable event push in <code>.env</code>.</li>
    <li>Perform a known action (for example admin login).</li>
    <li>Confirm vmagent ingestion and downstream query visibility.</li>
    <li>Check for push failures in PHP logs if expected metrics are absent.</li>
</ol>

<h4>Operational Cautions</h4>
<ul>
    <li>Use conservative timeout settings to avoid request latency impact.</li>
    <li>Keep static labels stable to prevent cardinality growth.</li>
    <li>Avoid embedding sensitive values in labels.</li>
</ul>
