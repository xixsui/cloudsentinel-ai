"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { api, formatDate } from "@/lib/api";

import ScanCenter from "@/components/ScanCenter";

type Scan = { id: string; scanned_at: string | null; imported_at: string;
  source: string; scope: {accounts:string[]}; synthetic: boolean; event_count: number; observation_count: number; counts: Record<string, number>;
  comparison_notice?: string; findings_imported?: number };
type Comparison = { counts: Record<string, number>; notice: string;
  items: { key: string; account: string; region: string; resource: string; check: string;
    version: string; outcome: string; before_status: string | null; after_status: string | null }[] };

export default function ScanHistory() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [before, setBefore] = useState("");
  const [after, setAfter] = useState("");
  const [result, setResult] = useState<Comparison | null>(null);
  const [file, setFile] = useState<File | null>(null);
  const [preview, setPreview] = useState<(Scan & {duplicate:boolean; repeated_observations:number; warnings:string[]}) | null>(null);
  const [pendingEvents, setPendingEvents] = useState<Record<string, unknown>[] | null>(null);
  const [synthetic, setSynthetic] = useState(false);
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const selectedBefore = scans.find(s => s.id === before);
  const selectedAfter = scans.find(s => s.id === after);
  const comparisonIssue = !selectedBefore || !selectedAfter ? "" :
    before === after ? "Choose two different scan reports." :
    selectedBefore.synthetic !== selectedAfter.synthetic ? "Synthetic and historical reports cannot be compared. Use the same evidence label for both." :
    !selectedBefore.scanned_at || !selectedAfter.scanned_at ? "A scan has no readable event time. Reimport the original JSON with the updated importer." :
    new Date(selectedAfter.scanned_at) <= new Date(selectedBefore.scanned_at) ? "After must be a later scan. Reimporting the same report does not create a newer scan." : "";
  const load = async () => setScans((await api<{items: Scan[]}>("scans")).items);
  useEffect(() => { load().catch(e => setError(e.message)).finally(() => setLoading(false)); }, []);

  async function previewFile() {
    if (!file) return;
    setBusy(true); setError(""); setMessage(""); setResult(null); setPreview(null); setPendingEvents(null);
    try {
      if (file.size > 10 * 1024 * 1024) throw new Error("Choose a JSON file smaller than 10 MB.");
      let data;
      try {data = JSON.parse(await file.text());} catch {throw new Error("Invalid JSON. Export a Prowler OCSF JSON report and try again.");}
      const events = Array.isArray(data) ? data : data?.events ?? data?.findings ?? data?.results;
      if (!Array.isArray(events)) throw new Error("Expected an OCSF event array or events/findings/results wrapper.");
      if (!events.length || events.length > 20000) throw new Error("Choose a report containing 1–20,000 events.");
      setPreview(null); setPendingEvents(null);
      const checked = await api<Scan & {duplicate:boolean; repeated_observations:number; warnings:string[]}>("scans/preview", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({events,synthetic})});
      setPreview(checked); setPendingEvents(events);
    } catch (e) { setError(e instanceof Error ? e.message : "Import failed"); }
    finally { setBusy(false); }
  }

  async function confirmImport() {
    if (!preview || !pendingEvents) return;
    setBusy(true); setError("");
    try {
      const imported = await api<Scan>("scans/import", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({events:pendingEvents,synthetic,preview_id:preview.id})});
      setPreview(null); setPendingEvents(null);
      setMessage(`Report saved: ${imported.event_count} events; ${imported.findings_imported ?? 0} FAIL findings captured. Newer stored evidence is preserved. Remediation states are unchanged.`);
      await load();
    } catch(e) {setError(e instanceof Error ? e.message : "Import failed");}
    finally {setBusy(false);}
  }

  async function compare() {
    setBusy(true); setError(""); setResult(null);
    try { setResult(await api<Comparison>(`scans/compare?before=${before}&after=${after}`)); }
    catch (e) { setError(e instanceof Error ? e.message : "Comparison failed"); }
    finally { setBusy(false); }
  }

  return <div className="page-stack">
    <div className="page-top"><div><p className="eyebrow">SCAN EVIDENCE</p><h1>Scan History</h1>
      <p className="page-subtitle">Import Prowler reports and compare check outcomes across time.</p></div></div>
    <ScanCenter onCompleted={() => {void load().catch(e=>setError(e.message));}}/>
    <div className="notice">Historical imports are scanner claims, not live AWS scans. Missing checks never count as resolved.
      Reports stay on this local server and are not sent to an AI provider.</div>
    <section id="import" className="panel scan-panel"><h2>Import OCSF JSON</h2>
      <div className="scan-controls"><label>Report file <input type="file" accept=".json,application/json" disabled={busy}
        onChange={e => {setFile(e.target.files?.[0] ?? null);setPreview(null);setPendingEvents(null);setError("");setMessage("");}}/></label>
      <label><input type="checkbox" checked={synthetic} disabled={busy} onChange={e => {setSynthetic(e.target.checked);setPreview(null);setPendingEvents(null);}}/> Synthetic demo data</label>
      <button className="btn-outline" disabled={!file || busy} onClick={previewFile}>{busy ? "Working…" : "Preview report"}</button></div>
      {preview && <div className="panel settings-provider" aria-label="Report preview"><h3>Review before importing</h3>
        <p>Account: {preview.scope.accounts.join(", ") || "Unknown"} · Scan time: {formatDate(preview.scanned_at)}</p>
        <p>{preview.synthetic ? "Synthetic demo" : "Historical report"} · {preview.event_count} events · {preview.observation_count} unique observations · {preview.repeated_observations} repeated observations</p>
        <p>{Object.entries(preview.counts).map(([label,count])=>`${label}: ${count}`).join(" · ")}</p>
        <p>{preview.findings_imported} FAIL findings captured. {preview.duplicate ? "Already imported." : "Not previously imported with this evidence label."}</p>
        {preview.warnings.map(w=><p className="notice" key={w}>{w}</p>)}
        <p className="muted">No report data has been added to this workspace. Import does not run AWS scans or mark remediation as verified.</p>
        <div className="ai-actions"><button className="btn-primary" disabled={busy} onClick={()=>void confirmImport()}>Confirm import</button><button className="btn-outline" disabled={busy} onClick={()=>{setPreview(null);setPendingEvents(null);}}>Cancel</button></div>
      </div>}
      <p className="page-subtitle">Maximum 10 MB / 20,000 events. FAIL findings appear in Overview and Misconfigurations. Leave Synthetic unchecked for real historical AWS reports.</p>
    </section>
    {error && <p className="error-inline" role="alert">{error}</p>}
    {message && <div className="notice" role="status">{message} <Link href="/findings">View findings →</Link></div>}
    <section className="panel no-padding"><div className="panel-head pad"><h2>Recent imports</h2></div>
      {loading ? <p className="empty-state">Loading scan history…</p> : !scans.length ?
        <p className="empty-state">No scan history yet. Import two reports with different scan times to compare them.</p> :
        <div className="table-scroll"><table className="findings-table"><thead><tr><th>Scan</th><th>Evidence</th><th>Scan time</th><th>Events / unique checks</th><th>PASS</th><th>FAIL</th><th>MANUAL</th><th>Unknown / conflict</th></tr></thead>
          <tbody>{scans.map(s => <tr key={s.id}><td className="mono">{s.id.slice(0, 10)}</td><td>{s.synthetic ? "Synthetic" : s.source === "Prowler web scan" ? "Web scan" : "Historical import"}<small style={{display:"block"}}>{s.scope.accounts.join(", ") || "Account unknown"}</small></td>
            <td>{s.scanned_at ? formatDate(s.scanned_at) : "Unknown — reimport report"}</td><td>{s.event_count} / {s.observation_count}</td>
            <td>{s.counts.PASS}</td><td>{s.counts.FAIL}</td><td>{s.counts.MANUAL}</td><td>{s.counts.UNKNOWN} / {s.counts.CONFLICT}</td></tr>)}</tbody>
        </table></div>}
    </section>
    <section className="panel scan-panel"><h2>Before / after comparison</h2>
      <div className="scan-controls">{(["Before", "After"] as const).map(label => <label key={label}>{label}
        <select value={label === "Before" ? before : after} disabled={busy} onChange={e => {
          (label === "Before" ? setBefore : setAfter)(e.target.value); setResult(null);
        }}><option value="">Select a scan</option>{scans.map(s => <option key={s.id} value={s.id}>
          {formatDate(s.scanned_at)} · {s.synthetic ? "Synthetic" : "Historical"} · {s.id.slice(0, 8)}</option>)}</select>
      </label>)}<button className="btn-outline" disabled={busy || !before || !after || !!comparisonIssue} onClick={compare}>Compare scans</button></div>
      {comparisonIssue && <p className="notice" role="status">{comparisonIssue}</p>}
      <p className="page-subtitle">Compare two different scans, not two uploads of the same report. Counts above refer to unique check/resource observations.</p>
    </section>
    {result && <><div className="metric-grid">{Object.entries(result.counts).map(([label, count]) =>
      <div className="metric-card" key={label}><div className="metric-title">{label}</div><div className="metric-value">{count}</div></div>)}</div>
      <p className="notice">{result.notice}</p><section className="panel no-padding"><div className="table-scroll">
      <table className="findings-table"><thead><tr><th>Outcome</th><th>Check / version</th><th>Resource</th><th>Account / region</th><th>Before → After</th></tr></thead>
        <tbody>{result.items.map(i => <tr key={i.key}><td>{i.outcome}</td><td>{i.check}<small> / {i.version}</small></td>
          <td className="scan-resource">{i.resource || "Missing resource"}</td><td>{i.account} / {i.region || "Unknown"}</td>
          <td>{i.before_status ?? "Absent"} → {i.after_status ?? "Absent"}</td></tr>)}</tbody></table>
        {!result.items.length && <p className="empty-state">No FAIL observations to compare in these reports.</p>}
      </div></section></>}
  </div>;
}
