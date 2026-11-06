"use client";
import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { api, formatDate } from "@/lib/api";
import type { AWSStatus } from "./AWSSettings";

export default function AWSOverview() {
  const [data, setData] = useState<AWSStatus | null>(null), [error, setError] = useState("");
  const [busy, setBusy] = useState(false), [filter, setFilter] = useState("");
  const [page, setPage] = useState(1);
  const load = useCallback(() => api<AWSStatus>("aws/inventory").then(setData).catch(e => setError(e.message)), []);
  useEffect(() => {void load();}, [load]);
  useEffect(() => {if (!data?.loading) return; const timer = setInterval(() => void load(), 2500); return () => clearInterval(timer);}, [data?.loading, load]);
  async function refresh() {
    setBusy(true); setError("");
    try {setData(await api<AWSStatus>("aws/inventory/refresh", {method:"POST",headers:{"Content-Type":"application/json"},body:"{}"})); setPage(1);}
    catch(e) {setError(e instanceof Error ? e.message : "Unable to refresh");} finally {setBusy(false);}
  }
  const snap = data?.snapshot;
  const rows = snap?.resources.filter(r => `${r.service} ${r.name} ${r.id} ${r.region}`.toLowerCase().includes(filter.toLowerCase())) || [];
  const counts = snap?.resources.reduce<Record<string,number>>((out,r) => {out[r.service]=(out[r.service]||0)+1; return out;}, {}) || {};
  if (!error && !data?.connected) return null;
  return <section className="panel settings-provider">
    <div className="settings-provider-heading"><div><h2>AWS resources</h2><p className="muted">Read-only account inventory, separate from imported security findings.</p></div><Link className="btn-outline" href="/settings#aws">AWS settings</Link></div>
    {error && <p className="error-inline" role="alert">{error} <button className="btn-outline" onClick={() => {setError(""); void load();}}>Retry</button></p>}
    {!data ? <p role="status">Loading connection status…</p> : !data.connected ? <div className="notice"><div><b>AWS is not connected</b><p>Connect AWS to see your resources. You can still upload a Prowler report without connecting.</p><div className="ai-actions"><Link className="btn-primary" href="/settings#aws">Connect AWS in Settings</Link><Link className="btn-outline" href="/scans">Upload scan report</Link></div></div></div> : <>
      <Link className="btn-outline" href="/scans#scan-center">Run Prowler scan</Link>
      <p>Account <b>{data.identity?.Account}</b> · Region <b>{data.region}</b></p>
      <p className="muted">EC2, VPC, security groups, RDS, Lambda and CloudTrail use this region. S3 and IAM are account-wide. This is a resource listing, not a security scan or complete AWS service inventory.</p>
      <button className="btn-secondary" disabled={busy || data.loading} onClick={() => void refresh()}>{busy || data.loading ? "Loading AWS resources…" : "Refresh AWS resources"}</button>
      {data.loading && <p role="status" className="muted">Loading in the background. You can use other pages while this completes.</p>}
      {!snap && !data.loading && <p className="muted">No snapshot yet. Refresh to query AWS using your connected identity.</p>}
      {snap && <><p className="muted">Last fetched: {formatDate(snap.fetched_at)} · {snap.resources.length} listed resources{data.loading ? " · showing previous snapshot" : ""}</p>
        {snap.errors.map(e => <p className="notice" key={e}>{e}</p>)}
        {!!snap.truncated.length && <p className="notice">Partial listing: capped at 1,000 resources per category for {snap.truncated.join(", ")}.</p>}
        <div className="ai-actions">{Object.entries(counts).map(([service,n]) => <span className="ai-mode-tag" key={service}>{service}: {n}</span>)}</div>
        <label className="field">Search resources<input value={filter} onChange={e => {setFilter(e.target.value);setPage(1);}} placeholder="Name, service, ID or region"/></label>
        <div className="resource-table-wrap"><table className="resource-table"><thead><tr><th>Service</th><th>Name / ID</th><th>Region</th><th>State</th></tr></thead><tbody>{rows.slice((page-1)*20,page*20).map((r,i) => <tr key={`${r.service}-${r.id}-${i}`}><td>{r.service}</td><td>{r.name}<small>{r.id !== r.name ? r.id : ""}</small></td><td>{r.region}</td><td>{r.state || "—"}</td></tr>)}</tbody></table></div>
        {!rows.length && <p className="muted">{snap.errors.length ? "No matching resources available. Some categories could not be read; this does not mean the account is empty." : "No matching resources in this snapshot."}</p>}
        {rows.length > 20 && <div className="ai-actions"><button className="btn-outline" disabled={page===1} onClick={()=>setPage(page-1)}>Previous</button><span>Page {page} / {Math.ceil(rows.length/20)}</span><button className="btn-outline" disabled={page*20>=rows.length} onClick={()=>setPage(page+1)}>Next</button></div>}
      </>}
    </>}
  </section>;
}
