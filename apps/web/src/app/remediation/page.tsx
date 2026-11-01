"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import { ArrowRight, ClipboardCheck, RefreshCw } from "lucide-react";
import { api,formatDate } from "@/lib/api";
import { Remediation } from "@/lib/types";
import {StatusBadge} from "@/components/SeverityBadge";
export default function RemediationTracker(){
 const [items,setItems]=useState<Remediation[]>([]),[error,setError]=useState(""),[busy,setBusy]=useState(true);
 const load=()=>{setBusy(true);api<{items:Remediation[]}>("remediations").then(d=>{setItems(d.items);setError("");}).catch(e=>setError(e.message)).finally(()=>setBusy(false));};
 useEffect(()=>{load();},[]);
 return <div className="page-stack"><div className="page-top"><div><p className="eyebrow">ENGINEER WORKFLOW</p><h1>Remediation Tracker</h1><p className="page-subtitle">Track manual fixes, ownership, evidence, and scan-based verification.</p></div><button className="btn-outline" onClick={load}><RefreshCw size={15}/> Refresh</button></div>
  <div className="metric-grid three">{["In Progress","Pending Verification","Verified"].map(name=><div className="metric-card" key={name}><div className="metric-title">{name}<ClipboardCheck size={18}/></div><div className="metric-value">{items.filter(x=>x.state===name).length}</div><div className="metric-sub">Tracked cases</div></div>)}</div>
  <div className="notice">Verified requires a newer, independent Prowler PASS for the same check and resource. A manual note alone cannot verify a fix.</div>
  <section className="panel no-padding"><div className="panel-head pad"><div><h2>Remediation Cases</h2><p>Cases are created when an engineer saves a tracking update</p></div></div>{error?<p className="error-inline">{error}</p>:busy?<p className="empty-state">Loading cases…</p>:items.length?<div className="table-scroll"><table className="findings-table"><thead><tr><th>Finding ID</th><th>Status</th><th>Assigned Engineer</th><th>Updated</th><th/></tr></thead><tbody>{items.map(r=><tr key={r.finding_id}><td className="mono truncate-id" title={r.finding_id}>{r.finding_id}</td><td><StatusBadge status={r.state}/></td><td>{r.assignee||"Unassigned"}</td><td className="table-date">{formatDate(r.updated_at)}</td><td><Link href={`/findings/${encodeURIComponent(r.finding_id)}`}><ArrowRight size={16}/></Link></td></tr>)}</tbody></table></div>:<div className="empty-centered"><ClipboardCheck size={26}/><h3>No remediation cases yet</h3><p>Open a finding and use Engineer Tracking to assign a case.</p><Link href="/findings" className="btn-outline">Browse Findings <ArrowRight size={15}/></Link></div>}</section>
 </div>;
}
