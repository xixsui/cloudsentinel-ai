"use client";

import { useEffect, useRef, useState } from "react";

import Link from "next/link";

import { ArrowRight, ChartColumnIncreasing, CircleAlert, Info, ListChecks, Radar, RefreshCw, ShieldCheck } from "lucide-react";

import { api } from "@/lib/api";

import { Summary } from "@/lib/types";

import AWSOverview from "@/components/AWSOverview";

import ScopeFilter, {Scope} from "@/components/ScopeFilter";

import GettingStarted from "@/components/GettingStarted";

const colours:Record<string,string>={Critical:"#fb6b70",High:"#f8ac64",Medium:"#f3d47a",Low:"#55bbb9",Informational:"#829bbd"};

export default function Overview(){

 const requestId=useRef(0);
 const [scope,setScope]=useState<Scope>({account:"",scan:""});

 const [summary,setSummary]=useState<Summary|null>(null);

 const [error,setError]=useState("");

 const [loading,setLoading]=useState(true);

 const refresh=()=>{const id=++requestId.current;setLoading(true);setError("");api<Summary>(`posture/summary?account_id=${encodeURIComponent(scope.account)}&scan_id=${encodeURIComponent(scope.scan)}`).then(value=>{if(id===requestId.current)setSummary(value);}).catch(e=>{if(id===requestId.current)setError(e.message);}).finally(()=>{if(id===requestId.current)setLoading(false);});};

 useEffect(()=>{refresh();},[scope.account,scope.scan]);

 const total=summary?.total||0;

 return <div className="page-stack">

  <div className="page-top"><div><p className="eyebrow">CLOUD SECURITY POSTURE</p><h1>Security Overview</h1><p className="page-subtitle">One place to understand cloud exposure, prioritize findings, and guide remediation.</p></div><button className="btn-outline" onClick={refresh}><RefreshCw size={15}/> Refresh</button></div>

  <GettingStarted/>

  <AWSOverview/>

  <ScopeFilter value={scope} onChange={setScope}/>

  <p className="muted">Stored findings accounts: {summary?.accounts?.join(", ") || "None / unknown"} · Latest finding evidence: {summary?.latest_evidence_at ? new Date(summary.latest_evidence_at).toLocaleString() : "None"}</p>

  <div className="notice"><Info size={17}/><span><b>Historical findings, not live cloud posture.</b> Scan coverage and PASS results are not included in this overview. No attack is confirmed by a failed configuration check.</span></div>

  {error&&<div className="error-card">API unavailable: {error}. Start <code>scripts/start-web-dev.sh</code> in WSL2.</div>}

  {loading&&!summary?<p className="empty-state">Loading security posture…</p>:<>

  <div className="metric-grid">

   {[{name:"Total Misconfigurations",value:total,icon:Radar,sub:"Stored FAIL findings"},{name:"Critical",value:summary?.severity.Critical||0,icon:CircleAlert,sub:"Highest source severity",tone:"critical"},{name:"High",value:summary?.severity.High||0,icon:ChartColumnIncreasing,sub:"Elevated review priority",tone:"high"},{name:"Tracked Remediations",value:summary?.tracked||0,icon:ListChecks,sub:"Engineer workflow records"}].map(({name,value,icon:Icon,sub,tone})=><div key={name} className="metric-card"><div className="metric-title">{name}<Icon size={18}/></div><div className={`metric-value ${tone||""}`}>{value.toLocaleString()}</div><div className="metric-sub">{sub}</div></div>)}

  </div>

  <div className="two-cols"><section className="panel"><div className="panel-head"><div><h2>Severity Breakdown</h2><p>By original scanner severity</p></div><span className="small-label">{total} findings</span></div>

    <div className="severity-visual"><div className="stacked-meter">{Object.entries(summary?.severity||{}).map(([key,n])=><span key={key} style={{width:`${total?n/total*100:0}%`,background:colours[key]}}/>)}</div>

    {Object.entries(summary?.severity||{}).map(([key,n])=><div key={key} className="bar-row"><span className="legend-dot" style={{background:colours[key]}}/><span>{key}</span><div className="track"><div style={{width:`${total?n/total*100:0}%`,background:colours[key]}}/></div><b>{n}</b></div>)}

    {total===0&&<p className="muted empty-note">No findings yet. Upload your own Prowler OCSF report from Scan History.</p>}

    </div></section>

    <section className="panel"><div className="panel-head"><div><h2>Findings by Source</h2><p>Where findings were collected</p></div></div><div className="source-list">{Object.entries(summary?.sources||{}).map(([source,n])=><div key={source} className="source-entry"><div className="source-logo"><ShieldCheck size={19}/></div><div><b>{source}</b><span>Source findings</span></div><strong>{n}</strong></div>)}{Object.keys(summary?.sources||{}).length===0&&<p className="muted empty-note">No source data available.</p>}</div>

    <div className="panel-foot"><Info size={15}/>{summary?.synthetic_count||0} synthetic demo findings included (when present)</div></section>

  </div>

  <section className="section-banner"><div><span className="eyebrow">INVESTIGATION WORKFLOW</span><h2>From detection to verified remediation</h2><p>Review evidence, inspect mapped weaknesses, follow human-reviewed guidance, then request a new scan for verification.</p></div><Link className="btn-primary" href="/findings">Explore findings <ArrowRight size={16}/></Link></section>

  </>}

 </div>;

}

