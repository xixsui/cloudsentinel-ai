"use client";
import {useEffect,useState} from "react";
import {api,formatDate} from "@/lib/api";

type Summary={id:string;scanned_at:string|null;synthetic:boolean;event_count:number;observation_count:number;
  scope:{accounts:string[];regions:string[]};counts:Record<string,number>;reported_errors:number|null;reported_skipped:number|null;
  incomplete_observations:number;coverage_notice:string;outcome_notice:string;checks:string[];
  services:{service:string;basis:string;observations:number;checks:string[]}[]};

export default function ScanReport({scanId}:{scanId:string}){
 const [data,setData]=useState<Summary|null>(null),[error,setError]=useState("");
 const [identifiers,setIdentifiers]=useState(false),[notes,setNotes]=useState(false),[ai,setAI]=useState(false);
 const [busy,setBusy]=useState(false),[message,setMessage]=useState("");
 useEffect(()=>{let active=true;setData(null);setError("");setMessage("");setIdentifiers(false);setNotes(false);setAI(false);
   api<Summary>(`scans/${scanId}/summary`).then(v=>{if(active)setData(v);}).catch(e=>{if(active)setError(e.message);});return()=>{active=false;};},[scanId]);
 async function download(format:"html"|"csv"){
  setBusy(true);setError("");setMessage("");
  try{const result=await api<{filename:string;mime:string;content:string}>(`scans/${scanId}/export`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({format,include_identifiers:identifiers,include_notes:notes,include_ai:ai})});
   const url=URL.createObjectURL(new Blob([result.content],{type:result.mime}));const a=document.createElement("a");a.href=url;a.download=result.filename;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);setMessage("Report generated. Review the downloaded file before sharing.");
  }catch(e){setError(e instanceof Error?e.message:"Export failed");}finally{setBusy(false);}
 }
 return <section className="panel scan-panel" aria-label="Selected scan report"><h2>Scan summary & export</h2>
  {error&&<p className="error-inline" role="alert">{error}</p>}
  {!data?<p>Loading report summary…</p>:<>
   <p><b>{data.synthetic?"Synthetic demo":"Historical scanner evidence"}</b> · {formatDate(data.scanned_at)}<br/>Accounts: {data.scope.accounts.join(", ")||"Unknown"} · Regions: {data.scope.regions.join(", ")||"Unknown"}</p>
   <div className="ai-actions">{Object.entries(data.counts).map(([label,n])=><span className="ai-mode-tag" key={label}>{label}: {n}</span>)}</div>
   <p>{data.event_count} events · {data.observation_count} unique observations · {data.checks.length} distinct check IDs<br/>Reported errors: {data.reported_errors??"Not recorded (legacy report)"} · Reported skips: {data.reported_skipped??"Not recorded (legacy report)"}<br/>{data.incomplete_observations} observations lack comparable identity/time.</p>
   <p className="muted">{data.outcome_notice}</p><p className="notice">{data.coverage_notice}</p>
   <div className="table-scroll"><table className="findings-table"><thead><tr><th>Service represented</th><th>Source</th><th>Observations</th><th>Checks</th></tr></thead><tbody>{data.services.map(s=><tr key={`${s.service}-${s.basis}`}><td>{s.service}</td><td>{s.basis}</td><td>{s.observations}</td><td>{s.checks.length}</td></tr>)}</tbody></table></div>
   <details><summary>Check IDs present in this report</summary><ul>{data.checks.map(c=><li key={c}>{c}</li>)}</ul></details>
   <h3>Export privacy</h3><p className="muted">By default, account/resource fields are hidden and finding titles/descriptions are omitted. Check IDs and regions remain with best-effort identifier removal. Raw evidence is never included. Review before sharing.</p>
   <div className="report-options"><label><input type="checkbox" checked={identifiers} disabled={busy} onChange={e=>{setIdentifiers(e.target.checked);setNotes(false);setAI(false);}}/> Include account/resource identifiers and free-text finding details</label>
   <label><input type="checkbox" checked={notes} disabled={!identifiers||busy} onChange={e=>setNotes(e.target.checked)}/> Include current remediation notes (may contain sensitive data)</label>
   <label><input type="checkbox" checked={ai} disabled={!identifiers||busy} onChange={e=>setAI(e.target.checked)}/> Include latest saved Web Advisor text (may concern newer evidence)</label></div>
   <p className="muted">Workflow states, notes and AI are current at export, not historical scan evidence. No new AI request is made. Reports without saved finding snapshots must be reimported before export.</p>
   <div className="ai-actions"><button className="btn-outline" disabled={busy} onClick={()=>void download("html")}>Download HTML</button><button className="btn-outline" disabled={busy} onClick={()=>void download("csv")}>Download CSV</button></div>
   {message&&<p role="status">{message}</p>}
  </>}
 </section>;
}
