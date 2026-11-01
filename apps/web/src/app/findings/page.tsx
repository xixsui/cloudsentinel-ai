"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import { ArrowRight, Search, SlidersHorizontal } from "lucide-react";
import { SeverityBadge } from "@/components/SeverityBadge";
import { api, formatDate } from "@/lib/api";
import { FindingPage } from "@/lib/types";
import ScopeFilter, {Scope} from "@/components/ScopeFilter";
export default function Findings(){
  const [scope,setScope]=useState<Scope>({account:"",scan:""});
  useEffect(()=>{const q=new URLSearchParams(window.location.search);setScope({account:q.get("account_id")||"",scan:q.get("scan_id")||""});},[]);
  const [search,setSearch]=useState("");const [severity,setSeverity]=useState("");const [page,setPage]=useState(1);
  const queryKey=JSON.stringify([page,search,severity,scope.account,scope.scan]);
  const [result,setResult]=useState<{key:string;data:FindingPage|null;error:string}|null>(null);
  const current=result?.key===queryKey?result:null;
  const data=current?.data??null;const error=current?.error??"";const busy=!current;
  useEffect(()=>{
    let live=true;
    const timer=setTimeout(()=>{
      const p=new URLSearchParams({page:String(page),page_size:"15"});if(scope.account)p.set("account_id",scope.account);if(scope.scan)p.set("scan_id",scope.scan);if(search)p.set("search",search);if(severity)p.set("severity",severity);
      api<FindingPage>(`findings?${p}`).then(d=>{if(live)setResult({key:queryKey,data:d,error:""});}).catch(e=>{if(live)setResult({key:queryKey,data:null,error:e.message});});
    },250);
    return ()=>{live=false;clearTimeout(timer);};
  },[page,search,severity,scope.account,scope.scan,queryKey]);
  return <div className="page-stack">
    <div className="page-top"><div><p className="eyebrow">CLOUD SECURITY ASSESSMENT</p><h1>Misconfigurations</h1><p className="page-subtitle">Investigate Prowler findings, understand exposures, and guide safe remediation.</p></div><span className="outline-counter">{data?.total??"—"} findings</span></div>
    <div className="notice"><SlidersHorizontal size={16}/> Filtering stored FAIL findings. Some resources may represent historical scans rather than current AWS state.</div>
    <ScopeFilter value={scope} onChange={value=>{setScope(value);setPage(1);}}/>
    <section className="panel no-padding"><div className="table-tools"><label className="search-control"><Search size={17}/><input aria-label="Search findings" placeholder="Search finding, resource or description..." value={search} onChange={e=>{setSearch(e.target.value);setPage(1);}}/></label><select aria-label="Filter severity" value={severity} onChange={e=>{setSeverity(e.target.value);setPage(1);}}><option value="">All severities</option>{["Critical","High","Medium","Low","Informational"].map(x=><option key={x}>{x}</option>)}</select></div>
     {error?<p className="error-inline">{error}</p>:<div className="table-scroll"><table className="findings-table"><thead><tr><th>Finding</th><th>Severity</th><th>Cloud Resource</th><th>Source</th><th>Detected</th><th/></tr></thead><tbody>{data?.items.map(f=><tr key={f.finding_id}><td><Link className="finding-name" href={`/findings/${encodeURIComponent(f.finding_id)}${scope.scan?`?scan_id=${scope.scan}`:""}`}>{f.title}</Link><div className="finding-code">{f.check_id||"Unknown check"} {f.synthetic&&<span className="demo-marker">SYNTHETIC</span>}</div></td><td><SeverityBadge severity={f.severity}/></td><td className="resource-cell" title={f.resource}>{f.resource||"—"}<small style={{display:"block"}}>Account {f.account_id||"unknown"} · {f.region||"unknown region"}</small></td><td><span className="source-tag">{f.source}</span></td><td className="table-date">{formatDate(f.timestamp)}</td><td><Link href={`/findings/${encodeURIComponent(f.finding_id)}${scope.scan?`?scan_id=${scope.scan}`:""}`} aria-label={`View ${f.title}`}><ArrowRight size={16}/></Link></td></tr>)}</tbody></table>{!busy&&data?.items.length===0&&<p className="empty-state">No findings match these filters.</p>}{busy&&<div className="loading-strip">Updating results…</div>}</div>}
     <div className="table-footer"><span>{data?.total?`Showing ${(page-1)*15+1}–${Math.min(page*15,data.total)} of ${data.total}`:busy?"Loading findings…":error?"Results unavailable":"No findings"}</span><div className="pagination"><button disabled={busy||page<=1} onClick={()=>setPage(v=>v-1)}>Previous</button><span>Page {page}</span><button disabled={!data||page*15>=data.total} onClick={()=>setPage(v=>v+1)}>Next</button></div></div>
    </section>
  </div>;
}
