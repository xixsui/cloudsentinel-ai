"use client";
import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { api } from "@/lib/api";

type Status = {installed:boolean;version:string|null;verified:boolean;supported:boolean;target_version:string;state:string;message:string;busy:boolean;can_install:boolean;server_managed:boolean;python_version:string};
export default function ScannerSettings() {
  const [data,setData]=useState<Status|null>(null);
  const [loading,setLoading]=useState(false), [consent,setConsent]=useState(false), [error,setError]=useState("");
  const load=useCallback(async()=>{const next=await api<Status>("settings/scanner");setData(next);setError("");},[]);
  useEffect(()=>{void load().catch(e=>setError(e.message));},[load]);
  useEffect(()=>{if(!data?.busy)return;const timer=setInterval(()=>{void load().catch(e=>setError(e.message));},2500);return()=>clearInterval(timer);},[data?.busy,load]);
  async function install(){setLoading(true);setError("");try{setData(await api<Status>("settings/scanner/install",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({consent})}));setConsent(false);}catch(e){setError(e instanceof Error?e.message:"Installation failed");}finally{setLoading(false);}}
  return <section id="scanner" className="panel settings-provider">
    <div className="settings-provider-heading"><h2>Prowler scanner</h2><span className="ai-mode-tag">{!data?"Checking…":data.busy?"Setting up":data.verified?"Ready":data.installed?"Needs attention":"Not installed"}</span></div>
    <p className="muted">Install the scanner once on this backend. CloudSentinel runs it for you; AWS credentials and permissions are configured separately.</p>
    {data&&<>
      <p>Python {data.python_version} · Prowler {data.version??(data.installed?"version could not be verified":"not detected")}</p>
      {!data.supported&&<p className="notice">Automatic setup and web scanning require Linux / WSL and Python 3.10 or newer.</p>}
      {data.server_managed&&<p className="notice">The scanner path is managed by the server configuration. Contact the operator to change or repair it.</p>}
      {data.installed&&!data.verified&&<p className="notice">A scanner was found but its version check failed. Check its installation on the backend; it will not be overwritten.</p>}
      {data.can_install&&<><p className="muted">Installs Prowler {data.target_version} from PyPI in an isolated environment. Internet access and disk space are required. Existing Python packages are kept separate.</p>
        <label className="ai-consent"><input type="checkbox" checked={consent} disabled={loading} onChange={e=>setConsent(e.target.checked)}/><span>Download and install Prowler and its dependencies on this backend.</span></label></>}
      <p role="status" aria-live="polite">{data.message}</p>
      {data.busy&&<div className="ai-progress"><div className="ai-progress-bar"/><span>{data.state} — you can leave this page and return. Keep the backend running.</span></div>}
      <div className="ai-actions">
        {data.can_install&&<button className="btn-primary" disabled={loading||!consent} onClick={()=>void install()}>{loading?"Starting…":["failed","interrupted"].includes(data.state)?"Retry installation":"Install Prowler"}</button>}
        <button className="btn-outline" disabled={loading} onClick={()=>void load().catch(e=>setError(e.message))}>Refresh environment</button>
        {data.verified&&data.supported&&<Link className="btn-outline" href="/scans">Go to scans →</Link>}
      </div>
    </>}
    {error&&<p className="error-inline" role="alert">{error} {!data&&<button className="btn-outline" onClick={()=>void load().catch(e=>setError(e.message))}>Retry</button>}</p>}
  </section>;
}
