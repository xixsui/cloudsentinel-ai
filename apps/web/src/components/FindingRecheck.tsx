"use client";
import {useCallback,useEffect,useState} from "react";
import Link from "next/link";
import {api} from "@/lib/api";
type Job={id:string;target_finding_id?:string;status:string;message:string;verification_result?:string};
export default function FindingRecheck({id,account,region,check,state,onDone}:{id:string;account:string;region:string;check:string;state:string;onDone:()=>void}){
 const [jobs,setJobs]=useState<Job[]>([]),[consent,setConsent]=useState(false),[busy,setBusy]=useState(false),[error,setError]=useState("");
 const load=useCallback(async()=>{const data=await api<{items:Job[]}>("scans/jobs");setJobs(data.items.filter(j=>j.target_finding_id===id));},[id]);
 useEffect(()=>{void load().catch(e=>setError(e.message));},[load]);
 const active=jobs.some(j=>["queued","running","importing","cancelling"].includes(j.status));
 useEffect(()=>{if(!active)return;const timer=setInterval(()=>{void load().catch(e=>setError(e.message));},2000);return()=>clearInterval(timer);},[active,load]);
 useEffect(()=>{if(jobs[0]?.status==="completed")onDone();},[jobs[0]?.id,jobs[0]?.status,onDone]);
 async function start(){setBusy(true);setError("");try{await api(`findings/${encodeURIComponent(id)}/recheck`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({consent})});setConsent(false);await load();}catch(e){setError(e instanceof Error?e.message:"Unable to recheck");}finally{setBusy(false);}}
 return <section className="panel"><h2>Recheck this finding</h2><p className="muted">Runs a read-only scan of the check&apos;s service in {region}. Verification evaluates only this account, resource and check; other findings may also be imported.</p><p>Account {account} · Check {check}</p>{state!=="Pending Verification"&&<p className="notice">Set In Progress, then Pending Verification in Engineer Tracking before requesting a recheck.</p>}<label className="ai-consent"><input type="checkbox" checked={consent} disabled={busy||active||state!=="Pending Verification"} onChange={e=>setConsent(e.target.checked)}/><span>I approve scanning this account and service to verify the finding.</span></label><div className="ai-actions"><button className="btn-primary" disabled={!consent||busy||active||state!=="Pending Verification"} onClick={()=>void start()}>Run verification scan</button><Link className="btn-outline" href="/scans">Scan jobs / cancel</Link></div>{jobs[0]&&<p role="status">{jobs[0].status} · {jobs[0].verification_result||jobs[0].message}</p>}{error&&<p className="error-inline" role="alert">{error}</p>}</section>;
}
