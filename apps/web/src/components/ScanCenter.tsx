"use client";
import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import ScanFailure from "./ScanFailure";
import { api, formatDate } from "@/lib/api";
import type { AWSStatus } from "./AWSSettings";
type Job = {target_finding_id?:string;id:string;account:string;region:string;services:string[];status:string;message:string;created_at:string;finished_at:string|null;scan_id:string|null;findings_imported:number};
type Jobs = {items:Job[];installed:boolean;services:string[]};
const active = (s:string) => ["queued","running","importing","cancelling"].includes(s);
const serviceNames: Record<string,string> = {cloudtrail:"CloudTrail",cloudwatch:"CloudWatch",config:"AWS Config",ec2:"EC2",guardduty:"GuardDuty",iam:"IAM",kms:"KMS",rds:"RDS",s3:"S3",vpc:"VPC"};
export default function ScanCenter({onCompleted}:{onCompleted?:()=>void}) {
  const [data,setData]=useState<Jobs|null>(null), [aws,setAws]=useState<AWSStatus|null>(null);
  const [region,setRegion]=useState("ap-southeast-1"), [services,setServices]=useState(["s3","iam","ec2"]);
  const [retryNotice,setRetryNotice]=useState("");
  const [demo,setDemo]=useState("");
  const [consent,setConsent]=useState(false), [busy,setBusy]=useState(false), [error,setError]=useState("");
  const load=useCallback(async()=>{const [jobs,connection]=await Promise.all([api<Jobs>("scans/jobs"),api<AWSStatus>("settings/aws")]);setData(jobs);setAws(connection);setError("");},[]);
  useEffect(()=>{load().catch(e=>setError(e.message));},[load]);
  useEffect(()=>{setConsent(false);if(aws?.region)setRegion(aws.region);},[aws?.identity?.Account]);
  const running=data?.items.some(j=>active(j.status));
  const validRegion=/^[a-z]{2}(?:-gov)?-[a-z0-9-]+-\d+$/.test(region);
  const validServices=services.length>0&&services.every(s=>data?.services.includes(s));
  const ready=!error&&!!aws?.connected&&!!aws.identity?.Account&&!!data?.installed&&validRegion&&validServices&&!running;

  useEffect(()=>{if(!running)return;const timer=setInterval(()=>{load().catch(e=>setError(e.message));},2000);return()=>clearInterval(timer);},[running,load]);
  useEffect(()=>{if(data?.items[0]?.status==="completed")onCompleted?.();},[data?.items[0]?.id,data?.items[0]?.status]); // refresh imported history once on completion
  async function start(){if(!ready||!consent)return;setBusy(true);setError("");try{await api("scans/start",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({account_id:aws?.identity?.Account,region,services,consent})});setConsent(false);await load();}catch(e){setError(e instanceof Error?e.message:"Unable to start scan");}finally{setBusy(false);}}
  function prepareRetry(j:Job){
    setConsent(false);
    if(j.account!==aws?.identity?.Account){setRetryNotice(`Connect AWS account ${j.account} before preparing this retry.`);return;}
    setRegion(j.region);setServices([...j.services]);setRetryNotice("Previous scope restored. Review the account, region and services, then confirm again and click Start scan. The previous record is retained.");
    document.getElementById("scan-center")?.scrollIntoView({behavior:"smooth"});
  }
  async function cancel(id:string){setBusy(true);setError("");try{await api(`scans/jobs/${id}/cancel`,{method:"POST",headers:{"Content-Type":"application/json"},body:"{}"});await load();}catch(e){setError(e instanceof Error?e.message:"Unable to cancel");}finally{setBusy(false);}}
  return <section id="scan-center" className="panel settings-provider"><h2>Run a Prowler scan</h2>
    <p className="muted">Read-only checks using the connected AWS identity. Findings are imported automatically; remediation changes are never applied. Maximum duration: 30 minutes.</p>
    <div className="notice"><div><h3>Before you scan</h3><ul>
      <li>AWS: {!aws?"Checking...":aws.connected?`Connected: ${aws.identity?.Account}`:<Link href="/settings#aws">Connect AWS in Settings</Link>}</li>
      <li>Prowler: {!data?"Checking...":data.installed?"Executable detected":<Link href="/settings#scanner">Set up Prowler in Settings</Link>}</li>
      <li>Region: {validRegion?`${region} (format valid)`:"Enter a region such as ap-southeast-1 below."}</li>
      <li>Services: {validServices?`${services.length} selected`:"Select at least one supported service below."}</li>
      <li>Scan slot: {!data?"Checking...":running?"Busy: wait or cancel the active scan below.":"Available"}</li>
    </ul><p className="muted">Local readiness only. AWS identity is checked again at launch; region availability and scan permissions are not guaranteed. <Link href="/settings#aws">Review AWS settings and read-access diagnostics</Link></p></div></div>
    {!aws?.connected?<p className="notice"><Link href="/settings#aws">Connect AWS in Settings</Link> to enable live scanning. You can import an existing report below without AWS credentials.</p>:<p className="notice">Target account: <b>{aws.identity?.Account}</b>. The scan keeps this identity even if you later disconnect or switch accounts; use Cancel to stop it.</p>}
    {data && !data.installed && <div className="notice"><span>Prowler is not installed. <Link href="/settings#scanner">Set up the scanner in Settings →</Link> Then refresh scan status here.</span></div>}
    <label className="field">Scan region<input value={region} disabled={busy||running} maxLength={40} aria-invalid={!validRegion} onChange={e=>{setRegion(e.target.value.trim());setConsent(false);}}/></label>
    <fieldset className="scan-services" disabled={busy||running}>
      <legend>Services to scan</legend>
      <div className="scan-services-toolbar"><span aria-live="polite">{services.length} selected</span><div><button type="button" disabled={!data} onClick={()=>{setServices(data?.services??[]);setConsent(false);}}>Select all</button><button type="button" onClick={()=>{setServices([]);setConsent(false);}}>Clear</button></div></div>
      <div className="scan-services-grid">{data?.services.map(s=><label className={`scan-service${services.includes(s)?" is-selected":""}`} key={s}><input type="checkbox" checked={services.includes(s)} onChange={e=>{setServices(old=>e.target.checked?[...old,s]:old.filter(x=>x!==s));setConsent(false);}}/><span>{serviceNames[s]??s}</span></label>)}</div>
    </fieldset>
    <p className="muted">Regional checks use the selected region; account-wide services such as IAM may also be included. Results are limited to accessible checks, not proof of complete account security.</p>
    <div className="scan-consent-box">
      <label className="scan-consent"><input type="checkbox" checked={consent} disabled={busy||!ready} aria-describedby="scan-consent-help" onChange={e=>setConsent(e.target.checked)}/><span>I authorize a scan of the displayed AWS account and selected scope.</span></label>
      <p id="scan-consent-help">{!aws?.connected?<><Link href="/settings#aws">Connect AWS in Settings →</Link><span> This confirmation becomes available after your AWS identity is verified.</span></>:running?"A scan is in progress. Wait for it to finish or cancel it before starting another.":"Confirm the account, region and services above, then check this box to enable Start scan."}</p>
    </div>
    <div className="ai-actions"><button className="btn-primary" disabled={busy||!ready||!consent} onClick={()=>void start()}>Start scan</button><button className="btn-outline" disabled={busy} onClick={()=>void load().catch(e=>setError(e.message))}>Refresh scan status</button></div>
    {retryNotice&&<p className="notice" role="status">{retryNotice}</p>}
    {error&&<p className="error-inline" role="alert">{error}</p>}
    {data?.items.map(j=><div key={j.id} className="notice"><div><b>{j.status.toUpperCase()} · Account {j.account} · {j.region}</b><p>{j.services.join(", ")} · Started {formatDate(j.created_at)}{j.finished_at?` · Finished ${formatDate(j.finished_at)}`:""}</p><p role="status">{j.message}</p>{["failed","timed_out","interrupted","cancelled"].includes(j.status)&&<><ScanFailure status={j.status} message={j.message}/>{j.target_finding_id?<Link href={`/findings/${encodeURIComponent(j.target_finding_id)}`}>Return to finding to request a new verification</Link>:<button className="btn-outline" disabled={busy||running} onClick={()=>prepareRetry(j)}>Prepare retry with same scope</button>}</>}{j.scan_id&&<p>{j.findings_imported} FAIL findings imported. <Link href={`/findings?account_id=${encodeURIComponent(j.account)}&scan_id=${j.scan_id}`}>View findings from this scan →</Link></p>}{active(j.status)&&<button className="btn-outline" disabled={busy||j.status==="importing"} onClick={()=>void cancel(j.id)}>Cancel scan</button>}</div></div>)}
    <details><summary>Preview failure guidance (demo only)</summary><p className="muted">Example messages only. No AWS requests, scan jobs or database changes.</p><label className="field">Example failure<select value={demo} onChange={e=>setDemo(e.target.value)}><option value="">Choose an example</option><option value="expired">Credentials expired</option><option value="denied this read">Read access denied</option><option value="endpoint could not">Network failure</option><option value="timeout">Timeout</option><option value="Prowler failed">Prowler failure</option></select></label>{demo&&<ScanFailure status={demo==="timeout"?"timed_out":"failed"} message={demo}/>}</details>
  </section>;
}
