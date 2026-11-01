"use client";
import {useEffect,useState} from "react";
import {api,formatDate} from "@/lib/api";
import type {AWSStatus} from "./AWSSettings";
export default function AWSDiagnostics(){
 const [data,setData]=useState<AWSStatus|null>(null),[error,setError]=useState(""),[busy,setBusy]=useState(false);
 useEffect(()=>{if(!data?.loading)return;const timer=setInterval(()=>{api<AWSStatus>("aws/inventory").then(setData).catch(e=>setError(e.message));},2500);return()=>clearInterval(timer);},[data?.loading]);
 async function run(){setBusy(true);setError("");try{setData(await api<AWSStatus>("aws/inventory/refresh",{method:"POST",headers:{"Content-Type":"application/json"},body:"{}"}));}catch(e){setError(e instanceof Error?e.message:"Diagnostics failed");}finally{setBusy(false);}}
 return <section className="panel settings-provider"><h2>AWS read-access diagnostics</h2><p className="muted">Run the same read-only resource listing used on Home. Reports inaccessible services and credential/network failures. This is not a complete Prowler permissions audit and does not change IAM policies.</p><button className="btn-outline" disabled={busy||data?.loading} onClick={()=>void run()}>{busy||data?.loading?"Checking AWS read access…":"Check AWS read access"}</button>{error&&<p role="alert" className="error-inline">{error}</p>}{data?.snapshot&&!data.loading&&<div><p>Checked {formatDate(data.snapshot.fetched_at)} · Account {data.snapshot.account}</p>{data.snapshot.errors.length?data.snapshot.errors.map(e=><p key={e} className="notice">{e}</p>):<p className="result-message">The supported resource-listing requests completed without reported errors.</p>}</div>}</section>;
}
