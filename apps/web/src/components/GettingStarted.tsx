"use client";
import {useEffect,useState} from "react";
import Link from "next/link";
import {api} from "@/lib/api";
type Status={finding_count:number;aws_connected:boolean;ai_configured:boolean;prowler_installed:boolean;scans:unknown[]};
export default function GettingStarted(){
 const [data,setData]=useState<Status|null>(null);
 useEffect(()=>{api<Status>("workspace/status").then(setData).catch(()=>{});},[]);
 if(!data||data.finding_count>0||data.scans.length>0)return null;
 return <section className="panel settings-provider"><h2>Welcome — start with your own data</h2><p>No scans or findings have been imported. Choose either path; AI configuration is optional.</p><div className="settings-provider-grid"><div><h3>Upload an existing report</h3><p>No AWS connection needed. Import a Prowler OCSF JSON report.</p><Link className="btn-primary" href="/scans#import">Upload report</Link></div><div><h3>Scan your AWS account</h3><p>Connect an AWS identity, choose a scope and start Prowler.</p><Link className="btn-primary" href={data.aws_connected?"/scans#scan-center":"/settings#aws"}>{data.aws_connected?"Start a scan":"Connect AWS"}</Link></div></div><p className="muted">AWS: {data.aws_connected?"Connected":"Not connected"} · Scanner: {data.prowler_installed?"Installed":"Setup needed"} · AI: {data.ai_configured?"Configured":"Optional — not configured"}</p><Link href="/settings#ai">Configure AI providers</Link></section>;
}
