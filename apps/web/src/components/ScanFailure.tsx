"use client";
import Link from "next/link";
export function failureHelp(status:string,message:string){
  if(status==="timed_out")return {title:"Scan timed out",step:"Select fewer services and retry. Keep WSL and the backend running.",href:"/settings#scanner"};
  if(status==="interrupted")return {title:"Scan interrupted",step:"The backend stopped before completion. Start a new scan when it is running again.",href:"/settings#scanner"};
  if(status==="cancelled")return {title:"Scan cancelled",step:"No automatic retry will occur. Review the scope before starting again.",href:"/settings#scanner"};
  if(message.includes("expired"))return {title:"Credentials expired",step:"Renew temporary credentials or sign in again, then reconnect AWS.",href:"/settings#aws"};
  if(message.includes("denied this read"))return {title:"Read access denied",step:"Run read-access diagnostics. Ask your administrator to review the required read permissions and organization restrictions.",href:"/settings#aws"};
  if(message.includes("endpoint could not"))return {title:"AWS endpoint unreachable",step:"Check the region, network, proxy and DNS before retrying.",href:"/settings#aws"};
  if(message.includes("credentials")&&!message.startsWith("Prowler failed"))return {title:"AWS connection needs attention",step:"Review credentials and reconnect AWS in Settings.",href:"/settings#aws"};
  if(message.includes("limit reached"))return {title:"AWS request limit reached",step:"Wait before retrying; reduce the scan scope if this repeats.",href:"/settings#aws"};
  if(message.startsWith("Prowler failed"))return {title:"Prowler exited unsuccessfully",step:"The exit status does not identify the exact cause. Check scanner setup, reconnect AWS and review read-access diagnostics.",href:"/settings#scanner"};
  return {title:"Scan could not complete",step:"Review the message above. Check the account and scanner settings, or reduce the scope if the report exceeded limits.",href:"/settings#scanner"};
}
export default function ScanFailure({status,message}:{status:string;message:string}){const help=failureHelp(status,message);return <div className="scan-consent-box"><h3>{help.title}</h3><p>{help.step}</p><Link href={help.href}>Open relevant settings →</Link></div>;}
