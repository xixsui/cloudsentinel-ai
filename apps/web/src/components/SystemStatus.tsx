"use client";
import {useCallback,useEffect,useState} from "react";
import Link from "next/link";
import {api} from "@/lib/api";
export default function SystemStatus(){
 const [error,setError]=useState(""),[checking,setChecking]=useState(true),[aws,setAws]=useState<boolean|null>(null);
 const check=useCallback(async()=>{setChecking(true);try{await api("health",{signal:AbortSignal.timeout(18000)});setError("");
   try{const status=await api<{connected:boolean}>("settings/aws",{signal:AbortSignal.timeout(18000)});setAws(status.connected);}catch{setAws(null);}
 }catch(e){setError(e instanceof Error?e.message:"Unable to check the local API");setAws(null);}finally{setChecking(false);}},[]);
 useEffect(()=>{void check();},[check]);
 return <div className={error?"notice error-inline":"notice"} role="status"><div><b>{checking?"Checking local API…":error?"Local API needs attention":"Local API connected"}</b>
 {error?<><p>{error}</p><p>Windows: Start CloudSentinel.cmd. Linux: bash scripts/start-linux.sh. Logs are in .runtime/service.log. After recovery, reload the page to refresh its data.</p></>:!checking&&<span> · AWS: {aws===null?"status unavailable":aws?"connected":"not connected"} {!aws&&<Link href="/settings#aws">Configure AWS</Link>}</span>}
 <div className="ai-actions"><button className="btn-outline" disabled={checking} onClick={()=>void check()}>Check connection</button>{error&&<button className="btn-outline" onClick={()=>window.location.reload()}>Reload page</button>}</div></div></div>;
}
