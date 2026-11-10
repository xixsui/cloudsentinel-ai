"use client";
import {useCallback,useEffect,useState} from "react";
import {api} from "@/lib/api";
export default function SystemStatus(){
 const [error,setError]=useState(""),[checking,setChecking]=useState(true);
 const check=useCallback(async()=>{setChecking(true);try{await api("health",{signal:AbortSignal.timeout(18000)});setError("");
 }catch(e){setError(e instanceof Error?e.message:"Unable to check the local API");}finally{setChecking(false);}},[]);
 useEffect(()=>{void check();},[check]);
 if(!error)return null;
 return <div className="notice error-inline" role="status"><div><b>Local API needs attention</b>
 <p>{error}</p><p>Run Check CloudSentinel.cmd (Windows) or bash scripts/check-linux.sh (Linux) for dependency, port and API checks. Start CloudSentinel, then reload the page.</p>
 <div className="ai-actions"><button className="btn-outline" disabled={checking} onClick={()=>void check()}>Check connection</button>{error&&<button className="btn-outline" onClick={()=>window.location.reload()}>Reload page</button>}</div></div></div>;
}
