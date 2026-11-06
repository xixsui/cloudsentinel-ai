"use client";
import {useState} from "react";
import {api} from "@/lib/api";
type Preview={counts:Record<string,number>;created_at:string;sha256:string};
export default function WorkspaceBackup(){
  const [archive,setArchive]=useState<unknown>(null),[preview,setPreview]=useState<Preview|null>(null);
  const [confirm,setConfirm]=useState(""),[busy,setBusy]=useState(false),[message,setMessage]=useState(""),[error,setError]=useState("");
  const post=<T,>(action:string,body:unknown)=>api<T>(`settings/data/${action}`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
  async function download(){setBusy(true);setError("");setMessage("");try{
    const data=await post<unknown>("backup",{});const url=URL.createObjectURL(new Blob([JSON.stringify(data)],{type:"application/json"}));
    const a=document.createElement("a");a.href=url;a.download=`cloudsentinel-workspace-${new Date().toISOString().slice(0,10)}.json`;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
    setMessage("Backup downloaded. Keep it private: it contains scan evidence and notes.");
  }catch(e){setError(e instanceof Error?e.message:"Backup failed");}finally{setBusy(false);}}
  async function choose(file?:File){setPreview(null);setArchive(null);setConfirm("");setError("");setMessage("");if(!file)return;setBusy(true);try{
    if(file.size>20*1024*1024)throw new Error("Archive exceeds 20 MB.");
    const data=JSON.parse(await file.text());const checked=await post<Preview>("preview",data);setArchive(data);setPreview(checked);
  }catch(e){setError(e instanceof Error?e.message:"Invalid archive");}finally{setBusy(false);}}
  async function restore(){if(!preview||confirm!=="RESTORE")return;setBusy(true);setError("");try{
    const result=await post<{restored:number;recovery_file:string}>("restore",{archive,sha256:preview.sha256,confirmation:confirm});
    setPreview(null);setArchive(null);setConfirm("");setMessage(`Restored ${result.restored} findings. Recovery backup: ${result.recovery_file}. Reload the page to view restored data.`);
  }catch(e){setError(e instanceof Error?e.message:"Restore failed");}finally{setBusy(false);}}
  return <section className="panel settings-provider" aria-label="Workspace backup and restore"><h2>Backup and restore</h2>
    <p>Save findings, scan evidence, remediation history and AI analysis. AWS and AI credentials are excluded. Notes and raw evidence may still contain sensitive information. Store backups privately.</p>
    <button className="btn-outline" disabled={busy} onClick={()=>void download()}>Download workspace backup</button>
    <label className="field">Preview a backup to restore (JSON, maximum 20 MB)<input type="file" accept=".json,application/json" disabled={busy} onChange={e=>void choose(e.target.files?.[0])}/></label>
    {preview&&<div className="data-confirm"><h3>Replace workspace data?</h3><p>Archive created {preview.created_at}. This replaces current records, clears scan job history and cached AI responses, and saves a private recovery backup on the backend. Credentials are kept. Restored verification states are historical records, not a new live scan.</p>
      <ul>{Object.entries(preview.counts).filter(([,n])=>n>0).map(([name,n])=><li key={name}>{name.replaceAll("_"," ")}: {n}</li>)}</ul>
      <p>{preview.counts.findings} findings in this backup.</p><label className="field">Type RESTORE to confirm<input value={confirm} disabled={busy} autoComplete="off" onChange={e=>setConfirm(e.target.value)}/></label>
      <button className="btn-outline danger-action" disabled={busy||confirm!=="RESTORE"} onClick={()=>void restore()}>Restore workspace</button>
    </div>}
    {busy&&<p role="status">Working…</p>}{error&&<p role="alert" className="error-inline">{error}</p>}{message&&<p role="status">{message}</p>}
  </section>;
}
