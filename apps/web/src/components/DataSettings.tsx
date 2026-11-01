"use client";
import { useCallback, useEffect, useState } from "react";
import { api } from "@/lib/api";
type Finding = {finding_id:string; title:string; severity:string; resource:string};
type List = {items:Finding[];total:number};
export default function DataSettings() {
  const [data,setData]=useState<List|null>(null), [search,setSearch]=useState(""), [query,setQuery]=useState("");
  const [page,setPage]=useState(1), [selected,setSelected]=useState<string[]>([]);
  const [scope,setScope]=useState<"selected"|"all"|null>(null), [confirmation,setConfirmation]=useState("");
  const [busy,setBusy]=useState(false), [error,setError]=useState(""), [message,setMessage]=useState("");
  const load=useCallback(async()=>{setData(await api<List>(`findings?page=${page}&page_size=20&search=${encodeURIComponent(query)}`));},[page,query]);
  useEffect(()=>{load().catch(e=>setError(e.message));},[load]);
  function confirm(value:"selected"|"all") {setScope(value);setConfirmation("");setMessage("");setError("");}
  async function remove() {
    if(!scope) return;
    setBusy(true);setError("");
    try {
      const result=await api<{deleted:number}>("settings/data/delete",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({scope,confirmation,finding_ids:scope==="selected"?selected:[]})});
      setSelected([]);setScope(null);setConfirmation("");setMessage(`Deleted ${result.deleted} local findings. AWS resources and provider settings were not changed.`);
      if(page!==1) setPage(1); else await load();
    } catch(e) {setError(e instanceof Error?e.message:"Deletion failed");} finally {setBusy(false);}
  }
  return <section id="data" className="panel settings-provider">
    <div className="settings-provider-heading"><h2>Local data management</h2><span className="ai-mode-tag">Local records only</span></div>
    <p className="muted">Delete selected findings or start with an empty workspace. These actions never delete AWS resources, disconnect AWS, or remove AI provider credentials.</p>
    <form className="ai-actions" onSubmit={e=>{e.preventDefault();setQuery(search);setPage(1);setSelected([]);setScope(null);}}><label className="field">Find findings<input value={search} maxLength={200} disabled={busy} onChange={e=>setSearch(e.target.value)} placeholder="Search title, ID or resource"/></label><button className="btn-outline" disabled={busy}>Search</button></form>
    {data ? <><p className="muted">{data.total} matching findings · {selected.length} selected (maximum 100)</p>
      <div className="resource-table-wrap"><table className="resource-table"><thead><tr><th>Select</th><th>Finding</th><th>Severity</th></tr></thead><tbody>{data.items.map(f=><tr key={f.finding_id}><td><input type="checkbox" aria-label={`Select ${f.title}`} checked={selected.includes(f.finding_id)} disabled={busy || !!scope || (!selected.includes(f.finding_id) && selected.length>=100)} onChange={e=>setSelected(old=>e.target.checked?[...old,f.finding_id]:old.filter(id=>id!==f.finding_id))}/></td><td>{f.title}<small>{f.finding_id} · {f.resource}</small></td><td>{f.severity}</td></tr>)}</tbody></table></div>
      {!data.items.length && <p className="muted">No matching findings. Upload your own report from Scan History to get started.</p>}
      <div className="ai-actions"><button className="btn-outline" disabled={busy || page===1} onClick={()=>setPage(page-1)}>Previous</button><span>Page {page} / {Math.max(1,Math.ceil(data.total/20))}</span><button className="btn-outline" disabled={busy || page*20>=data.total} onClick={()=>setPage(page+1)}>Next</button></div>
    </> : <p>Loading findings…</p>}
    <div className="ai-actions"><button className="btn-outline danger-action" disabled={busy || !selected.length} onClick={()=>confirm("selected")}>Delete selected ({selected.length})</button><button className="btn-outline danger-action" disabled={busy} onClick={()=>confirm("all")}>Clear all findings & history</button></div>
    {scope && <div className="data-confirm" role="region" aria-label="Confirm local data deletion">
      <h3>{scope==="all"?"Clear the local workspace?":`Delete ${selected.length} selected findings?`}</h3>
      <p>{scope==="all"?"This removes ALL findings, AI analysis and feedback, remediation records, incidents, scan imports and scan comparisons. You can upload your own reports again afterwards.":"This removes the selected findings and their AI analysis, feedback and remediation records. Linked incident records are updated. Historical scan reports remain available and importing a report again can restore its findings."}</p>
      <p>Deletion cannot be undone in the app. Source JSON files and external backups remain unchanged.</p>
      <label className="field">Type {scope==="all"?"CLEAR ALL":"DELETE"} to confirm<input autoComplete="off" value={confirmation} disabled={busy} onChange={e=>setConfirmation(e.target.value)}/></label>
      <div className="ai-actions"><button className="btn-outline danger-action" disabled={busy || confirmation!==(scope==="all"?"CLEAR ALL":"DELETE")} onClick={()=>void remove()}>{busy?"Deleting…":"Confirm deletion"}</button><button className="btn-outline" disabled={busy} onClick={()=>{setScope(null);setConfirmation("");}}>Cancel</button></div>
    </div>}
    {error && <p role="alert" className="error-inline">{error}</p>}{message && <p role="status" className="result-message">{message}</p>}
  </section>;
}
