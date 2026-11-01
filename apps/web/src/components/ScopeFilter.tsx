"use client";
import {useEffect,useState} from "react";
import {api,formatDate} from "@/lib/api";
export type Scope = {account:string;scan:string};
type Status={accounts:string[];scans:{id:string;scanned_at:string|null;scope:{accounts:string[]}}[]};
export default function ScopeFilter({value,onChange}:{value:Scope;onChange:(value:Scope)=>void}) {
  const [data,setData]=useState<Status|null>(null),[error,setError]=useState("");
  useEffect(()=>{api<Status>("workspace/status").then(setData).catch(e=>setError(e.message));},[]);
  return <section className="panel settings-provider"><div className="ai-provider-selectors">
    <label className="field">Findings account<select value={value.account} onChange={e=>onChange({account:e.target.value,scan:""})}><option value="">All stored accounts</option>{data?.accounts.map(a=><option key={a}>{a}</option>)}</select></label>
    <label className="field">Scan snapshot<select value={value.scan} onChange={e=>onChange({...value,scan:e.target.value})}><option value="">All stored scans</option>{data?.scans.filter(s=>!value.account||s.scope.accounts.includes(value.account)).map(s=><option key={s.id} value={s.id}>{formatDate(s.scanned_at)} · {s.id.slice(0,10)}</option>)}</select></label>
    </div><p className="muted">Filters apply to stored findings, independently of the currently connected AWS account. A selected scan shows its saved evidence snapshot. Older reports need reimporting before a snapshot is available. Workflow counts remain current.</p>{error&&<p className="error-inline">{error}</p>}</section>;
}
