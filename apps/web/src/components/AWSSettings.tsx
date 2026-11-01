"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import { api } from "@/lib/api";
export type AWSStatus = {connected: boolean; saved_access_key: boolean; storage_supported: boolean; identity: {Account: string; Arn: string} | null; region: string | null; mode: string | null; loading: boolean;
  snapshot: null | {account: string; region: string; fetched_at: string; errors: string[]; truncated: string[];
    resources: {service: string; name: string; id: string; region: string; state: string}[]}};

export default function AWSSettings() {
  const [status, setStatus] = useState<AWSStatus | null>(null);
  const [mode, setMode] = useState("access_key"), [region, setRegion] = useState("ap-southeast-1"), [profile, setProfile] = useState("");
  const [access, setAccess] = useState(""), [secret, setSecret] = useState(""), [token, setToken] = useState("");
  const [busy, setBusy] = useState(false), [error, setError] = useState("");
  const [save, setSave] = useState(false), [confirmRemove, setConfirmRemove] = useState(false);
  const [message, setMessage] = useState("");
  useEffect(() => {api<AWSStatus>("settings/aws").then(setStatus).catch(e => setError(e.message));}, []);
  async function submit(action = "connect") {
    setBusy(true); setError(""); setMessage("");
    try {
      const response = await api<AWSStatus>(`settings/aws/${action}`, {method: "POST", headers: {"Content-Type": "application/json"},
        body: JSON.stringify(action !== "connect" ? {} : {mode, region, save_credentials: mode === "access_key" && save, ...(mode === "profile" ? {profile} : {}), ...(["temporary", "access_key"].includes(mode) ? {access_key_id: access, secret_access_key: secret, ...(mode === "temporary" ? {session_token: token} : {})} : {})})});
      setStatus(response); setConfirmRemove(false); setMessage(action === "disconnect" ? "Disconnected. Saved credentials, if any, remain available." : action === "remove-saved" ? "Saved AWS credentials removed and AWS disconnected." : "AWS identity verified. " + (action === "connect" && mode === "access_key" && save ? "Credentials saved encrypted on the backend. " : "") + "Open Home and refresh AWS resources to load inventory.");
    } catch(e) {setError(e instanceof Error ? e.message : "Connection failed");}
    finally {setAccess(""); setSecret(""); setToken(""); setBusy(false);}
  }
  return <section id="aws" className="panel settings-provider">
    <div className="settings-provider-heading"><h2>AWS connection</h2><span className="ai-mode-tag">{status?.connected ? "Identity verified" : "Not connected"}</span></div>
    <p className="muted">Connect an AWS identity to view resources. Identity verification does not verify inventory permissions. Credentials stay in server memory by default. Access Keys can optionally be saved encrypted on this backend. After restarting, click Connect saved credentials; no automatic AWS request runs on page load.</p>
    {status?.connected && <p className="notice">Account {status.identity?.Account} · {status.region}<br/>{status.identity?.Arn}</p>}
    <form onSubmit={e => {e.preventDefault(); void submit();}}>
      <div className="ai-provider-selectors">
        <label className="field">Authentication<select value={mode} disabled={busy} onChange={e => {setMode(e.target.value); setAccess(""); setSecret(""); setToken("");}}>
          <option value="access_key">Access Key (ID + Secret)</option><option value="default">Server IAM Role / Environment</option><option value="profile">Server AWS Profile</option><option value="temporary">Temporary AWS credentials</option>
        </select></label>
        <label className="field">AWS region<input required value={region} maxLength={40} disabled={busy} onChange={e => setRegion(e.target.value.trim())} placeholder="ap-southeast-1"/></label>
      </div>
      {mode === "default" && <p className="muted">Uses the AWS credential chain on the backend server. No AWS request is made until you click Connect.</p>}
      {mode === "profile" && <label className="field">Profile name<input required maxLength={128} value={profile} disabled={busy} onChange={e => setProfile(e.target.value)} placeholder="Profile configured in WSL / backend server"/></label>}
      {["temporary", "access_key"].includes(mode) && <>{[["Access key ID",access,setAccess],["Secret access key",secret,setSecret],...(mode === "temporary" ? [["Session token",token,setToken]] : [])].map(([label,value,setter]) => <label key={label as string} className="field">{label as string}<input type="password" required autoComplete="new-password" spellCheck={false} disabled={busy} value={value as string} maxLength={label === "Session token" ? 16384 : 512} onChange={e => (setter as (v:string)=>void)(e.target.value.trim())}/></label>)}</>}
      {mode === "access_key" && <div><p className="muted">Enter your AWS Access Key ID and Secret Access Key. No Session Token is needed. Values are cleared after submitting and never returned by the backend.</p><label><input type="checkbox" checked={save} disabled={busy || !status?.storage_supported} onChange={e => setSave(e.target.checked)}/> Save encrypted on this backend for reuse</label><p className="muted">{status?.storage_supported ? "Optional: stored outside the project with private file permissions. Existing saved credentials remain until replaced or removed." : "Encrypted saving requires Linux/WSL. Memory-only connection is available."}</p></div>}
      <div className="ai-actions"><button className="btn-primary" disabled={busy}>{busy ? "Working…" : "Connect & verify identity"}</button>
        {status?.connected && <button type="button" className="btn-outline" disabled={busy} onClick={() => void submit("disconnect")}>Disconnect AWS</button>}
        <Link className="btn-outline" href="/">View AWS resources</Link></div>
    </form>
    {status?.saved_access_key && <div className="notice"><div><b>Encrypted AWS Access Key saved</b><p>The secret is never displayed. Removing it also disconnects the current AWS connection.</p><div className="ai-actions"><button className="btn-secondary" disabled={busy} onClick={() => void submit("connect-saved")}>Connect saved credentials</button><button className="btn-outline" disabled={busy} onClick={() => setConfirmRemove(true)}>Remove saved AWS credentials</button></div>{confirmRemove && <div><p>Remove the saved Access Key from this application? This does not revoke it in AWS.</p><div className="ai-actions"><button className="btn-outline" disabled={busy} onClick={() => void submit("remove-saved")}>Confirm removal</button><button className="btn-outline" disabled={busy} onClick={() => setConfirmRemove(false)}>Cancel</button></div></div>}</div></div>}
    {message && <p role="status" className="result-message">{message}</p>}{error && <p role="alert" className="error-inline">{error}</p>}
  </section>;
}
