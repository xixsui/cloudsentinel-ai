"use client";

import { useCallback, useEffect, useState } from "react";
import { CheckCircle2, KeyRound, Settings2, ShieldCheck, Save } from "lucide-react";
import { api } from "@/lib/api";
import { AIStatus } from "@/lib/types";

import AWSDiagnostics from "@/components/AWSDiagnostics";
import AWSSettings from "@/components/AWSSettings";
import WorkspaceBackup from "@/components/WorkspaceBackup";
import DataSettings from "@/components/DataSettings";
import ScannerSettings from "@/components/ScannerSettings";

type Provider = { id: string; name: string; configured: boolean; models: string[];
  credential_source: "environment" | "encrypted-local" | "none"; destination: string };
type Settings = { status: AIStatus; providers: Provider[]; saved_default: {provider: string; model: string} | null; storage_supported: boolean; notice: string };

function CredentialCard({ provider, supported, onSaved }: {
  provider: Provider; supported: boolean; onSaved: (data: Settings) => void;
}) {
  const [key, setKey] = useState("");
  const [busy, setBusy] = useState(false);
  const [confirmRemove, setConfirmRemove] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const managed = provider.credential_source === "environment";
  const disabled = busy || managed || !supported || (provider.id === "private" && !provider.configured);

  async function submit(action: "save" | "remove") {
    setBusy(true); setMessage(""); setError("");
    try {
      const data = await api<Settings>("settings/ai/credential", {
        method: "PUT", headers: {"Content-Type": "application/json"},
        body: JSON.stringify({provider: provider.id, action, ...(action === "save" ? {api_key: key.trim()} : {})}),
      });
      onSaved(data);
      setMessage(action === "save" ? "Key saved securely. No provider request was made; validity has not been tested." : "Saved key removed. Server environment credentials are unchanged.");
      setConfirmRemove(false);
    } catch (e) { setError(e instanceof Error ? e.message : "Unable to save credential"); }
    finally { setKey(""); setBusy(false); }
  }

  return <section className="panel settings-provider">
    <div className="settings-provider-heading"><h3>{provider.name}</h3><span className="ai-mode-tag">
      {managed ? "Server managed" : provider.credential_source === "encrypted-local" ? "Key saved" : provider.configured ? "Endpoint configured" : "Not configured"}
    </span></div>
    <p className="muted">{provider.id === "private" ? "Private endpoint and approved model are configured on the server. An API key is optional if your endpoint does not require one." : "Save a key to make this provider available for analysis. Saved keys are never shown again."}</p>
    {managed ? <p className="notice">This provider uses a server environment variable. Update it on the server and restart the service to change the key.</p> :
      <form onSubmit={e => {e.preventDefault(); void submit("save");}}>
        <label className="field">{provider.name} API key
          <input type="password" name={`api-key-${provider.id}`} autoComplete="new-password" spellCheck={false}
            value={key} maxLength={4096} disabled={disabled} onChange={e => setKey(e.target.value)}
            placeholder={provider.credential_source === "encrypted-local" ? "Enter a new key to replace the saved key" : "Paste your API key"}/>
        </label>
        <div className="ai-actions"><button type="submit" className="btn-secondary" disabled={disabled || !key.trim()}><KeyRound size={15}/>{busy ? "Saving…" : provider.credential_source === "encrypted-local" ? "Replace key" : "Save key"}</button>
          {provider.credential_source === "encrypted-local" && <button type="button" className="btn-outline" disabled={disabled} onClick={() => setConfirmRemove(true)}>Remove saved key</button>}
        </div>
      </form>}
    {confirmRemove && <div className="notice">Remove this saved key? Analysis using this provider will be unavailable unless it has another configured credential.
      <div className="ai-actions"><button className="btn-secondary" disabled={busy} onClick={() => void submit("remove")}>Confirm removal</button><button className="btn-outline" disabled={busy} onClick={() => setConfirmRemove(false)}>Cancel</button></div>
    </div>}
    {message && <p className="result-message" role="status">{message}</p>}
    {error && <p className="error-inline" role="alert">{error}</p>}
  </section>;
}

export default function SettingsPage() {
  const [data, setData] = useState<Settings | null>(null);
  const [provider, setProvider] = useState("");
  const [model, setModel] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const load = useCallback(async () => {
    const response = await api<Settings>("settings/ai");
    setData(response); setProvider(response.status.provider || ""); setModel(response.status.model || "");
  }, []);
  useEffect(() => {load().catch(e => setError(e.message));}, [load]);
  const available = data?.providers.filter(p => p.configured) || [];
  const selected = available.find(p => p.id === provider);
  const valid = !!selected?.models.includes(model);
  const changed = !data?.saved_default || provider !== data.saved_default.provider || model !== data.saved_default.model;

  async function saveDefault() {
    setBusy(true); setError(""); setMessage("");
    try {
      const response = await api<Settings>("settings/ai/default", {method: "PUT", headers: {"Content-Type": "application/json"}, body: JSON.stringify({provider, model})});
      setData(response); setMessage("Default saved. Finding analysis will use this provider and model; saved analysis history is unchanged.");
    } catch (e) {setError(e instanceof Error ? e.message : "Unable to save default");}
    finally {setBusy(false);}
  }

  return <div className="page-stack">
    <div className="page-top"><div><p className="eyebrow">WORKSPACE PREFERENCES</p><h1>Settings</h1><p className="page-subtitle">Manage AWS connections, AI providers and local data.</p></div><Settings2 size={25}/></div>
    {error && <p className="error-inline" role="alert">{error}</p>}
    <nav className="ai-actions" aria-label="Settings sections"><a className="btn-outline" href="#aws">AWS connection</a><a className="btn-outline" href="#scanner">Prowler scanner</a><a className="btn-outline" href="#ai">AI providers</a><a className="btn-outline" href="#data">Data management</a></nav>
    <AWSSettings/>
    <AWSDiagnostics/>
    <ScannerSettings/>
    <div id="ai"><h2>AI providers</h2></div>
    {!data ? <div className="panel settings-provider">{error ? <button className="btn-outline" onClick={() => void load().catch(e => setError(e.message))}>Retry</button> : <p role="status">Loading AI settings…</p>}</div> : <>
      <div className="notice"><ShieldCheck size={17}/> API keys stay on this local server after saving. They are not returned to your browser or stored in the project. Sending finding evidence still requires consent on each analysis.</div>
      {!data.storage_supported && <p className="notice">Saving settings through this page currently requires Linux/WSL. On native Windows, use server environment variables.</p>}
      <section className="panel settings-provider"><div className="settings-provider-heading"><h2>Default analysis model</h2><span className="ai-mode-tag">Applies to all findings</span></div>
        <p className="muted">{data.status.message}</p>
        <div className="ai-provider-selectors"><label className="field">AI Provider<select aria-label="Default AI Provider" value={provider} disabled={busy || !data.storage_supported}
          onChange={e => {setProvider(e.target.value); setModel(available.find(p => p.id === e.target.value)?.models[0] || ""); setMessage("");}}>
          <option value="">Choose a configured provider</option>{available.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}</select></label>
          <label className="field">Model<select aria-label="Default AI Model" value={model} disabled={busy || !selected || !data.storage_supported} onChange={e => {setModel(e.target.value); setMessage("");}}>
            <option value="">Choose an approved model</option>{selected?.models.map(m => <option key={m} value={m}>{m}</option>)}</select></label></div>
        <button className="btn-primary" disabled={busy || !valid || !changed || !data.storage_supported} onClick={() => void saveDefault()}><Save size={15}/>{busy ? "Saving…" : "Save default"}</button>
        {!available.length && <p className="muted">Save an API key below first, then choose your default provider and model.</p>}
        {message && <p className="result-message" role="status"><CheckCircle2 size={15}/> {message}</p>}
      </section>
      <div><h2>Provider credentials</h2><p className="page-subtitle">{data.notice}</p></div>
      <div className="settings-provider-grid">{data.providers.map(p => <CredentialCard key={p.id} provider={p} supported={data.storage_supported} onSaved={response => {
        setData(response);
        if (!provider) {setProvider(response.status.provider || ""); setModel(response.status.model || "");}
      }}/>)}</div>
    </>}
    <WorkspaceBackup/><DataSettings/>
  </div>;
}
