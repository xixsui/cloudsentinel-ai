"use client";
import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { AlertTriangle, BrainCircuit, CheckCircle2, ClipboardCopy, Clock3, FileSearch, RefreshCcw, ShieldCheck, Sparkles, ThumbsDown, ThumbsUp } from "lucide-react";
import { api, formatDate } from "@/lib/api";
import { AIAdvisorResult, AIAnalyzeResponse, AIHistoryEntry, AIStatus, AIFeedback } from "@/lib/types";

function AdviceSteps({ title, steps }: { title: string; steps: string[] }) {
  const [copied, setCopied] = useState<number | null>(null);
  return <section className="ai-review-card">
    <h3>{title}</h3>
    <ol className="ai-ordered-list ai-action-list">{steps.map((step, i) => <li key={i}>
      <span className="ai-step-copy">{step}</span>
      <button type="button" className="ai-copy" title="Copy this suggestion for manual review"
        aria-label={`Copy ${title.toLowerCase()} step ${i+1}`}
        onClick={async () => { try { await navigator.clipboard.writeText(step); setCopied(i); } catch { setCopied(null); } }}>
        <ClipboardCopy size={14} /> {copied === i ? "Copied" : "Copy"}
      </button>
    </li>)}</ol>
  </section>;
}

export function AIAdvisor({ findingId }: { findingId: string }) {
  const [status, setStatus] = useState<AIStatus | null>(null);
  const [history, setHistory] = useState<AIHistoryEntry[]>([]);
  const [analysis, setAnalysis] = useState<AIAdvisorResult | null>(null);
  const [activeId, setActiveId] = useState<number | null>(null);
  const [consent, setConsent] = useState(false);
  const [privacy,setPrivacy] = useState("standard");
  const [preview,setPreview] = useState<{prompt:string;hash:string;provider:string;model:string;notice:string}|null>(null);
  const [previewBusy,setPreviewBusy] = useState(false);
  async function loadPreview(){setPreviewBusy(true);setConsent(false);setPreview(null);setError("");try{setPreview(await api(`findings/${encodeURIComponent(findingId)}/ai/preview?${new URLSearchParams({privacy,provider_id:selectedProvider,model:selectedModel})}`));}catch(e){setError(e instanceof Error?e.message:"Unable to preview");}finally{setPreviewBusy(false);}}
  const [selectedProvider, setSelectedProvider] = useState("");
  const [selectedModel, setSelectedModel] = useState("");
  const [running, setRunning] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [loaded, setLoaded] = useState(false);
  const [feedbackNote, setFeedbackNote] = useState("");
  const [feedbackSaving, setFeedbackSaving] = useState(false);
  const [feedbackMessage, setFeedbackMessage] = useState("");

  const loadHistory = useCallback(async () => {
    const data = await api<{ items: AIHistoryEntry[] }>(`findings/${encodeURIComponent(findingId)}/ai/history`);
    setHistory(data.items);
    if (data.items.length) {
      setAnalysis(data.items[0].analysis);
      setActiveId(data.items[0].id);
    }
  }, [findingId]);

  useEffect(() => {
    let active = true;
    Promise.all([
      api<AIStatus>("ai/status"),
      api<{ items: AIHistoryEntry[] }>(`findings/${encodeURIComponent(findingId)}/ai/history`),
    ]).then(([config, records]) => {
      if (!active) return;
      setStatus(config);
      setHistory(records.items);
      setSelectedProvider(config.provider || "");
      setSelectedModel(config.model || "");
      if (records.items.length) {
        setAnalysis(records.items[0].analysis);
        setActiveId(records.items[0].id);
        setFeedbackNote(records.items[0].feedback?.note || "");
      }
      setLoaded(true);
    }).catch(e => {
      if(active) { setError(e instanceof Error ? e.message : "Unable to load AI advisor"); setLoaded(true); }
    });
    return () => { active = false; };
  }, [findingId]);

  const providerChoice = status?.providers?.find(item => item.id === selectedProvider);
  const modelAllowed = !!providerChoice?.models.includes(selectedModel);
  const privateDestination = providerChoice?.destination === "operator-configured";
  const visibleRun = history.find(item => item.id === activeId);

  const analyze = async (forceRefresh: boolean) => {
    if (!preview || !consent || !status?.configured || !modelAllowed || running) return;
    setRunning(true); setError(""); setNotice(""); setFeedbackMessage("");
    try {
      const response = await api<AIAnalyzeResponse>(`findings/${encodeURIComponent(findingId)}/ai/analyze`, {
        method:"POST", headers:{"Content-Type":"application/json"},
        body: JSON.stringify({consent_to_external_processing:true, force_refresh:forceRefresh,
          provider_id:selectedProvider, model:selectedModel, privacy, preview_hash:preview.hash}),
      });
      setAnalysis(response.analysis); setActiveId(response.id);
      setNotice(response.cached ? "Loaded matching cached analysis. No provider call was made." : "New AI analysis saved for engineer review.");
      setFeedbackNote("");
      await loadHistory();
    } catch(e) { setError(e instanceof Error ? e.message : "Analysis failed"); }
    finally { setRunning(false); setConsent(false); }
  };

  const saveFeedback = async (rating: "helpful" | "needs_correction") => {
    if (!activeId || feedbackSaving) return;
    setFeedbackSaving(true); setFeedbackMessage("");
    try {
      const result = await api<AIFeedback>(`findings/${encodeURIComponent(findingId)}/ai/runs/${activeId}/feedback`, {
        method: "PUT", headers: {"Content-Type": "application/json"},
        body: JSON.stringify({ rating, note: feedbackNote.trim() }),
      });
      setHistory(prev => prev.map(h => h.id === activeId ? { ...h, feedback: result } : h));
      setFeedbackMessage("Feedback saved locally for this analysis run.");
    } catch (e) { setFeedbackMessage(e instanceof Error ? e.message : "Could not save feedback"); }
    finally { setFeedbackSaving(false); }
  };

  return <section className="panel ai-advisor">
    <div className="ai-advisor-heading"><div><span className="eyebrow">OPT-IN AI DECISION SUPPORT</span><h2><BrainCircuit size={19}/> AI Remediation Advisor</h2></div><span className="ai-mode-tag">Human approval required</span></div>
    {!loaded && <p className="muted">Checking AI provider configuration…</p>}
    {loaded && status && <div className="ai-config"><span className={status.configured ? "status-indicator online" : "status-indicator"}/><div><strong>{status.configured?`${status.provider} · ${status.model}`:"Local guidance only"}</strong><p>{status.message}</p></div></div>}
    <p className="muted">Provider and default model are managed in <Link href="/settings">Settings / AI Providers</Link>.</p>
    <p className="muted">Only a redacted, bounded finding summary is sent on request to the selected provider.
      {privateDestination ? " This endpoint is configured by the server operator; it may be local or internal. Confirm its privacy policy." : " This provider is an external AI service."}
      {" "}Review advice and potential service impact before changing AWS resources.</p>
    <div className="ai-review-card"><h3>Review what will be sent</h3><label className="field">Evidence sharing<select value={privacy} disabled={running||previewBusy} onChange={e=>{setPrivacy(e.target.value);setPreview(null);setConsent(false);}}><option value="standard">Redacted summary</option><option value="minimal">Minimal — omit title and description</option></select></label><p className="muted">Account IDs, ARNs and known resource identifiers are masked. Minimal mode also excludes finding narrative text. Review for any remaining sensitive details.</p><button className="btn-outline" disabled={!modelAllowed||running||previewBusy} onClick={()=>void loadPreview()}>{previewBusy?"Preparing preview…":"Preview sending content"}</button>{preview&&<><p>{preview.provider} · {preview.model}</p><p className="muted">{preview.notice}</p><pre className="evidence-preview">{preview.prompt}</pre></>}</div>
    <label className="ai-consent"><input type="checkbox" checked={consent} disabled={!preview||running} onChange={e=>setConsent(e.target.checked)} />
      <span>I approve sending abbreviated finding metadata to {providerChoice?.name || "the selected AI provider"} for this analysis.</span>
    </label>
    <div className="ai-actions"><button className="btn-primary" disabled={!consent||!status?.configured||!modelAllowed||running} onClick={()=>void analyze(false)}><Sparkles size={16}/>{running?"Analyzing…":"Analyze finding"}</button>
      <button className="btn-secondary" disabled={!consent||!status?.configured||!modelAllowed||running} onClick={()=>void analyze(true)}><RefreshCcw size={15}/> Regenerate</button></div>
    {running && <div className="ai-progress" role="status"><div className="ai-progress-bar"/>Contacting configured provider. Only this panel is updating…</div>}
    {notice && <p className="result-message" role="status">{notice}</p>}
    {error && <div className="error-card" role="alert">{error}</div>}

    {analysis ? <div className="ai-analysis-output">
      <div className="ai-analysis-head"><strong>AI Generated Guidance</strong><span className="severity">Suggested priority: {analysis.risk_priority}</span></div>
      {visibleRun && <p className="muted">Saved analysis from {visibleRun.provider} · {visibleRun.model} · {formatDate(visibleRun.analyzed_at)}.
        {visibleRun.provider !== selectedProvider || visibleRun.model !== selectedModel
          ? " Current default differs from this saved result; Analyze uses the default shown above." : ""}</p>}

      <div className="ai-review-grid">
        <section className="ai-review-card"><h3><FileSearch size={16}/> Scan evidence (not proof of exploitation)</h3>
          {analysis.review?.scan_evidence?.length ? <dl className="ai-facts">{analysis.review.scan_evidence.map(item=><div key={item.label}><dt>{item.label}</dt><dd>{item.value}</dd></div>)}</dl> : <p className="muted">See Finding Overview for the original Prowler check.</p>}
          <p className="muted">{analysis.review?.activity_evidence || "Static configuration findings do not establish an observed attack."}</p>
        </section>
        <section className="ai-review-card"><h3>Unverified conditions</h3>
          <ul>{(analysis.review?.unverified_conditions || ["Confirm actual exposure, intended access, and remediation impact."]).map((item,i)=><li key={i}>{item}</li>)}</ul>
        </section>
      </div>
      <section className="ai-review-card"><h3>Security impact</h3><p className="long-copy">{analysis.explanation}</p>
        <h3>Potential abuse scenario (conditional)</h3><p className="long-copy">{analysis.attack_scenario || "No scenario provided. No attack is confirmed."}</p>
        <h3>Priority rationale</h3><p className="long-copy">{analysis.risk_justification}</p></section>

      <div className="ai-review-card ai-review-status">
        <div><strong>Recommendation review · {analysis.review?.alerts.length || 0} pattern alert(s)</strong>
          <p className="muted">{analysis.review?.disclaimer || "Engineer review required; model output is not validated as executable or safe."}</p></div>
        {analysis.review?.alerts.length ? <div className="ai-flag-list" role="alert">{analysis.review.alerts.map(alert=><div className="ai-flag" key={alert.code}>
          <AlertTriangle size={17}/><div><strong>{alert.title}</strong><p>{alert.explanation}</p><p><b>Engineer check:</b> {alert.engineer_check}</p></div></div>)}</div> :
          <p className="ai-no-flags"><CheckCircle2 size={17}/> No known patterns flagged. This is <strong>not</strong> a safety certification.</p>}
      </div>
      <AdviceSteps title="Suggested remediation — review before use" steps={analysis.mitigation_steps}/>
      <AdviceSteps title="Verification checklist" steps={analysis.verification_steps}/>
      {analysis.cautions.length>0&&<div className="ai-warning"><AlertTriangle size={18}/><div><strong>Change safety considerations</strong><ul>{analysis.cautions.map((c,i)=><li key={i}>{c}</li>)}</ul></div></div>}
      <div className="info-callout"><ShieldCheck size={16}/> No cloud changes are executed. Only a later independent scan can establish a verified fix.</div>

      {visibleRun && <section className="ai-review-card ai-feedback"><h3>Engineer feedback on this analysis</h3>
        <p className="muted">Saved locally against this specific model response. Feedback does not retrain the model or approve AWS changes.</p>
        <label className="field">Note (optional, no credentials)
          <textarea rows={2} maxLength={500} value={feedbackNote} onChange={e=>setFeedbackNote(e.target.value)} placeholder="What was helpful or needs correction?" />
        </label>
        <div className="ai-actions"><button className="btn-secondary" disabled={feedbackSaving} onClick={()=>void saveFeedback("helpful")}><ThumbsUp size={15}/> Helpful</button>
          <button className="btn-secondary" disabled={feedbackSaving} onClick={()=>void saveFeedback("needs_correction")}><ThumbsDown size={15}/> Needs correction</button></div>
        {visibleRun.feedback && <p className="muted">Current feedback: <strong>{visibleRun.feedback.rating.replace("_", " ")}</strong> · {formatDate(visibleRun.feedback.updated_at)}</p>}
        {feedbackMessage && <p className="result-message" role="status">{feedbackMessage}</p>}
      </section>}
    </div> : <div className="empty-subcard"><BrainCircuit size={22}/><strong>No AI result saved</strong><p>Use the local remediation checklist, or configure a provider on the server and opt in to generate analysis.</p></div>}
    {history.length>0&&<div className="ai-history"><h3><Clock3 size={16}/> Analysis History</h3><div className="history-items">{history.map(h=><button key={h.id} className={activeId===h.id?"history-entry active":"history-entry"}
      onClick={()=>{setAnalysis(h.analysis);setActiveId(h.id);setFeedbackNote(h.feedback?.note||"");setFeedbackMessage("");}}>
      <strong>#{h.id} · {h.provider}/{h.model}</strong><span>{formatDate(h.analyzed_at)}{h.feedback ? ` · ${h.feedback.rating.replace("_"," ")}` : ""}</span></button>)}</div></div>}
  </section>;
}
