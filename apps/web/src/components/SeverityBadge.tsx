export function SeverityBadge({ severity }: { severity: string }) {
  return <span className={`severity severity-${severity.toLowerCase()}`}>{severity}</span>;
}
export function StatusBadge({ status }: { status: string }) {
  return <span className="status-pill"><span className="status-dot" />{status}</span>;
}
