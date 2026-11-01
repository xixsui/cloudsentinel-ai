"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { Activity, ArrowUpRight, CircleHelp, Cloud, LayoutDashboard, ListChecks, Radar, ShieldCheck, Settings } from "lucide-react";

const nav = [
  { href: "/", title: "Overview", icon: LayoutDashboard },
  { href: "/findings", title: "Misconfigurations", icon: Radar },
  { href: "/scans", title: "Scan History", icon: Activity },
  { href: "/remediation", title: "Remediation Tracker", icon: ListChecks },
  { href: "/settings", title: "Settings", icon: Settings },
];
export function Shell({ children }: { children: React.ReactNode }) {
  const current = usePathname();
  return <div className="shell">
    <aside className="sidebar">
      <Link href="/" className="brand"><span className="brand-icon"><ShieldCheck size={22}/></span><span>CloudSentinel <b>AI</b><small>SECURITY POSTURE PLATFORM</small></span></Link>
      <div className="nav-group-label">WORKSPACE</div>
      <nav className="nav-list" aria-label="Main navigation">{nav.map(({href,title,icon:Icon})=><Link key={href} href={href} className={`nav-link ${(href==="/"?current===href:current.startsWith(href))?"active":""}`}><Icon size={17}/>{title}</Link>)}</nav>
      <div className="nav-group-label nav-secondary">INTEGRATIONS</div>
      <Link className="nav-link" href="/settings#scanner"><Cloud size={17}/> AWS / Prowler</Link>
      <div className="sidebar-bottom"><div className="local-pill"><span className="live-dot"/> Local Development</div><p>Local security workspace<br/>Read-only AWS scanning</p><a href="http://127.0.0.1:8000/docs" target="_blank" rel="noreferrer">API docs <ArrowUpRight size={12}/></a></div>
    </aside>
    <div className="main-shell">
      <header className="topbar"><div className="breadcrumb"><Activity size={15}/> CSPM Workspace <span>/</span> {current==="/"?"Overview":current.startsWith("/settings")?"Settings":current.startsWith("/scans")?"Scan History":current.startsWith("/remediation")?"Remediation Tracker":"Misconfigurations"}</div><div className="topbar-right"><span className="topbar-badge">LOCAL PREVIEW</span><CircleHelp size={17} className="muted-ink"/></div></header>
      <main className="content">{children}</main>
    </div>
  </div>;
}
