import { FormEvent, useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity, Archive, ArrowDownToLine, Building2, Check, ChevronDown,
  ChevronRight, CircleHelp, FilePlus2, FileText, FolderClosed, LayoutDashboard,
  LockKeyhole, LogOut, Menu, MoreHorizontal, Plus, Search, Settings2, ShieldCheck,
  Share2, Upload, Users, X,
} from "lucide-react";

type User = { id: string; email: string; name: string };
type Organization = { id: string; name: string; role: "owner" | "admin" | "member" };
type DocumentItem = {
  id: string; organization_id: string; owner_id: string; owner_name: string;
  title: string; description: string; original_name: string; content_type: string;
  size: number; created_at: string; updated_at: string; permission: string;
};
type Member = { id: string; email: string; name: string; role: string };
type ActivityItem = {
  id: string; event_type: string; actor_id: string | null; resource_id: string | null;
  result: string; source_ip: string | null; request_id: string; created_at: string;
};
type Share = { user_id: string; name: string; email: string; permission: string };
type Page = "overview" | "documents" | "members" | "activity" | "profile";

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`/api${path}`, {
    ...init,
    credentials: "same-origin",
    headers: init?.body instanceof FormData
      ? init.headers
      : { "Content-Type": "application/json", ...init?.headers },
  });
  if (!response.ok) {
    const body = await response.json().catch(() => null);
    throw new Error(body?.detail || `Une erreur est survenue (${response.status})`);
  }
  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}

function formatSize(bytes: number) {
  if (bytes < 1024) return `${bytes} o`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(0)} Ko`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} Mo`;
}

function formatDate(value: string) {
  return new Intl.DateTimeFormat("fr-FR", { day: "numeric", month: "short", year: "numeric" }).format(new Date(value));
}

const eventLabels: Record<string, string> = {
  "auth.login": "Connexion", "auth.logout": "Déconnexion", "auth.register": "Création de compte",
  "document.create": "Document ajouté", "document.view": "Document consulté",
  "document.download": "Téléchargement", "document.update": "Document modifié",
  "document.delete": "Document supprimé", "document.share.update": "Partage modifié",
  "document.share.remove": "Partage retiré", "member.invitation": "Invitation envoyée",
  "member.invitation.accept": "Invitation acceptée", "member.role.update": "Rôle modifié",
  "member.remove": "Membre retiré", "organization.create": "Espace créé",
};

function App() {
  const [user, setUser] = useState<User | null>(null);
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [activeOrgId, setActiveOrgId] = useState("");
  const [page, setPage] = useState<Page>("overview");
  const [documents, setDocuments] = useState<DocumentItem[]>([]);
  const [members, setMembers] = useState<Member[]>([]);
  const [activity, setActivity] = useState<ActivityItem[]>([]);
  const [query, setQuery] = useState("");
  const [busy, setBusy] = useState(true);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [authMode, setAuthMode] = useState<"login" | "register">("login");
  const [showOrgForm, setShowOrgForm] = useState(false);
  const [showUpload, setShowUpload] = useState(false);
  const [shareDoc, setShareDoc] = useState<DocumentItem | null>(null);
  const [editingDoc, setEditingDoc] = useState<DocumentItem | null>(null);
  const [mobileNav, setMobileNav] = useState(false);

  const activeOrg = organizations.find((org) => org.id === activeOrgId) || organizations[0];
  const canManage = activeOrg?.role === "owner" || activeOrg?.role === "admin";

  const loadOrganizations = useCallback(async (preferredId?: string) => {
    const result = await api<{ organizations: Organization[] }>("/organizations");
    setOrganizations(result.organizations);
    setActiveOrgId((current) => preferredId && result.organizations.some((org) => org.id === preferredId)
      ? preferredId : result.organizations.some((org) => org.id === current) ? current : result.organizations[0]?.id || "");
  }, []);

  const completeAuthentication = async (loggedInUser: User) => {
    setUser(loggedInUser);
    let joinedOrganizationId: string | undefined;
    const invitationToken = new URLSearchParams(window.location.search).get("invitation");
    if (invitationToken) {
      try {
        const result = await api<{ organization_id: string }>("/invitations/accept", {
          method: "POST", body: JSON.stringify({ token: invitationToken }),
        });
        joinedOrganizationId = result.organization_id;
        setNotice("Invitation acceptée");
      } catch (err) {
        setError((err as Error).message);
      } finally {
        window.history.replaceState({}, "", window.location.pathname);
      }
    }
    await loadOrganizations(joinedOrganizationId);
  };

  const loadWorkspace = useCallback(async (organizationId: string) => {
    if (!organizationId) return;
    const [docs, memberResult] = await Promise.all([
      api<{ documents: DocumentItem[] }>(`/organizations/${organizationId}/documents`),
      api<{ members: Member[] }>(`/organizations/${organizationId}/members`),
    ]);
    setDocuments(docs.documents);
    setMembers(memberResult.members);
    if (activeOrg?.role !== "member") {
      const eventResult = await api<{ events: ActivityItem[] }>(`/organizations/${organizationId}/activity`);
      setActivity(eventResult.events);
    } else {
      setActivity([]);
    }
  }, [activeOrg?.role]);

  useEffect(() => {
    api<{ user: User }>("/auth/me")
      .then(async (result) => {
        await completeAuthentication(result.user);
      })
      .catch(() => setUser(null))
      .finally(() => setBusy(false));
  }, []);

  useEffect(() => {
    if (!user || !activeOrgId) return;
    loadWorkspace(activeOrgId).catch((err: Error) => setError(err.message));
  }, [user, activeOrgId, loadWorkspace]);

  useEffect(() => {
    if (!notice) return;
    const timeout = window.setTimeout(() => setNotice(""), 3500);
    return () => window.clearTimeout(timeout);
  }, [notice]);

  const refresh = async () => {
    if (activeOrgId) await loadWorkspace(activeOrgId);
  };

  const filteredDocuments = useMemo(() => documents.filter((doc) => {
    const text = `${doc.title} ${doc.description} ${doc.original_name}`.toLowerCase();
    return text.includes(query.toLowerCase());
  }), [documents, query]);

  const handleAuth = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    setError("");
    setBusy(true);
    try {
      const path = authMode === "login" ? "/auth/login" : "/auth/register";
      const body: Record<string, string> = {
        email: String(data.get("email")),
        password: String(data.get("password")),
      };
      if (authMode === "register") body.name = String(data.get("name"));
      const result = await api<{ user: User }>(path, { method: "POST", body: JSON.stringify(body) });
      await completeAuthentication(result.user);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const logout = async () => {
    try {
      await api("/auth/logout", { method: "POST" });
      setUser(null);
      setOrganizations([]);
      setDocuments([]);
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const download = async (doc: DocumentItem) => {
    try {
      const response = await fetch(`/api/documents/${doc.id}/download`, { credentials: "same-origin" });
      if (!response.ok) throw new Error("Téléchargement impossible");
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = doc.original_name;
      anchor.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      setError((err as Error).message);
    }
  };

  if (busy && !user) return <div className="loading-screen"><div className="brand-mark"><ShieldCheck size={23} /></div><span>Chargement de votre espace…</span></div>;

  if (!user) return (
    <main className="auth-page">
      <section className="auth-aside">
        <div className="brand brand-light"><span className="brand-mark"><ShieldCheck size={23} /></span>docuvault</div>
        <div className="auth-message">
          <div className="eyebrow">VOTRE ESPACE DOCUMENTAIRE</div>
          <h1>Tout votre travail,<br />à sa juste place.</h1>
          <p>Un espace sécurisé pour organiser, retrouver et partager les documents qui font avancer votre équipe.</p>
        </div>
        <div className="aside-foot"><LockKeyhole size={15} /> Vos documents restent privés et protégés.</div>
      </section>
      <section className="auth-main">
        <form className="auth-card" onSubmit={handleAuth}>
          <span className="auth-icon"><ShieldCheck size={21} /></span>
          <div className="eyebrow">BIENVENUE CHEZ DOCUVAULT</div>
          <h2>{authMode === "login" ? "Connectez-vous" : "Créez votre compte"}</h2>
          <p className="muted">{authMode === "login" ? "Retrouvez votre espace de travail." : "Commencez avec votre espace sécurisé."}</p>
          {authMode === "register" && <label>Nom complet<input name="name" autoComplete="name" required maxLength={120} /></label>}
          <label>Adresse e-mail<input name="email" type="email" autoComplete="email" required /></label>
          <label>Mot de passe<input name="password" type="password" autoComplete={authMode === "login" ? "current-password" : "new-password"} required minLength={12} /></label>
          {error && <div className="form-error">{error}</div>}
          <button className="button primary full" disabled={busy}>{authMode === "login" ? "Se connecter" : "Créer mon compte"}<ChevronRight size={17} /></button>
          <div className="auth-switch">{authMode === "login" ? "Pas encore de compte ?" : "Vous avez déjà un compte ?"}{" "}
            <button type="button" className="text-button" onClick={() => { setError(""); setAuthMode(authMode === "login" ? "register" : "login"); }}>
              {authMode === "login" ? "Créer un compte" : "Se connecter"}
            </button>
          </div>
        </form>
        <div className="auth-legal">Une plateforme de gestion documentaire pensée pour les équipes.</div>
      </section>
    </main>
  );

  const navItems: { key: Page; label: string; icon: typeof LayoutDashboard }[] = [
    { key: "overview", label: "Vue d’ensemble", icon: LayoutDashboard },
    { key: "documents", label: "Documents", icon: FolderClosed },
    { key: "members", label: "Membres", icon: Users },
    ...(canManage ? [{ key: "activity" as Page, label: "Activité", icon: Activity }] : []),
  ];

  const content = () => {
    if (!activeOrg) {
      return <div className="empty-workspace"><span className="empty-icon"><Building2 size={26} /></span><h2>Créez votre espace de travail</h2><p>Votre organisation est l’endroit où votre équipe retrouve ses documents.</p><button className="button primary" onClick={() => setShowOrgForm(true)}><Plus size={17} /> Créer une organisation</button></div>;
    }

    if (page === "overview") return (
      <>
        <div className="welcome-row"><div><div className="eyebrow">VOTRE ESPACE DE TRAVAIL</div><h1>Bonjour, {user.name.split(" ")[0]} <span className="wave">✦</span></h1><p className="muted">Voici ce qui se passe dans votre espace aujourd’hui.</p></div><button className="button primary" onClick={() => setShowUpload(true)}><FilePlus2 size={17} /> Ajouter un document</button></div>
        <div className="stat-grid">
          <div className="stat-card"><span className="stat-icon violet"><FileText size={19} /></span><div><span className="stat-label">Documents accessibles</span><strong>{documents.length}</strong><small>Dans votre espace</small></div></div>
          <div className="stat-card"><span className="stat-icon blue"><Users size={19} /></span><div><span className="stat-label">Membres</span><strong>{members.length}</strong><small>Dans votre organisation</small></div></div>
          <div className="stat-card"><span className="stat-icon green"><Share2 size={19} /></span><div><span className="stat-label">Partagés avec vous</span><strong>{documents.filter((doc) => doc.permission !== "owner" && doc.permission !== "admin").length}</strong><small>Documents collaboratifs</small></div></div>
        </div>
        <section className="panel">
          <div className="panel-heading"><div><h2>Documents récents</h2><p>Les dernières ressources de votre espace</p></div><button className="button subtle" onClick={() => setPage("documents")}>Tout voir <ChevronRight size={15} /></button></div>
          {documents.length ? <DocumentTable documents={documents.slice(0, 5)} onDownload={download} onShare={setShareDoc} onEdit={setEditingDoc} onDelete={async (doc) => { if (!window.confirm(`Supprimer « ${doc.title} » ?`)) return; try { await api(`/documents/${doc.id}`, { method: "DELETE" }); await refresh(); setNotice("Document supprimé"); } catch (err) { setError((err as Error).message); } }} /> : <EmptyDocuments onAdd={() => setShowUpload(true)} />}
        </section>
      </>
    );

    if (page === "documents") return (
      <>
        <div className="page-heading"><div><div className="eyebrow">BIBLIOTHÈQUE</div><h1>Documents</h1><p className="muted">Retrouvez et gérez les fichiers de votre espace.</p></div><button className="button primary" onClick={() => setShowUpload(true)}><Upload size={16} /> Importer un fichier</button></div>
        <div className="toolbar"><div className="searchbox"><Search size={17} /><input placeholder="Rechercher un document…" value={query} onChange={(e) => setQuery(e.target.value)} /><kbd>⌘ K</kbd></div><span className="result-count">{filteredDocuments.length} document{filteredDocuments.length === 1 ? "" : "s"}</span></div>
        <section className="panel documents-panel">{filteredDocuments.length ? <DocumentTable documents={filteredDocuments} onDownload={download} onShare={setShareDoc} onEdit={setEditingDoc} onDelete={async (doc) => { if (!window.confirm(`Supprimer « ${doc.title} » ?`)) return; try { await api(`/documents/${doc.id}`, { method: "DELETE" }); await refresh(); setNotice("Document supprimé"); } catch (err) { setError((err as Error).message); } }} /> : <EmptyDocuments onAdd={() => setShowUpload(true)} />}</section>
      </>
    );

    if (page === "members") return <MembersPage org={activeOrg} members={members} refresh={refresh} reloadOrganizations={loadOrganizations} setNotice={setNotice} setError={setError} />;
    if (page === "activity") return (
      <>
        <div className="page-heading"><div><div className="eyebrow">SUIVI DE L’ESPACE</div><h1>Activité</h1><p className="muted">Un historique des actions récentes de votre organisation.</p></div></div>
        <section className="panel activity-panel">
          {activity.length ? activity.map((event) => <div className="activity-row" key={event.id}><span className="activity-dot"><Activity size={15} /></span><div className="activity-copy"><strong>{eventLabels[event.event_type] || event.event_type}</strong><span>{event.actor_id ? `Par ${members.find((member) => member.id === event.actor_id)?.name || "un membre"}` : "Activité système"} · {event.result === "success" ? "Réussie" : "Échec"}</span></div><time>{formatDate(event.created_at)}</time></div>) : <div className="empty-state"><Activity size={23} /><strong>Aucune activité pour le moment</strong><span>Les actions de l’équipe apparaîtront ici.</span></div>}
        </section>
      </>
    );
    return <ProfilePage user={user} setUser={setUser} setNotice={setNotice} setError={setError} />;
  };

  return (
    <div className="app-shell">
      <aside className={`sidebar ${mobileNav ? "sidebar-open" : ""}`}>
        <div className="sidebar-brand"><span className="brand-mark"><ShieldCheck size={21} /></span><span>docuvault</span><button className="mobile-close icon-button" onClick={() => setMobileNav(false)}><X size={18} /></button></div>
        <div className="org-switcher">
          <span className="org-avatar">{activeOrg?.name.slice(0, 1).toUpperCase() || "D"}</span>
          <div className="org-switch-content"><span className="org-name">{activeOrg?.name || "Votre espace"}</span><small>{activeOrg ? `${activeOrg.role === "owner" ? "Propriétaire" : activeOrg.role === "admin" ? "Administrateur" : "Membre"}` : "Aucune organisation"}</small></div>
          <select aria-label="Choisir une organisation" value={activeOrgId} onChange={(e) => setActiveOrgId(e.target.value)}>{organizations.map((org) => <option value={org.id} key={org.id}>{org.name}</option>)}</select>
          <ChevronDown size={15} className="org-chevron" />
        </div>
        <button className="org-create-link" onClick={() => setShowOrgForm(true)}><Plus size={14} /> Créer un espace</button>
        <div className="nav-caption">ESPACE DE TRAVAIL</div>
        <nav className="side-nav">
          {navItems.map(({ key, label, icon: Icon }) => <button key={key} className={`nav-link ${page === key ? "active" : ""}`} onClick={() => { setPage(key); setMobileNav(false); }}><Icon size={18} /><span>{label}</span>{key === "documents" && <span className="nav-count">{documents.length}</span>}</button>)}
        </nav>
        <div className="sidebar-spacer" />
        <div className="storage-card"><span className="storage-icon"><LockKeyhole size={16} /></span><strong>Votre espace est protégé</strong><p>Les fichiers sont stockés en toute sécurité et accessibles uniquement aux membres autorisés.</p></div>
        <div className="sidebar-bottom">
          <button className={`nav-link ${page === "profile" ? "active" : ""}`} onClick={() => setPage("profile")}><Settings2 size={18} /><span>Profil et préférences</span></button>
          <button className="user-card" onClick={() => setPage("profile")}><span className="user-avatar">{user.name.split(" ").map((part) => part[0]).slice(0, 2).join("").toUpperCase()}</span><span className="user-info"><strong>{user.name}</strong><small>{user.email}</small></span><MoreHorizontal size={18} /></button>
        </div>
      </aside>
      {mobileNav && <button className="nav-backdrop" onClick={() => setMobileNav(false)} aria-label="Fermer le menu" />}
      <main className="main-area">
        <header className="topbar"><button className="mobile-menu icon-button" onClick={() => setMobileNav(true)}><Menu size={20} /></button><div className="breadcrumb"><span>{activeOrg?.name || "Mon espace"}</span>{page !== "overview" && <><ChevronRight size={14} /><strong>{navItems.find((item) => item.key === page)?.label || "Profil"}</strong></>}</div><div className="topbar-actions"><span className="secure-label"><span className="status-dot" /> Espace sécurisé</span><button className="icon-button help-button" title="Aide"><CircleHelp size={18} /></button><button className="icon-button" title="Déconnexion" onClick={logout}><LogOut size={18} /></button></div></header>
        <div className="page-content">{error && <div className="toast error-toast">{error}<button onClick={() => setError("")}><X size={15} /></button></div>}{content()}</div>
      </main>
      {showOrgForm && <OrganizationModal onClose={() => setShowOrgForm(false)} onCreated={async (organizationId) => { await loadOrganizations(organizationId); setShowOrgForm(false); setNotice("Votre espace de travail a été créé"); }} />}
      {showUpload && activeOrg && <UploadModal organizationId={activeOrg.id} onClose={() => setShowUpload(false)} onUploaded={async () => { await refresh(); setShowUpload(false); setNotice("Document importé avec succès"); }} />}
      {editingDoc && <EditDocumentModal document={editingDoc} onClose={() => setEditingDoc(null)} onSaved={async () => { await refresh(); setEditingDoc(null); setNotice("Document mis à jour"); }} />}
      {shareDoc && activeOrg && <ShareModal document={shareDoc} organizationId={activeOrg.id} members={members} onClose={() => setShareDoc(null)} onSaved={async () => { await refresh(); setShareDoc(null); setNotice("Partages mis à jour"); }} />}
      {notice && <div className="toast success-toast"><Check size={16} />{notice}<button onClick={() => setNotice("")}><X size={15} /></button></div>}
    </div>
  );
}

function DocumentTable({ documents, onDownload, onShare, onEdit, onDelete }: {
  documents: DocumentItem[]; onDownload: (doc: DocumentItem) => void; onShare: (doc: DocumentItem) => void;
  onEdit: (doc: DocumentItem) => void; onDelete: (doc: DocumentItem) => void;
}) {
  return <div className="table-scroll"><table><thead><tr><th>DOCUMENT</th><th>PROPRIÉTAIRE</th><th>MODIFIÉ LE</th><th>TAILLE</th><th /></tr></thead><tbody>
    {documents.map((doc) => <tr key={doc.id}><td><div className="file-cell"><span className={`file-icon ${doc.content_type === "application/pdf" ? "pdf" : doc.content_type.startsWith("image/") ? "image" : "text"}`}><FileText size={18} /></span><div><strong>{doc.title}</strong><span>{doc.original_name}</span></div></div></td><td><span className="owner-cell">{doc.owner_name}{doc.permission !== "owner" && <em>{doc.permission === "edit" ? "Modification" : doc.permission === "read" ? "Lecture" : "Admin"}</em>}</span></td><td className="date-cell">{formatDate(doc.updated_at)}</td><td className="size-cell">{formatSize(doc.size)}</td><td><div className="row-actions"><button title="Télécharger" onClick={() => onDownload(doc)}><ArrowDownToLine size={16} /></button>{doc.permission !== "read" && <button title="Partager" onClick={() => onShare(doc)}><Share2 size={16} /></button>}{doc.permission !== "read" && <button title="Modifier les informations" onClick={() => onEdit(doc)}><Settings2 size={16} /></button>}{(doc.permission === "owner" || doc.permission === "admin") && <button title="Supprimer" onClick={() => onDelete(doc)}><Archive size={16} /></button>}</div></td></tr>)}
  </tbody></table></div>;
}

function EmptyDocuments({ onAdd }: { onAdd: () => void }) {
  return <div className="empty-state"><span className="empty-icon"><FolderClosed size={24} /></span><strong>Aucun document pour le moment</strong><span>Importez un premier fichier pour le retrouver ici.</span><button className="button secondary" onClick={onAdd}><Upload size={15} /> Importer un document</button></div>;
}

function OrganizationModal({ onClose, onCreated }: { onClose: () => void; onCreated: (organizationId: string) => void }) {
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault(); setBusy(true); setError("");
    try { const organization = await api<Organization>("/organizations", { method: "POST", body: JSON.stringify({ name: new FormData(event.currentTarget).get("name") }) }); await onCreated(organization.id); }
    catch (err) { setError((err as Error).message); } finally { setBusy(false); }
  };
  return <Modal title="Créer un espace de travail" onClose={onClose}><p className="modal-intro">Donnez un nom à l’espace de votre organisation. Vous en serez le propriétaire.</p><form onSubmit={submit}><label>Nom de l’organisation<input name="name" required minLength={2} maxLength={120} placeholder="Ex. Atelier Horizon" /></label>{error && <div className="form-error">{error}</div>}<div className="modal-actions"><button className="button secondary" type="button" onClick={onClose}>Annuler</button><button className="button primary" disabled={busy}>Créer l’espace</button></div></form></Modal>;
}

function UploadModal({ organizationId, onClose, onUploaded }: { organizationId: string; onClose: () => void; onUploaded: () => void }) {
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault(); setBusy(true); setError("");
    const data = new FormData(event.currentTarget);
    const file = data.get("file");
    if (!(file instanceof File) || !file.size) { setError("Choisissez un fichier à importer."); setBusy(false); return; }
    const body = new FormData();
    body.append("title", String(data.get("title") || ""));
    body.append("description", String(data.get("description") || ""));
    body.append("file", file);
    try { await api(`/organizations/${organizationId}/documents`, { method: "POST", body }); await onUploaded(); }
    catch (err) { setError((err as Error).message); } finally { setBusy(false); }
  };
  return <Modal title="Importer un document" onClose={onClose}><p className="modal-intro">Ajoutez un fichier à l’espace. Formats acceptés : PDF, TXT, PNG et JPEG (15 Mo max.).</p><form onSubmit={submit}><label>Titre<input name="title" maxLength={200} placeholder="Nom du document" /></label><label>Description <span className="optional">— facultatif</span><textarea name="description" rows={3} maxLength={4000} placeholder="Ajoutez quelques détails utiles…" /></label><label className="file-picker"><Upload size={19} /><span><strong>Choisir un fichier</strong><small>ou déposez-le ici · 15 Mo maximum</small></span><input type="file" name="file" accept=".pdf,.txt,.png,.jpg,.jpeg" required /></label>{error && <div className="form-error">{error}</div>}<div className="modal-actions"><button className="button secondary" type="button" onClick={onClose}>Annuler</button><button className="button primary" disabled={busy}><Upload size={15} /> Importer</button></div></form></Modal>;
}

function EditDocumentModal({ document, onClose, onSaved }: { document: DocumentItem; onClose: () => void; onSaved: () => void }) {
  const [error, setError] = useState("");
  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault(); setError("");
    const data = new FormData(event.currentTarget);
    try { await api(`/documents/${document.id}`, { method: "PATCH", body: JSON.stringify({ title: data.get("title"), description: data.get("description") }) }); await onSaved(); }
    catch (err) { setError((err as Error).message); }
  };
  return <Modal title="Informations du document" onClose={onClose}><p className="modal-intro">Modifiez le titre et la description visibles par les personnes autorisées.</p><form onSubmit={submit}><label>Titre<input name="title" defaultValue={document.title} required minLength={1} maxLength={200} /></label><label>Description<textarea name="description" defaultValue={document.description} rows={4} maxLength={4000} /></label>{error && <div className="form-error">{error}</div>}<div className="modal-actions"><button className="button secondary" type="button" onClick={onClose}>Annuler</button><button className="button primary">Enregistrer</button></div></form></Modal>;
}

function ShareModal({ document, organizationId, members, onClose, onSaved }: {
  document: DocumentItem; organizationId: string; members: Member[]; onClose: () => void; onSaved: () => void;
}) {
  const [shares, setShares] = useState<Share[]>([]);
  const [memberId, setMemberId] = useState("");
  const [permission, setPermission] = useState("read");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const load = useCallback(() => api<{ shares: Share[] }>(`/documents/${document.id}/shares`).then((result) => setShares(result.shares)), [document.id]);
  useEffect(() => { load().catch((err: Error) => setError(err.message)); }, [load]);
  const available = members.filter((member) => member.id !== document.owner_id && !shares.some((share) => share.user_id === member.id));
  const add = async (event: FormEvent) => {
    event.preventDefault(); if (!memberId) return;
    setBusy(true); setError("");
    try { await api(`/documents/${document.id}/shares`, { method: "PUT", body: JSON.stringify({ user_id: memberId, permission }) }); await load(); setMemberId(""); }
    catch (err) { setError((err as Error).message); } finally { setBusy(false); }
  };
  const change = async (id: string, value: string) => {
    try { await api(`/documents/${document.id}/shares`, { method: "PUT", body: JSON.stringify({ user_id: id, permission: value }) }); await load(); }
    catch (err) { setError((err as Error).message); }
  };
  const remove = async (id: string) => {
    try { await api(`/documents/${document.id}/shares/${id}`, { method: "DELETE" }); await load(); }
    catch (err) { setError((err as Error).message); }
  };
  return <Modal title="Gérer les accès" onClose={onClose}><p className="modal-intro">Partagez « {document.title} » avec un membre de votre organisation.</p>{shares.length > 0 && <div className="share-list">{shares.map((share) => <div className="share-row" key={share.user_id}><span className="member-avatar">{share.name.slice(0, 1).toUpperCase()}</span><span className="share-member"><strong>{share.name}</strong><small>{share.email}</small></span><select value={share.permission} onChange={(event) => change(share.user_id, event.target.value)}><option value="read">Lecture</option><option value="edit">Modification</option></select><button className="icon-button danger-icon" title="Retirer l’accès" onClick={() => remove(share.user_id)}><X size={16} /></button></div>)}</div>}{available.length ? <form className="share-add" onSubmit={add}><label>Membre<select value={memberId} onChange={(event) => setMemberId(event.target.value)} required><option value="">Choisir un membre…</option>{available.map((member) => <option key={member.id} value={member.id}>{member.name} · {member.email}</option>)}</select></label><label>Accès<select value={permission} onChange={(event) => setPermission(event.target.value)}><option value="read">Lecture</option><option value="edit">Modification</option></select></label><button className="button primary" disabled={busy || !memberId}><Plus size={15} /> Ajouter</button></form> : <div className="empty-inline">{members.length <= 1 ? "Invitez des membres pour pouvoir partager ce document." : "Tous les membres ont déjà accès à ce document."}</div>}{error && <div className="form-error">{error}</div>}<div className="modal-actions"><button className="button secondary" onClick={onClose}>Fermer</button><button className="button primary" onClick={onSaved}>Terminé</button></div></Modal>;
}

function MembersPage({ org, members, refresh, reloadOrganizations, setNotice, setError }: {
  org: Organization; members: Member[]; refresh: () => Promise<void>; reloadOrganizations: (preferredId?: string) => Promise<void>; setNotice: (value: string) => void; setError: (value: string) => void;
}) {
  const [inviteOpen, setInviteOpen] = useState(false);
  const [inviteResult, setInviteResult] = useState("");
  const [acceptToken, setAcceptToken] = useState("");
  const [busy, setBusy] = useState(false);
  const invite = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault(); setBusy(true); setError(""); setInviteResult("");
    const data = new FormData(event.currentTarget);
    try {
      const result = await api<{ token: string; email: string; expires_at: string }>(`/organizations/${org.id}/invitations`, { method: "POST", body: JSON.stringify({ email: data.get("email"), role: data.get("role") }) });
      setInviteResult(`Invitation pour ${result.email} créée. Lien à transmettre : ${window.location.origin}/?invitation=${result.token}`);
      setNotice("Invitation créée");
    } catch (err) { setError((err as Error).message); } finally { setBusy(false); }
  };
  const accept = async (event: FormEvent) => {
    event.preventDefault(); setError("");
    try { const result = await api<{ organization_id: string }>("/invitations/accept", { method: "POST", body: JSON.stringify({ token: acceptToken }) }); setAcceptToken(""); await reloadOrganizations(result.organization_id); setNotice("Vous avez rejoint l’organisation"); }
    catch (err) { setError((err as Error).message); }
  };
  const changeRole = async (member: Member, role: string) => {
    try { await api(`/organizations/${org.id}/members/${member.id}`, { method: "PATCH", body: JSON.stringify({ role }) }); await refresh(); setNotice("Rôle mis à jour"); }
    catch (err) { setError((err as Error).message); }
  };
  const removeMember = async (member: Member) => {
    if (!window.confirm(`Retirer ${member.name} de l’organisation ?`)) return;
    try { await api(`/organizations/${org.id}/members/${member.id}`, { method: "DELETE" }); await refresh(); setNotice("Membre retiré"); }
    catch (err) { setError((err as Error).message); }
  };
  return <>
    <div className="page-heading"><div><div className="eyebrow">VOTRE ÉQUIPE</div><h1>Membres</h1><p className="muted">Gérez les accès à l’espace {org.name}.</p></div>{org.role !== "member" && <button className="button primary" onClick={() => { setInviteOpen(true); setInviteResult(""); }}><Plus size={16} /> Inviter un membre</button>}</div>
    <section className="panel members-panel"><div className="panel-heading"><div><h2>Équipe de l’organisation</h2><p>{members.length} membre{members.length === 1 ? "" : "s"} · accès gérés par rôle</p></div><span className="member-total"><Users size={15} /> {members.length}</span></div><div className="member-list">{members.map((member) => <div className="member-row" key={member.id}><span className="member-avatar">{member.name.split(" ").map((part) => part[0]).slice(0, 2).join("").toUpperCase()}</span><span className="member-main"><strong>{member.name}</strong><small>{member.email}</small></span><span className={`role-pill ${member.role}`}>{member.role === "owner" ? "Propriétaire" : member.role === "admin" ? "Admin" : "Membre"}</span>{org.role === "owner" && member.role !== "owner" ? <select className="role-select" value={member.role} onChange={(e) => changeRole(member, e.target.value)}><option value="member">Membre</option><option value="admin">Admin</option></select> : org.role === "admin" && member.role === "member" ? <select className="role-select" value={member.role} onChange={(e) => changeRole(member, e.target.value)}><option value="member">Membre</option><option value="admin" disabled>Admin</option></select> : <span className="role-fixed">{member.role === "owner" ? "Propriétaire" : member.role === "admin" ? "Administrateur" : "Collaborateur"}</span>}{org.role !== "member" && member.role !== "owner" && (org.role === "owner" || member.role === "member") && <button className="icon-button danger-icon" title="Retirer ce membre" onClick={() => removeMember(member)}><X size={16} /></button>}</div>)}</div></section>
    <section className="invite-accept panel"><div><span className="invite-icon"><Share2 size={17} /></span><div><strong>Vous avez reçu une invitation ?</strong><p>Collez le code d’invitation fourni par votre organisation.</p></div></div><form onSubmit={accept}><input value={acceptToken} onChange={(e) => setAcceptToken(e.target.value)} placeholder="Code d’invitation" minLength={32} required /><button className="button secondary" disabled={busy}>Rejoindre</button></form></section>
    {inviteOpen && <Modal title="Inviter un membre" onClose={() => setInviteOpen(false)}><p className="modal-intro">L’invitation est valable 7 jours. Partagez le lien généré avec la personne invitée.</p><form onSubmit={invite}><label>Adresse e-mail<input name="email" type="email" required /></label><label>Rôle<select name="role" defaultValue="member"><option value="member">Membre</option>{org.role === "owner" && <option value="admin">Administrateur</option>}</select></label>{inviteResult && <div className="invite-result"><Check size={16} /><span>{inviteResult}</span></div>}<div className="modal-actions"><button className="button secondary" type="button" onClick={() => setInviteOpen(false)}>Fermer</button><button className="button primary" disabled={busy}>Créer l’invitation</button></div></form></Modal>}
  </>;
}

function ProfilePage({ user, setUser, setNotice, setError }: {
  user: User; setUser: (user: User) => void; setNotice: (value: string) => void; setError: (value: string) => void;
}) {
  const saveProfile = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault(); setError("");
    try { const result = await api<{ user: User }>("/users/me", { method: "PATCH", body: JSON.stringify({ name: new FormData(event.currentTarget).get("name") }) }); setUser(result.user); setNotice("Profil mis à jour"); }
    catch (err) { setError((err as Error).message); }
  };
  const savePassword = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault(); setError("");
    const form = event.currentTarget;
    const data = new FormData(event.currentTarget);
    if (data.get("new_password") !== data.get("confirm_password")) { setError("Les nouveaux mots de passe ne correspondent pas."); return; }
    try { await api("/users/me/password", { method: "POST", body: JSON.stringify({ current_password: data.get("current_password"), new_password: data.get("new_password") }) }); form.reset(); setNotice("Mot de passe modifié"); }
    catch (err) { setError((err as Error).message); }
  };
  return <>
    <div className="page-heading"><div><div className="eyebrow">VOTRE COMPTE</div><h1>Profil et préférences</h1><p className="muted">Gérez vos informations personnelles et votre sécurité.</p></div></div>
    <div className="profile-grid">
      <section className="panel profile-card"><div className="panel-heading"><div><h2>Informations personnelles</h2><p>Ces informations sont visibles par les membres de votre espace.</p></div></div><div className="profile-summary"><span className="profile-avatar">{user.name.split(" ").map((part) => part[0]).slice(0, 2).join("").toUpperCase()}</span><div><strong>{user.name}</strong><span>{user.email}</span></div><span className="verified"><Check size={14} /> Compte actif</span></div><form onSubmit={saveProfile}><label>Nom complet<input name="name" defaultValue={user.name} required minLength={1} maxLength={120} /></label><label>Adresse e-mail<input value={user.email} disabled /></label><div className="form-footer"><button className="button primary">Enregistrer les modifications</button></div></form></section>
      <section className="panel profile-card"><div className="panel-heading"><div><h2>Sécurité du compte</h2><p>Choisissez un mot de passe robuste d’au moins 12 caractères.</p></div></div><form onSubmit={savePassword}><label>Mot de passe actuel<input name="current_password" type="password" autoComplete="current-password" required /></label><label>Nouveau mot de passe<input name="new_password" type="password" autoComplete="new-password" minLength={12} required /></label><label>Confirmer le mot de passe<input name="confirm_password" type="password" autoComplete="new-password" minLength={12} required /></label><div className="form-footer"><button className="button primary">Modifier le mot de passe</button></div></form></section>
    </div>
  </>;
}

function Modal({ title, children, onClose }: { title: string; children: React.ReactNode; onClose: () => void }) {
  useEffect(() => {
    const keydown = (event: KeyboardEvent) => { if (event.key === "Escape") onClose(); };
    window.addEventListener("keydown", keydown);
    return () => window.removeEventListener("keydown", keydown);
  }, [onClose]);
  return <div className="modal-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}><section className="modal"><header className="modal-header"><h2>{title}</h2><button className="icon-button" onClick={onClose}><X size={18} /></button></header>{children}</section></div>;
}

export default App;
