// src/views/DatabaseView.jsx
// Base de données — table browser with stats + CRUD.
import { useCallback, useEffect, useState } from "react";
import {
  Database,
  Server,
  Activity,
  Users,
  Clock,
  BarChart3,
  Table,
  CheckCircle2,
  AlertTriangle,
  Loader2,
  Search,
  X,
  KeyRound,
  Trash2,
} from "lucide-react";
import { apiFetch, getToken } from "../api";

export default function DatabaseView() {
  const [stats, setStats] = useState(null);
  const [tables, setTables] = useState([]);
  const [selectedTable, setSelectedTable] = useState(null);
  const [columns, setColumns] = useState([]);
  const [rows, setRows] = useState([]);
  const [total, setTotal] = useState(0);
  const [totalPages, setTotalPages] = useState(1);
  const [page, setPage] = useState(1);
  const [pageSize] = useState(50);
  const [search, setSearch] = useState("");
  const [sortBy, setSortBy] = useState(null);
  const [sortDir, setSortDir] = useState("desc");
  const [loading, setLoading] = useState(false);
  const [tablesLoading, setTablesLoading] = useState(true);

  // Edit state
  const [editingCell, setEditingCell] = useState(null); // { rowIndex, colName }
  const [editValue, setEditValue] = useState("");
  const [saveStatus, setSaveStatus] = useState(null); // { type: 'success'|'error', msg: '' }

  // Insert state
  const [showInsert, setShowInsert] = useState(false);
  const [insertData, setInsertData] = useState({});

  // Delete confirmation
  const [deletingRow, setDeletingRow] = useState(null);

  // View toggle: tables | stats
  const [viewMode, setViewMode] = useState("tables");

  // ── Create table state ──
  const [showCreateTable, setShowCreateTable] = useState(false);
  const [createTableName, setCreateTableName] = useState("");
  const [createColumns, setCreateColumns] = useState([
    { name: "", type: "text", nullable: true, primary_key: false, default: "" },
  ]);
  const [createLoading, setCreateLoading] = useState(false);

  // ── Drop table state ──
  const [droppingTable, setDroppingTable] = useState(null);

  // Fetch global stats
  useEffect(() => {
    if (!getToken()) return;
    apiFetch("/api/admin/database/stats")
      .then((r) => r.json())
      .then((d) => { setStats(d); setTables(d.tables || []); })
      .catch(() => {})
      .finally(() => setTablesLoading(false));
  }, []);

  // Auto-dismiss save status
  useEffect(() => {
    if (saveStatus) {
      const t = setTimeout(() => setSaveStatus(null), 3000);
      return () => clearTimeout(t);
    }
  }, [saveStatus]);

  // Fetch columns + rows when table changes
  const loadTable = useCallback(async (tableName, p, s, sb, sd) => {
    if (!getToken()) return;
    setLoading(true);
    try {
      const [colsRes, rowsRes] = await Promise.all([
        apiFetch(`/api/admin/database/tables/${tableName}/columns`),
        apiFetch(`/api/admin/database/tables/${tableName}/rows?page=${p}&page_size=${pageSize}${s ? `&search=${encodeURIComponent(s)}` : ""}${sb ? `&sort_by=${encodeURIComponent(sb)}&sort_dir=${sd}` : ""}`),
      ]);
      if (colsRes.ok) setColumns(await colsRes.json());
      if (rowsRes.ok) {
        const data = await rowsRes.json();
        setRows(data.rows || []);
        setTotal(data.total || 0);
        setTotalPages(data.total_pages || 1);
      }
    } catch (e) { /* ignore */ }
    setLoading(false);
  }, [pageSize]);

  useEffect(() => {
    if (selectedTable) loadTable(selectedTable, page, search, sortBy, sortDir);
  }, [selectedTable, page, search, sortBy, sortDir, loadTable]);

  const handleSearch = (e) => {
    e.preventDefault();
    setPage(1);
    if (selectedTable) loadTable(selectedTable, 1, search, sortBy, sortDir);
  };

  const handleSort = (col) => {
    if (sortBy === col) {
      setSortDir((d) => d === "asc" ? "desc" : "asc");
    } else {
      setSortBy(col);
      setSortDir("desc");
    }
    setPage(1);
  };

  // ── Inline cell editing ──
  const startEdit = (rowIndex, colName, currentValue) => {
    setEditingCell({ rowIndex, colName });
    setEditValue(currentValue === null ? "" : String(currentValue));
  };

  const cancelEdit = () => {
    setEditingCell(null);
    setEditValue("");
  };

  const saveEdit = async (rowIndex, colName) => {
    const pkCol = columns.find((c) => c.primary_key);
    if (!pkCol) { cancelEdit(); return; }
    const rowId = rows[rowIndex][pkCol.name];
    if (rowId === undefined) { cancelEdit(); return; }

    // Convert value back to proper type
    let newVal = editValue;
    const colMeta = columns.find((c) => c.name === colName);
    if (colMeta) {
      const t = colMeta.type.toUpperCase();
      if (t === "INTEGER" || t === "BIGINT" || t === "SMALLINT") {
        newVal = editValue === "" ? null : parseInt(editValue, 10);
      } else if (t === "FLOAT" || t === "DOUBLE PRECISION" || t === "NUMERIC" || t === "REAL") {
        newVal = editValue === "" ? null : parseFloat(editValue);
      } else if (t === "BOOLEAN") {
        newVal = editValue === "true";
      } else if (editValue === "") {
        newVal = null;
      }
    }

    try {
      const res = await apiFetch(`/api/admin/database/tables/${selectedTable}/rows/${rowId}`, {
        method: "PUT",
        body: JSON.stringify({ data: { [colName]: newVal } }),
      });
      if (!res.ok) {
        const d = await res.json().catch(() => ({}));
        throw new Error(d.detail || "Update failed");
      }
      // Update local row
      setRows((prev) => {
        const next = [...prev];
        next[rowIndex] = { ...next[rowIndex], [colName]: newVal };
        return next;
      });
      setSaveStatus({ type: "success", msg: `${colName} mis à jour` });
    } catch (err) {
      setSaveStatus({ type: "error", msg: err.message });
    }
    cancelEdit();
  };

  // ── Delete row ──
  const handleDelete = async (rowIndex) => {
    const pkCol = columns.find((c) => c.primary_key);
    if (!pkCol) return;
    const rowId = rows[rowIndex][pkCol.name];
    try {
      const res = await apiFetch(`/api/admin/database/tables/${selectedTable}/rows/${rowId}`, {
        method: "DELETE",
      });
      if (!res.ok) {
        const d = await res.json().catch(() => ({}));
        throw new Error(d.detail || "Delete failed");
      }
      setSaveStatus({ type: "success", msg: `Ligne #${rowId} supprimée` });
      setDeletingRow(null);
      loadTable(selectedTable, page, search, sortBy, sortDir);
      // Refresh stats
      apiFetch("/api/admin/database/stats").then((r) => r.json()).then(setStats).catch(() => {});
    } catch (err) {
      setSaveStatus({ type: "error", msg: err.message });
    }
  };

  // ── Insert row ──
  const handleInsert = async (e) => {
    e.preventDefault();
    try {
      const res = await apiFetch(`/api/admin/database/tables/${selectedTable}/rows`, {
        method: "POST",
        body: JSON.stringify({ data: insertData }),
      });
      if (!res.ok) {
        const d = await res.json().catch(() => ({}));
        throw new Error(d.detail || "Insert failed");
      }
      setSaveStatus({ type: "success", msg: "Ligne insérée" });
      setShowInsert(false);
      setInsertData({});
      setPage(1);
      loadTable(selectedTable, 1, search, sortBy, sortDir);
      apiFetch("/api/admin/database/stats").then((r) => r.json()).then(setStats).catch(() => {});
    } catch (err) {
      setSaveStatus({ type: "error", msg: err.message });
    }
  };

  // ── Create table ──
  const addCreateColumn = () => {
    setCreateColumns((prev) => [...prev, { name: "", type: "text", nullable: true, primary_key: false, default: "" }]);
  };
  const removeCreateColumn = (idx) => {
    setCreateColumns((prev) => prev.filter((_, i) => i !== idx));
  };
  const updateCreateColumn = (idx, field, value) => {
    setCreateColumns((prev) => prev.map((c, i) => i === idx ? { ...c, [field]: value } : c));
  };

  const handleCreateTable = async (e) => {
    e.preventDefault();
    setCreateLoading(true);
    try {
      const validCols = createColumns.filter((c) => c.name.trim());
      if (!createTableName.trim()) throw new Error("Nom de table requis");
      if (validCols.length === 0) throw new Error("Au moins une colonne requise");

      const res = await apiFetch("/api/admin/database/tables", {
        method: "POST",
        body: JSON.stringify({
          table_name: createTableName.trim(),
          columns: validCols.map((c) => ({
            name: c.name.trim(),
            type: c.type.trim(),
            nullable: c.nullable,
            primary_key: c.primary_key,
            default: c.default.trim() || null,
          })),
        }),
      });
      if (!res.ok) {
        const d = await res.json().catch(() => ({}));
        throw new Error(d.detail || "Création échouée");
      }
      setSaveStatus({ type: "success", msg: `Table "${createTableName}" créée` });
      setShowCreateTable(false);
      setCreateTableName("");
      setCreateColumns([{ name: "", type: "text", nullable: true, primary_key: false, default: "" }]);
      // Refresh table list + stats
      apiFetch("/api/admin/database/stats")
        .then((r) => r.json())
        .then((d) => { setStats(d); setTables(d.tables || []); })
        .catch(() => {});
    } catch (err) {
      setSaveStatus({ type: "error", msg: err.message });
    }
    setCreateLoading(false);
  };

  // ── Drop table ──
  const handleDropTable = async (tableName) => {
    try {
      const res = await apiFetch(`/api/admin/database/tables/${tableName}`, {
        method: "DELETE",
      });
      if (!res.ok) {
        const d = await res.json().catch(() => ({}));
        throw new Error(d.detail || "Suppression échouée");
      }
      setSaveStatus({ type: "success", msg: `Table "${tableName}" supprimée` });
      setDroppingTable(null);
      if (selectedTable === tableName) {
        setSelectedTable(null);
        setColumns([]);
        setRows([]);
      }
      apiFetch("/api/admin/database/stats")
        .then((r) => r.json())
        .then((d) => { setStats(d); setTables(d.tables || []); })
        .catch(() => {});
    } catch (err) {
      setSaveStatus({ type: "error", msg: err.message });
      setDroppingTable(null);
    }
  };

  const formatValue = (val) => {
    if (val === null || val === undefined) return <span className="db-cell-null">NULL</span>;
    if (typeof val === "boolean") return val ? <span className="db-cell-bool-true">true</span> : <span className="db-cell-bool-false">false</span>;
    const s = String(val);
    if (s.length > 80) return s.substring(0, 80) + "…";
    return s;
  };

  const pkCol = columns.find((c) => c.primary_key);

  return (
    <div className="admin-tab">
      <div className="admin-page-header">
        <h2><Database size={20} /> Base de données</h2>
        <div className="admin-page-header-actions">
          {saveStatus && (
            <span className={`db-save-status ${saveStatus.type}`}>
              {saveStatus.type === "success" ? <CheckCircle2 size={12} /> : <AlertTriangle size={12} />}
              {saveStatus.msg}
            </span>
          )}
          <button className="db-action-btn db-insert-btn" onClick={() => setShowCreateTable(!showCreateTable)}>
            <Database size={13} /> {showCreateTable ? "Fermer" : "Créer table"}
          </button>
          <div className="db-view-toggle">
            <button className={`admin-toggle-btn ${viewMode === "tables" ? "active" : ""}`} onClick={() => setViewMode("tables")}>
              <Database size={13} /> Tables
            </button>
            <button className={`admin-toggle-btn ${viewMode === "stats" ? "active" : ""}`} onClick={() => setViewMode("stats")}>
              <BarChart3 size={13} /> Statistiques
            </button>
          </div>
        </div>
      </div>

      {/* ═══ Global Stats Banner ═══ */}
      {stats && (
        <div className="db-stats-banner">
          <div className="db-stat-pill"><Server size={13} color="#60a5fa" /><span>{stats.database_name}</span><label>Nom</label></div>
          <div className="db-stat-pill"><Database size={13} color="#a855f7" /><span>{stats.database_size_human}</span><label>Taille</label></div>
          <div className="db-stat-pill"><Activity size={13} color="#34d399" /><span>{stats.connections.active}</span><label>Actives</label></div>
          <div className="db-stat-pill"><Clock size={13} color="#fbbf24" /><span>{stats.connections.idle}</span><label>Idle</label></div>
          <div className="db-stat-pill"><Users size={13} color="#60a5fa" /><span>{stats.connections.total}/{stats.max_connections}</span><label>Connexions</label></div>
          <div className="db-stat-pill"><BarChart3 size={13} color="#f87171" /><span>{stats.total_rows.toLocaleString()}</span><label>Total lignes</label></div>
          <div className="db-stat-pill"><Table size={13} color="#a855f7" /><span>{stats.total_tables}</span><label>Tables</label></div>
        </div>
      )}

      {/* ═══ Create Table Form ═══ */}
      {showCreateTable && (
        <div className="db-create-table-form">
          <h4><Database size={14} /> Nouvelle table</h4>
          <form onSubmit={handleCreateTable}>
            <div className="db-create-table-name">
              <label>Nom de la table</label>
              <input
                type="text"
                value={createTableName}
                onChange={(e) => setCreateTableName(e.target.value)}
                placeholder="ma_nouvelle_table"
                autoFocus
              />
            </div>

            <div className="db-create-columns">
              <label>Colonnes</label>
              {createColumns.map((col, idx) => (
                <div key={idx} className="db-create-col-row">
                  <input
                    type="text"
                    value={col.name}
                    onChange={(e) => updateCreateColumn(idx, "name", e.target.value)}
                    placeholder="nom_colonne"
                    className="db-create-col-name"
                  />
                  <select
                    value={col.type}
                    onChange={(e) => updateCreateColumn(idx, "type", e.target.value)}
                    className="db-create-col-type"
                  >
                    <option value="integer">INTEGER</option>
                    <option value="bigint">BIGINT</option>
                    <option value="smallint">SMALLINT</option>
                    <option value="real">REAL</option>
                    <option value="double precision">DOUBLE PRECISION</option>
                    <option value="numeric">NUMERIC</option>
                    <option value="boolean">BOOLEAN</option>
                    <option value="character varying(255)">VARCHAR(255)</option>
                    <option value="text">TEXT</option>
                    <option value="timestamp with time zone">TIMESTAMPTZ</option>
                    <option value="timestamp without time zone">TIMESTAMP</option>
                    <option value="date">DATE</option>
                    <option value="jsonb">JSONB</option>
                    <option value="json">JSON</option>
                    <option value="uuid">UUID</option>
                  </select>
                  <label className="db-create-col-check" title="Nullable">
                    <input
                      type="checkbox"
                      checked={col.nullable}
                      onChange={(e) => updateCreateColumn(idx, "nullable", e.target.checked)}
                    />
                    Nul
                  </label>
                  <label className="db-create-col-check" title="Primary Key">
                    <input
                      type="checkbox"
                      checked={col.primary_key}
                      onChange={(e) => updateCreateColumn(idx, "primary_key", e.target.checked)}
                    />
                    PK
                  </label>
                  <input
                    type="text"
                    value={col.default}
                    onChange={(e) => updateCreateColumn(idx, "default", e.target.value)}
                    placeholder="défaut (opt.)"
                    className="db-create-col-default"
                  />
                  {createColumns.length > 1 && (
                    <button type="button" className="db-row-delete" onClick={() => removeCreateColumn(idx)}>
                      <Trash2 size={11} />
                    </button>
                  )}
                </div>
              ))}
              <button type="button" className="db-action-btn admin-btn-mt-sm" onClick={addCreateColumn}>
                + Ajouter colonne
              </button>
            </div>

            <div className="db-create-actions">
              <button type="submit" className="admin-login-btn admin-btn-compact" disabled={createLoading}>
                {createLoading ? <><Loader2 size={13} className="admin-spin" /> Création...</> : <><Database size={13} /> Créer</>}
              </button>
              <button type="button" className="db-action-btn" onClick={() => setShowCreateTable(false)}>Annuler</button>
            </div>
          </form>
        </div>
      )}

      {/* ═══ View: Tables ═══ */}
      {viewMode === "tables" && (
        <>
          {/* ── Table cards ── */}
          {tablesLoading ? (
            <div className="admin-section-card"><div className="admin-empty"><Loader2 size={18} className="admin-spin" /> Chargement...</div></div>
          ) : (
            <div className="db-tables-grid">
              {tables.map((t) => (
                <div
                  key={t.name}
                  className={`db-table-card ${selectedTable === t.name ? "selected" : ""}`}
                  onClick={() => { setSelectedTable(t.name); setPage(1); setSearch(""); setSortBy(null); setShowInsert(false); }}
                >
                  <div className="db-table-card-icon"><Database size={16} /></div>
                  <div className="db-table-card-info">
                    <span className="db-table-card-name">{t.name}</span>
                    <span className="db-table-card-meta">{t.row_count.toLocaleString()} lignes · {t.column_count} cols · {t.total_size_human}</span>
                  </div>
                  <div className="db-table-card-actions" onClick={(e) => e.stopPropagation()}>
                    {droppingTable === t.name ? (
                      <div className="db-delete-confirm">
                        <span>Supprimer "{t.name}" ?</span>
                        <button className="db-edit-save" onClick={() => handleDropTable(t.name)}><CheckCircle2 size={11} /></button>
                        <button className="db-edit-cancel" onClick={() => setDroppingTable(null)}><X size={11} /></button>
                      </div>
                    ) : (
                      <button className="db-row-delete" onClick={() => setDroppingTable(t.name)} title="Supprimer cette table">
                        <Trash2 size={12} />
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* ── Data viewer ── */}
          {selectedTable && (
            <div className="db-viewer">
              <div className="db-viewer-header">
                <h3><Database size={14} /> {selectedTable}</h3>
                <div className="db-viewer-controls">
                  <span className="db-total-badge">{total.toLocaleString()} résultats</span>
                  <button className="db-action-btn db-insert-btn" onClick={() => { setShowInsert(!showInsert); setInsertData({}); }}>
                    <CheckCircle2 size={13} /> Insérer
                  </button>
                  <form className="db-search-form" onSubmit={handleSearch}>
                    <input type="text" value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Rechercher..." className="db-search-input" />
                    <button type="submit" className="db-search-btn"><Search size={14} /></button>
                    {search && <button type="button" className="db-search-clear" onClick={() => { setSearch(""); setPage(1); }}><X size={14} /></button>}
                  </form>
                </div>
              </div>

              {/* Column labels */}
              <div className="db-column-chips">
                {columns.map((c) => (
                  <span key={c.name} className={`db-col-chip ${c.primary_key ? "pk" : ""}`}>
                    {c.primary_key && <KeyRound size={10} />}
                    {c.name}
                    <span className="db-col-type">{c.type}</span>
                  </span>
                ))}
              </div>

              {/* Insert form */}
              {showInsert && (
                <form className="db-insert-form" onSubmit={handleInsert}>
                  <h4><CheckCircle2 size={14} /> Nouvelle ligne</h4>
                  <div className="db-insert-fields">
                    {columns.map((c) => (
                      <div key={c.name} className="db-insert-field">
                        <label>{c.name} {c.primary_key && <span className="db-col-type">(auto)</span>}</label>
                        <input
                          type="text"
                          disabled={c.primary_key}
                          value={insertData[c.name] ?? ""}
                          onChange={(e) => setInsertData((prev) => ({ ...prev, [c.name]: e.target.value }))}
                          placeholder={c.type}
                        />
                      </div>
                    ))}
                  </div>
                  <div className="db-insert-actions">
                    <button type="submit" className="admin-login-btn admin-btn-compact">Enregistrer</button>
                    <button type="button" className="db-action-btn" onClick={() => setShowInsert(false)}>Annuler</button>
                  </div>
                </form>
              )}

              {/* Data table */}
              <div className="db-table-wrap">
                {loading ? (
                  <div className="admin-empty"><Loader2 size={18} className="admin-spin" /> Chargement...</div>
                ) : rows.length === 0 ? (
                  <div className="admin-empty">Aucune donnée</div>
                ) : (
                  <table className="admin-table db-data-table">
                    <thead>
                      <tr>
                        {columns.map((c) => (
                          <th key={c.name} onClick={() => handleSort(c.name)} className={sortBy === c.name ? "sorted" : ""}>
                            {c.name}
                            {sortBy === c.name && <span className="db-sort-arrow">{sortDir === "asc" ? " ▲" : " ▼"}</span>}
                          </th>
                        ))}
                        <th className="db-actions-col">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {rows.map((row, ri) => (
                        <tr key={ri}>
                          {columns.map((c) => {
                            const isEditing = editingCell?.rowIndex === ri && editingCell?.colName === c.name;
                            return (
                              <td key={c.name} className={`db-cell ${isEditing ? "editing" : ""}`}
                                onDoubleClick={() => !c.primary_key && startEdit(ri, c.name, row[c.name])}
                                title={String(row[c.name] ?? "")}>
                                {isEditing ? (
                                  <div className="db-edit-box">
                                    <input
                                      autoFocus
                                      value={editValue}
                                      onChange={(e) => setEditValue(e.target.value)}
                                      onKeyDown={(e) => {
                                        if (e.key === "Enter") saveEdit(ri, c.name);
                                        if (e.key === "Escape") cancelEdit();
                                      }}
                                    />
                                    <div className="db-edit-actions">
                                      <button className="db-edit-save" onClick={() => saveEdit(ri, c.name)}><CheckCircle2 size={11} /></button>
                                      <button className="db-edit-cancel" onClick={cancelEdit}><X size={11} /></button>
                                    </div>
                                  </div>
                                ) : (
                                  formatValue(row[c.name])
                                )}
                              </td>
                            );
                          })}
                          <td className="db-actions-cell">
                            {deletingRow === ri ? (
                              <div className="db-delete-confirm">
                                <span>Supprimer?</span>
                                <button className="db-edit-save" onClick={() => handleDelete(ri)}><CheckCircle2 size={11} /></button>
                                <button className="db-edit-cancel" onClick={() => setDeletingRow(null)}><X size={11} /></button>
                              </div>
                            ) : (
                              <button className="db-row-delete" onClick={() => setDeletingRow(ri)} title="Supprimer cette ligne">
                                <Trash2 size={12} />
                              </button>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>

              {/* Pagination */}
              {totalPages > 1 && (
                <div className="db-pagination">
                  <button disabled={page <= 1} onClick={() => setPage((p) => Math.max(1, p - 1))}>← Préc</button>
                  <span className="db-page-info">Page {page} / {totalPages}</span>
                  <button disabled={page >= totalPages} onClick={() => setPage((p) => Math.min(totalPages, p + 1))}>Suiv →</button>
                </div>
              )}
            </div>
          )}
        </>
      )}

      {/* ═══ View: Stats ═══ */}
      {viewMode === "stats" && stats && (
        <div className="db-stats-view">
          <div className="admin-section-card">
            <h3><Server size={16} /> Informations</h3>
            <div className="db-info-grid">
              <div className="db-info-item"><span className="db-info-label">Base de données</span><span className="db-info-value">{stats.database_name}</span></div>
              <div className="db-info-item"><span className="db-info-label">PostgreSQL</span><span className="db-info-value">{stats.postgres_version?.split(",")[0]}</span></div>
              <div className="db-info-item"><span className="db-info-label">Taille totale</span><span className="db-info-value">{stats.database_size_human}</span></div>
              <div className="db-info-item"><span className="db-info-label">Tables</span><span className="db-info-value">{stats.total_tables}</span></div>
              <div className="db-info-item"><span className="db-info-label">Lignes totales</span><span className="db-info-value">{stats.total_rows.toLocaleString()}</span></div>
              <div className="db-info-item"><span className="db-info-label">Requêtes lentes</span><span className="db-info-value">{stats.slow_queries}</span></div>
              <div className="db-info-item"><span className="db-info-label">Connexions</span><span className="db-info-value">{stats.connections.total} / {stats.max_connections}</span></div>
              <div className="db-info-item"><span className="db-info-label">Actives / Idle</span><span className="db-info-value">{stats.connections.active} / {stats.connections.idle}</span></div>
            </div>
          </div>

          <div className="admin-section-card admin-section-mt">
            <h3><BarChart3 size={16} /> Détails par table</h3>
            <div className="db-table-wrap db-table-wrap-tall">
              <table className="admin-table db-stats-table">
                <thead>
                  <tr>
                    <th>Table</th>
                    <th>Lignes</th>
                    <th>Taille totale</th>
                    <th>Données</th>
                    <th>Index</th>
                    <th>Seq Scans</th>
                    <th>Idx Scans</th>
                    <th>Ins</th>
                    <th>Upd</th>
                    <th>Del</th>
                    <th>Mortes</th>
                    <th>Dernier vacuum</th>
                  </tr>
                </thead>
                <tbody>
                  {stats.tables.map((t) => (
                    <tr key={t.name}>
                      <td className="db-cell-name">{t.name}</td>
                      <td>{t.row_count.toLocaleString()}</td>
                      <td>{t.total_size_human}</td>
                      <td>{t.data_size_human}</td>
                      <td>{t.index_size_human}</td>
                      <td>{t.seq_scans.toLocaleString()}</td>
                      <td>{t.idx_scans.toLocaleString()}</td>
                      <td>{t.inserts.toLocaleString()}</td>
                      <td>{t.updates.toLocaleString()}</td>
                      <td>{t.deletes.toLocaleString()}</td>
                      <td>{t.dead_tuples > 0 ? <span className="db-cell-bool-false">{t.dead_tuples.toLocaleString()}</span> : "0"}</td>
                      <td className="db-cell-mono">{t.last_autovacuum || t.last_vacuum || "jamais"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}