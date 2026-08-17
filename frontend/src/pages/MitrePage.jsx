import { useState, useEffect, useCallback, useMemo } from "react";
import { Link } from "react-router-dom";
import { Target, RefreshCw, AlertTriangle, Loader2 } from "lucide-react";
import { useAuth } from "../contexts/AuthContext";
import { createFetchWithAuth } from "../lib/api";

const capitalize = (s) => (s ? s.charAt(0).toUpperCase() + s.slice(1) : s);

export default function MitrePage() {
  const { jwtToken } = useAuth();
  const [coverage, setCoverage] = useState(null); // null = loading
  const [error, setError] = useState(false);

  const api = useMemo(
    () =>
      createFetchWithAuth(
        () => jwtToken,
        () => {
          localStorage.removeItem("auth_token");
          localStorage.removeItem("auth_username");
          window.location.reload();
        },
      ),
    [jwtToken],
  );

  const loadCoverage = useCallback(async () => {
    setError(false);
    setCoverage(null);
    try {
      const res = await api("/api/rules/coverage", { silent: true });
      if (res.ok) {
        setCoverage(await res.json());
      } else {
        setError(true);
      }
    } catch {
      setError(true);
    }
  }, [api]);

  useEffect(() => {
    loadCoverage();
  }, [loadCoverage]);

  const tactics = coverage?.tactics || {};
  const tacticEntries = Object.entries(tactics);

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Target className="text-emerald-400" /> Matrice MITRE ATT&CK
          </h1>
          <p className="text-gray-400 text-sm">
            Couverture des règles de corrélation par tactique et technique
          </p>
        </div>
        <button
          onClick={loadCoverage}
          className="flex items-center gap-2 bg-gray-800 hover:bg-gray-700 px-4 py-2 rounded-lg text-sm"
        >
          <RefreshCw size={16} /> Actualiser
        </button>
      </div>

      {/* Loading */}
      {coverage === null && !error && (
        <div className="flex items-center justify-center py-16 text-gray-400">
          <Loader2 size={20} className="animate-spin mr-2" /> Chargement…
        </div>
      )}

      {/* Error */}
      {error && (
        <div className="flex items-center justify-between bg-red-900/30 border border-red-700 rounded-lg px-4 py-3 text-red-300">
          <span className="flex items-center gap-2">
            <AlertTriangle size={16} /> Impossible de charger la couverture MITRE ATT&CK
          </span>
          <button onClick={loadCoverage} className="text-sm underline hover:text-white">
            Réessayer
          </button>
        </div>
      )}

      {/* Empty */}
      {coverage !== null && !error && tacticEntries.length === 0 && (
        <div className="bg-gray-900 border border-gray-800 rounded-lg px-4 py-12 text-center text-gray-500">
          Aucune règle taguée MITRE
          <div className="mt-3">
            <Link to="/rules" className="text-emerald-400 hover:text-emerald-300 text-sm underline">
              Voir les règles de corrélation
            </Link>
          </div>
        </div>
      )}

      {/* Data */}
      {coverage !== null && !error && tacticEntries.length > 0 && (
        <div className="overflow-x-auto">
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4 min-w-[320px]">
            {tacticEntries.map(([tacticKey, tactic]) => (
              <div key={tacticKey} className="bg-gray-900 border border-gray-800 rounded-lg p-4">
                <div className="flex items-center justify-between mb-3">
                  <h2 className="font-semibold text-emerald-400">{capitalize(tacticKey)}</h2>
                  <span className="text-xs text-gray-400">
                    {tactic.total_rules} règle{tactic.total_rules > 1 ? "s" : ""}
                  </span>
                </div>
                <div className="space-y-2">
                  {Object.entries(tactic.techniques || {}).map(([techId, tech]) => (
                    <div key={techId} className="flex items-center justify-between bg-gray-800/50 rounded px-3 py-2 text-sm">
                      <div className="min-w-0">
                        <div className="text-gray-300 truncate">{tech.name}</div>
                        <div className="text-xs text-gray-500 font-mono">{techId}</div>
                      </div>
                      <span className="ml-3 flex-shrink-0 bg-emerald-900/40 text-emerald-300 text-xs px-2 py-0.5 rounded">
                        {tech.rule_count}
                      </span>
                    </div>
                  ))}
                  {Object.keys(tactic.techniques || {}).length === 0 && (
                    <div className="text-sm text-gray-500">Aucune technique</div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}