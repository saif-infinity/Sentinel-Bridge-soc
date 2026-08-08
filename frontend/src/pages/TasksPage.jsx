import { Clock } from "lucide-react";
import { useData } from "../contexts/DataContext";
import { useTranslation } from "../i18n";

export default function TasksPage() {
  const { pendingTasks } = useData();
  const { lang } = useTranslation();

  return (
    <div className="tab-pane animate-fade-in">
      <div className="section-card">
        <div className="section-header">
          <h2>
            <Clock size={18} /> {lang === "fr" ? "Historique des Taches Background" : "Background Jobs History"}
          </h2>
        </div>

        {pendingTasks.length === 0 ? (
          <div style={{ textAlign: "center", padding: "40px", color: "var(--text-muted)" }}>
            {lang === "fr" ? "Aucune tache enregistree." : "No tasks recorded."}
          </div>
        ) : (
          <div className="job-list">
            {pendingTasks.map((task, idx) => (
              <div key={idx} className="job-card">
                <div className="job-info">
                  <h4>{task.type} - {task.target}</h4>
                  <span>ID: {task.id.substring(0, 16)}... | Start: {task.startTime.toLocaleTimeString()}</span>
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: "20px" }}>
                  <span className={`job-status-pill status-${task.status.toLowerCase()}`}>{task.status}</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
