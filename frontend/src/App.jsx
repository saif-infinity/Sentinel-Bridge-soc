import React, { Suspense, lazy, Component } from "react";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ToastContainer } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";
import "./App.css";

import { AuthProvider, useAuth } from "./contexts/AuthContext";
import { DataProvider } from "./contexts/DataContext";
import Layout from "./components/Layout";
import LoginPage from "./components/LoginPage";
import SplashScreen from "./components/SplashScreen";
import "./styles/splash.css";

const DashboardPage = lazy(() => import("./pages/DashboardPage"));
const TopologyPage = lazy(() => import("./pages/TopologyPage"));
const InventoryPage = lazy(() => import("./pages/InventoryPage"));
const RadarPage = lazy(() => import("./pages/RadarPage"));
const TerminalPage = lazy(() => import("./pages/TerminalPage"));
const RemediationPage = lazy(() => import("./pages/RemediationPage"));
const TerminalAlertsPage = lazy(() => import("./pages/TerminalAlertsPage"));
const SuricataPage = lazy(() => import("./pages/SuricataPage"));
const NetworkControlPage = lazy(() => import("./pages/NetworkControlPage"));
const NetworkDevicesPage = lazy(() => import("./pages/NetworkDevicesPage"));
const AICopilotPage = lazy(() => import("./pages/AICopilotPage"));
const AIHistoryPage = lazy(() => import("./pages/AIHistoryPage"));
const SettingsPage = lazy(() => import("./pages/SettingsPage"));
const RulesPage = lazy(() => import("./pages/RulesPage"));
const MitrePage = lazy(() => import("./pages/MitrePage"));
const CasesPage = lazy(() => import("./pages/CasesPage"));
const HuntingPage = lazy(() => import("./pages/HuntingPage"));
const PlaybooksPage = lazy(() => import("./pages/PlaybooksPage"));
const RegisterPage = lazy(() => import("./pages/RegisterPage"));
const PricingPage = lazy(() => import("./pages/PricingPage"));
const AdminPage = lazy(() => import("./pages/AdminPage"));
const SuperAdminPage = lazy(() => import("./pages/SuperAdminPage"));
const HostAgentsPage = lazy(() => import("./pages/HostAgentsPage"));

const PageLoader = () => (
  <div className="page-loader">
    <div className="page-loader-spinner" />
    Loading...
  </div>
);

class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }
  static getDerivedStateFromError(error) {
    console.error("[ErrorBoundary]", error);
    return { hasError: true, error };
  }
  render() {
    if (this.state.hasError) {
      return (
        <div className="error-boundary">
          <p className="error-boundary-title">⚠️ Une erreur est survenue</p>
          <p className="error-boundary-message">
            {this.state.error?.message || "Erreur inconnue"}
          </p>
          <div className="error-boundary-actions">
            <button
              onClick={() => this.setState({ hasError: false })}
              className="error-boundary-btn error-boundary-btn-retry"
            >
              Réessayer
            </button>
            <button
              onClick={() => { this.setState({ hasError: false }); window.location.reload(); }}
              className="error-boundary-btn error-boundary-btn-reload"
            >
              Recharger
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { retry: 1, refetchOnWindowFocus: false },
  },
});

// Client-side route guard: redirects to "/" when the current role is below the
// minimum required. Backend endpoints remain the source of truth for access.
function RequireRole({ minRole, children }) {
  const { hasRole } = useAuth();
  if (!hasRole(minRole)) return <Navigate to="/" replace />;
  return children;
}

function AppRoutes() {
  const { isAuthenticated, login } = useAuth();
  const [splashDone, setSplashDone] = React.useState(false);

  // Login gate: default behavior requires authentication. Dev escape hatch is
  // only active when VITE_AUTOLOGIN=1 is set in the environment.
  if (!isAuthenticated && import.meta.env.VITE_AUTOLOGIN !== "1") {
    if (!splashDone) {
      return <SplashScreen onDone={() => setSplashDone(true)} />;
    }
    return <LoginPage onLogin={login} />;
  }

  return (
    <DataProvider>
      <Layout>
        <ErrorBoundary>
          <Suspense fallback={<PageLoader />}>
            <Routes>
              <Route path="/" element={<DashboardPage />} />
              <Route path="/topology" element={<TopologyPage />} />
              <Route path="/inventory" element={<InventoryPage />} />
              <Route path="/radar" element={<RadarPage />} />
              <Route path="/terminal" element={<TerminalPage />} />
              <Route path="/remediation" element={<RemediationPage />} />
              <Route path="/alerts" element={<TerminalAlertsPage />} />
              <Route path="/suricata" element={<SuricataPage />} />
              <Route path="/network-control" element={<NetworkControlPage />} />
              <Route path="/network-devices" element={<NetworkDevicesPage />} />
              <Route path="/ai" element={<AICopilotPage />} />
              <Route path="/ai-history" element={<AIHistoryPage />} />
              <Route path="/settings" element={<SettingsPage />} />
              <Route path="/rules" element={<RulesPage />} />
              <Route path="/mitre" element={<MitrePage />} />
              <Route path="/cases" element={<CasesPage />} />
              <Route path="/hunting" element={<HuntingPage />} />
              <Route path="/playbooks" element={<PlaybooksPage />} />
              <Route path="/host-agents" element={<HostAgentsPage />} />
              <Route path="/register" element={<RegisterPage />} />
              <Route path="/pricing" element={<PricingPage />} />
              <Route
                path="/admin"
                element={
                  <RequireRole minRole="admin">
                    <AdminPage />
                  </RequireRole>
                }
              />
              <Route
                path="/super-admin"
                element={
                  <RequireRole minRole="super_admin">
                    <SuperAdminPage />
                  </RequireRole>
                }
              />
            </Routes>
          </Suspense>
        </ErrorBoundary>
      </Layout>
    </DataProvider>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <QueryClientProvider client={queryClient}>
        <AuthProvider>
          <ToastContainer position="top-right" autoClose={5000} theme="dark" />
          <AppRoutes />
        </AuthProvider>
      </QueryClientProvider>
    </BrowserRouter>
  );
}
