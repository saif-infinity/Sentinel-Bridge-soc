import SurveillanceDashboard from "../components/SurveillanceDashboard";
import { useAuth } from "../contexts/AuthContext";

export default function SurveillancePage() {
  const { jwtToken } = useAuth();
  return (
    <div className="tab-pane animate-fade-in">
      <SurveillanceDashboard token={jwtToken} />
    </div>
  );
}
