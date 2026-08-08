import React, { useState } from "react";
import { Shield, Check, ArrowRight, X, Loader2 } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { toast } from "react-toastify";
import { useAuth } from "../contexts/AuthContext";

export default function PricingPage() {
  const navigate = useNavigate();
  const { jwtToken, hasRole } = useAuth();
  const [isLoading, setIsLoading] = useState(null);
  const [subscriptionResult, setSubscriptionResult] = useState(null);

  const isAdmin = hasRole("admin");

  const plans = [
    {
      id: "trial",
      name: "Trial",
      price: "$0",
      period: "/mois",
      description: "Pour découvrir la plateforme",
      features: ["5 agents Wazuh", "10 endpoints", "7 jours de rétention", "IA basique", "Support communautaire"],
      cta: "Commencer gratuitement",
      popular: false,
      color: "#64748b",
    },
    {
      id: "basic",
      name: "Basic",
      price: "$99",
      period: "/mois",
      description: "Pour les petites équipes SOC",
      features: ["5 agents Wazuh", "10 endpoints", "7 jours de rétention", "Analyse IA", "Email support"],
      cta: "S'abonner",
      popular: false,
      color: "#3b82f6",
    },
    {
      id: "pro",
      name: "Pro",
      price: "$299",
      period: "/mois",
      description: "Pour les équipes SOC professionnelles",
      features: ["25 agents Wazuh", "50 endpoints", "30 jours de rétention", "Analyse IA avancée", "Support prioritaire", "API complète"],
      cta: "S'abonner",
      popular: true,
      color: "#8b5cf6",
    },
  ];

  const handlePlanSelect = async (planId) => {
    if (isLoading) return;
    
    if (planId === "trial") {
      navigate("/register");
      return;
    }
    
    setIsLoading(planId);
    setSubscriptionResult(null);
    
    try {
      const response = await fetch("/api/tenants/subscribe", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${jwtToken}`,
        },
        body: JSON.stringify({
          plan: planId
        })
      });
      
      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.detail || "Failed to subscribe");
      }
      
      const data = await response.json();
      
      if (data.checkout_url) {
        // Redirect to Stripe checkout
        window.location.href = data.checkout_url;
      } else {
        // Backend applies the plan directly; show the resulting state.
        setSubscriptionResult(data);
        toast.success(`Subscribed to the ${data.plan} plan`);
      }
      
    } catch (error) {
      console.error("Subscription error:", error);
      toast.error(error.message || "Subscription failed", {
        icon: <X className="text-yellow-400" />
      });
    } finally {
      setIsLoading(null);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-[#050a0e] via-[#0a1018] to-[#0f1a24] py-12 px-4">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="text-center mb-16">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-gradient-to-br from-[#00ff88] to-[#00e5ff] mb-6 shadow-lg shadow-cyan-500/20">
            <Shield size={32} className="text-[#050a0e]" />
          </div>
          <h1 className="text-4xl md:text-5xl font-bold text-[#00ff88] font-mono tracking-wider mb-4">
            Choose Your Plan
          </h1>
          <p className="text-[#94a3b8] text-lg max-w-2xl mx-auto">
            Select the perfect SOC solution for your organization. All plans include 24/7 monitoring and advanced threat detection.
          </p>
        </div>

        {/* Pricing Cards */}
        {!isAdmin ? (
          <div className="max-w-6xl mx-auto">
            <div className="bg-[var(--bg-card)] rounded-lg border border-[var(--border)] p-8 text-center">
              <Shield size={32} className="text-[#94a3b8] mx-auto mb-4" />
              <h3 className="text-[#c8d6e5] font-semibold mb-2">Administrator access required</h3>
              <p className="text-[#94a3b8] text-sm">
                Only administrators can manage the tenant subscription. Contact your workspace administrator to change the plan.
              </p>
            </div>
          </div>
        ) : (
          <>
            {subscriptionResult && (
              <div className="max-w-6xl mx-auto mb-8">
                <div className="bg-[var(--bg-card)] rounded-lg border border-[#00ff88]/30 p-6 text-center">
                  <Check size={24} className="text-[#00ff88] mx-auto mb-2" />
                  <h3 className="text-[#00ff88] font-semibold">Subscription updated</h3>
                  <p className="text-[#94a3b8] text-sm mt-1">
                    Plan: <span className="text-[#c8d6e5] font-mono uppercase">{subscriptionResult.plan}</span>
                    {subscriptionResult.subscription_end && <> · Renews {new Date(subscriptionResult.subscription_end).toLocaleDateString()}</>}
                  </p>
                </div>
              </div>
            )}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8 max-w-6xl mx-auto">
              {plans.map((plan) => (
            <div
              key={plan.id}
              className={`relative group ${plan.popular ? 'lg:scale-105 z-10' : 'hover:scale-[1.02]'} transition-all duration-300`}
            >
              {/* Popular badge */}
              {plan.popular && (
                <div className="absolute -top-4 left-1/2 transform -translate-x-1/2 z-20">
                  <span className="bg-gradient-to-r from-[#8b5cf6] to-[#a855f7] text-white px-4 py-1 rounded-full text-xs font-bold uppercase tracking-wider shadow-lg">
                    POPULAR
                  </span>
                </div>
              )}

              {/* Card */}
              <div className={`h-full rounded-2xl border backdrop-blur-xl p-8 transition-all duration-300
                ${plan.popular 
                  ? 'bg-[var(--bg-card)] border-[#8b5cf6]/30 shadow-2xl shadow-purple-500/10' 
                  : 'bg-[var(--bg-card)] border-[var(--border)] hover:border-[var(--accent)]/30 hover:shadow-xl hover:shadow-cyan-500/10'
                }
              `}
              style={plan.popular ? {
                boxShadow: '0 0 50px rgba(139, 92, 246, 0.15), inset 0 0 40px rgba(139, 92, 246, 0.05)'
              } : {}}
              >
                {/* Plan header */}
                <div className="text-center mb-8">
                  <h3 className={`text-2xl font-bold mb-2 ${plan.popular ? 'text-[#8b5cf6]' : 'text-[#c8d6e5]'}`}>{plan.name}</h3>
                  <p className="text-[#94a3b8] text-sm mb-6">{plan.description}</p>
                  
                  {/* Price */}
                  <div className="mb-6">
                    <span className="text-4xl font-bold text-[#c8d6e5]">{plan.price}</span>
                    <span className="text-[#94a3b8] ml-1">{plan.period}</span>
                  </div>
                </div>

                {/* Features */}
                <div className="space-y-4 mb-8">
                  {plan.features.map((feature, index) => (
                    <div key={index} className="flex items-center gap-3">
                      <div className="flex-shrink-0 w-5 h-5 rounded-full bg-[#00ff88]/10 flex items-center justify-center">
                        <Check size={12} className="text-[#00ff88]" />
                      </div>
                      <span className="text-[#94a3b8] text-sm">{feature}</span>
                    </div>
                  ))}
                </div>

                {/* CTA Button */}
                <button
                  onClick={() => handlePlanSelect(plan.id)}
                  disabled={isLoading === plan.id}
                  className={`w-full py-3 px-4 rounded-lg font-semibold transition-all duration-200 flex items-center justify-center gap-2 font-mono uppercase tracking-wider
                    ${plan.popular
                      ? 'bg-gradient-to-r from-[#8b5cf6] to-[#a855f7] text-white hover:shadow-lg hover:shadow-purple-500/25 transform hover:scale-[1.02]'
                      : 'bg-[var(--bg-primary)] border border-[var(--border)] text-[#c8d6e5] hover:border-[var(--accent)]/50 hover:bg-[var(--accent)]/5'
                    }
                    ${isLoading === plan.id ? 'opacity-50 cursor-not-allowed' : ''}
                  `}
                >
                  {isLoading === plan.id ? (
                    <>
                      <Loader2 size={18} className="animate-spin" />
                      Processing...
                    </>
                  ) : (
                    <>
                      {plan.cta}
                      <ArrowRight size={16} />
                    </>
                  )}
                </button>
              </div>
            </div>
          ))}
            </div>
          </>
        )}

        {/* FAQ Section */}
        <div className="mt-20 max-w-4xl mx-auto">
          <h2 className="text-2xl font-bold text-[#00ff88] text-center mb-8 font-mono">Questions Fréquentes</h2>
          <div className="grid md:grid-cols-2 gap-6">
            <div className="bg-[var(--bg-card)] rounded-lg border border-[var(--border)] p-6">
              <h3 className="text-[#c8d6e5] font-semibold mb-2">Can I upgrade my plan later?</h3>
              <p className="text-[#94a3b8] text-sm">Yes, you can upgrade or downgrade your plan at any time. Changes take effect at the next billing cycle.</p>
            </div>
            <div className="bg-[var(--bg-card)] rounded-lg border border-[var(--border)] p-6">
              <h3 className="text-[#c8d6e5] font-semibold mb-2">Is there a setup fee?</h3>
              <p className="text-[#94a3b8] text-sm">No setup fees. You only pay the monthly subscription for your chosen plan.</p>
            </div>
            <div className="bg-[var(--bg-card)] rounded-lg border border-[var(--border)] p-6">
              <h3 className="text-[#c8d6e5] font-semibold mb-2">What payment methods are accepted?</h3>
              <p className="text-[#94a3b8] text-sm">We accept all major credit cards through Stripe. Payment is processed securely.</p>
            </div>
            <div className="bg-[var(--bg-card)] rounded-lg border border-[var(--border)] p-6">
              <h3 className="text-[#c8d6e5] font-semibold mb-2">Can I cancel anytime?</h3>
              <p className="text-[#94a3b8] text-sm">Yes, you can cancel your subscription at any time. No long-term commitments required.</p>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="text-center mt-16">
          <p className="text-xs text-[#5a7a8a] font-mono">
            © 2026 Sentinel Bridge. All rights reserved.
          </p>
        </div>
      </div>
    </div>
  );
}
