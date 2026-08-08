import React, { useState, useEffect } from "react";
import { Shield, User, Mail, Lock, Eye, EyeOff, CheckCircle, AlertCircle, Loader2, UserPlus, CreditCard, ArrowRight, Check, X } from "lucide-react";
import { useNavigate, Link } from "react-router-dom";
import { toast } from "react-toastify";

export default function RegisterPage() {
  const navigate = useNavigate();
  const [formData, setFormData] = useState({
    company_name: "",
    email: "",
    admin_username: "",
    admin_password: "",
    confirm_password: ""
  });
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [errors, setErrors] = useState({});
  const [passwordStrength, setPasswordStrength] = useState({
    score: 0,
    label: "",
    color: ""
  });

  // Check if user is already authenticated
  useEffect(() => {
    const token = localStorage.getItem("auth_token");
    if (token) {
      navigate("/");
    }
  }, [navigate]);

  const validateForm = () => {
    const newErrors = {};
    
    if (!formData.company_name.trim()) {
      newErrors.company_name = "Company name is required";
    }
    
    if (!formData.email.trim()) {
      newErrors.email = "Email is required";
    } else if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(formData.email)) {
      newErrors.email = "Please enter a valid email";
    }
    
    if (!formData.admin_username.trim()) {
      newErrors.admin_username = "Username is required";
    } else if (formData.admin_username.length < 3) {
      newErrors.admin_username = "Username must be at least 3 characters";
    }
    
    if (!formData.admin_password) {
      newErrors.admin_password = "Password is required";
    } else {
      const password = formData.admin_password;
      const hasUpper = /[A-Z]/.test(password);
      const hasLower = /[a-z]/.test(password);
      const hasNumber = /[0-9]/.test(password);
      const hasMinLength = password.length >= 8;
      
      if (!hasUpper || !hasLower || !hasNumber || !hasMinLength) {
        newErrors.admin_password = "Password must be at least 8 characters with uppercase, lowercase, and a number";
      }
    }
    
    if (!formData.confirm_password) {
      newErrors.confirm_password = "Please confirm your password";
    } else if (formData.admin_password !== formData.confirm_password) {
      newErrors.confirm_password = "Passwords do not match";
    }
    
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const calculatePasswordStrength = (password) => {
    let score = 0;
    let label = "";
    let color = "";
    
    if (password.length >= 8) score += 1;
    if (password.length >= 12) score += 1;
    if (/[A-Z]/.test(password)) score += 1;
    if (/[a-z]/.test(password)) score += 1;
    if (/[0-9]/.test(password)) score += 1;
    if (/[^A-Za-z0-9]/.test(password)) score += 1;
    
    if (score <= 2) {
      label = "Weak";
      color = "text-red-400";
    } else if (score <= 4) {
      label = "Medium";
      color = "text-yellow-400";
    } else {
      label = "Strong";
      color = "text-green-400";
    }
    
    setPasswordStrength({ score, label, color });
  };

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
    
    if (name === "admin_password") {
      calculatePasswordStrength(value);
    }
    
    if (errors[name]) {
      setErrors(prev => ({ ...prev, [name]: "" }));
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!validateForm()) return;
    
    setIsLoading(true);
    
    try {
      const response = await fetch("/api/tenants/register", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          company_name: formData.company_name,
          email: formData.email,
          admin_username: formData.admin_username,
          admin_password: formData.admin_password
        })
      });
      
      if (!response.ok) {
        const errorData = await response.json();
        if (response.status === 409) {
          throw new Error("Email already exists. Please use a different email or login if you already have an account.");
        } else if (response.status === 400) {
          throw new Error(errorData.detail || "Invalid registration data");
        } else {
          throw new Error(errorData.detail || `Registration failed (${response.status})`);
        }
      }
      
      const data = await response.json();
      
      // Store auth data in localStorage
      localStorage.setItem("auth_token", data.access_token);
      localStorage.setItem("auth_username", formData.admin_username);
      localStorage.setItem("auth_tenant_id", data.tenant_id);
      
      toast.success("Registration successful! Welcome to your SOC platform.", {
        icon: <CheckCircle className="text-green-400" />
      });
      
      // Redirect to dashboard
      setTimeout(() => {
        navigate("/");
      }, 1500);
      
    } catch (error) {
      toast.error(error.message, {
        icon: <AlertCircle className="text-red-400" />
      });
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-[#050a0e] via-[#0a1018] to-[#0f1a24] flex items-center justify-center p-4">
      <div className="w-full max-w-480px">
        {/* Logo/Brand */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-gradient-to-br from-[#00ff88] to-[#00e5ff] mb-4 shadow-lg shadow-cyan-500/20">
            <Shield size={32} className="text-[#050a0e]" />
          </div>
          <h1 className="text-3xl font-bold text-[#00ff88] font-mono tracking-wider">SENTINEL BRIDGE</h1>
          <p className="text-[#5a7a8a] text-sm mt-2">Enterprise SOC Platform</p>
        </div>

        {/* Registration Card */}
        <div className="bg-[var(--bg-card)] rounded-2xl border border-[var(--border)] backdrop-blur-xl p-8 shadow-2xl">
          <div className="text-center mb-6">
            <h2 className="text-2xl font-bold text-[#c8d6e5] mb-2">Create Your Account</h2>
            <p className="text-[#94a3b8] text-sm">Start your 14-day free trial today</p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-5">
            {/* Company Name */}
            <div>
              <label className="block text-xs font-semibold text-[#00ff88] uppercase tracking-wider mb-2">
                Company Name
              </label>
              <div className="relative">
                <User size={16} className="absolute left-3 top-1/2 transform -translate-y-1/2 text-[#5a7a8a]" />
                <input
                  type="text"
                  name="company_name"
                  value={formData.company_name}
                  onChange={handleChange}
                  className={`w-full pl-10 pr-4 py-3 bg-[var(--bg-primary)] border rounded-lg text-[#c8d6e5] placeholder-[#5a7a8a] focus:outline-none focus:ring-2 focus:ring-[#00ff88] focus:border-transparent transition-all font-mono ${errors.company_name ? 'border-[#ff6b6b]' : 'border-[var(--border)]'}`}
                  placeholder="Acme Corporation"
                  disabled={isLoading}
                />
              </div>
              {errors.company_name && (
                <p className="mt-1 text-xs text-[#ff6b6b]">{errors.company_name}</p>
              )}
            </div>

            {/* Email */}
            <div>
              <label className="block text-xs font-semibold text-[#00ff88] uppercase tracking-wider mb-2">
                Email Address
              </label>
              <div className="relative">
                <Mail size={16} className="absolute left-3 top-1/2 transform -translate-y-1/2 text-[#5a7a8a]" />
                <input
                  type="email"
                  name="email"
                  value={formData.email}
                  onChange={handleChange}
                  className={`w-full pl-10 pr-4 py-3 bg-[var(--bg-primary)] border rounded-lg text-[#c8d6e5] placeholder-[#5a7a8a] focus:outline-none focus:ring-2 focus:ring-[#00ff88] focus:border-transparent transition-all font-mono ${errors.email ? 'border-[#ff6b6b]' : 'border-[var(--border)]'}`}
                  placeholder="admin@company.com"
                  disabled={isLoading}
                />
              </div>
              {errors.email && (
                <p className="mt-1 text-xs text-[#ff6b6b]">{errors.email}</p>
              )}
              <p className="mt-1 text-xs text-[#5a7a8a] flex items-center gap-1">
                <Check size={12} className="text-[#00ff88]" /> Email verification required
              </p>
            </div>

            {/* Admin Username */}
            <div>
              <label className="block text-xs font-semibold text-[#00ff88] uppercase tracking-wider mb-2">
                Admin Username
              </label>
              <div className="relative">
                <User size={16} className="absolute left-3 top-1/2 transform -translate-y-1/2 text-[#5a7a8a]" />
                <input
                  type="text"
                  name="admin_username"
                  value={formData.admin_username}
                  onChange={handleChange}
                  className={`w-full pl-10 pr-4 py-3 bg-[var(--bg-primary)] border rounded-lg text-[#c8d6e5] placeholder-[#5a7a8a] focus:outline-none focus:ring-2 focus:ring-[#00ff88] focus:border-transparent transition-all font-mono ${errors.admin_username ? 'border-[#ff6b6b]' : 'border-[var(--border)]'}`}
                  placeholder="admin"
                  disabled={isLoading}
                />
              </div>
              {errors.admin_username && (
                <p className="mt-1 text-xs text-[#ff6b6b]">{errors.admin_username}</p>
              )}
            </div>

            {/* Password */}
            <div>
              <label className="block text-xs font-semibold text-[#00ff88] uppercase tracking-wider mb-2">
                Password
              </label>
              <div className="relative">
                <Lock size={16} className="absolute left-3 top-1/2 transform -translate-y-1/2 text-[#5a7a8a]" />
                <input
                  type={showPassword ? "text" : "password"}
                  name="admin_password"
                  value={formData.admin_password}
                  onChange={handleChange}
                  className={`w-full pl-10 pr-12 py-3 bg-[var(--bg-primary)] border rounded-lg text-[#c8d6e5] placeholder-[#5a7a8a] focus:outline-none focus:ring-2 focus:ring-[#00ff88] focus:border-transparent transition-all font-mono ${errors.admin_password ? 'border-[#ff6b6b]' : 'border-[var(--border)]'}`}
                  placeholder="••••••••"
                  disabled={isLoading}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 transform -translate-y-1/2 text-[#5a7a8a] hover:text-[#00ff88] transition-colors"
                  disabled={isLoading}
                >
                  {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
              {errors.admin_password && (
                <p className="mt-1 text-xs text-[#ff6b6b]">{errors.admin_password}</p>
              )}
              {formData.admin_password && (
                <div className="mt-2">
                  <div className="flex items-center justify-between mb-1">
                    <span className={`text-xs ${passwordStrength.color}`}>{passwordStrength.label} Password</span>
                    <span className="text-xs text-[#5a7a8a]">{formData.admin_password.length}/16</span>
                  </div>
                  <div className="w-full bg-[var(--bg-primary)] rounded-full h-1">
                    <div 
                      className={`h-1 rounded-full transition-all duration-300 ${passwordStrength.score <= 2 ? 'bg-[#ff6b6b]' : passwordStrength.score <= 4 ? 'bg-[#eab308]' : 'bg-[#00ff88]'}`}
                      style={{ width: `${Math.min(passwordStrength.score * 20, 100)}%` }}
                    />
                  </div>
                </div>
              )}
            </div>

            {/* Confirm Password */}
            <div>
              <label className="block text-xs font-semibold text-[#00ff88] uppercase tracking-wider mb-2">
                Confirm Password
              </label>
              <div className="relative">
                <Lock size={16} className="absolute left-3 top-1/2 transform -translate-y-1/2 text-[#5a7a8a]" />
                <input
                  type={showConfirmPassword ? "text" : "password"}
                  name="confirm_password"
                  value={formData.confirm_password}
                  onChange={handleChange}
                  className={`w-full pl-10 pr-12 py-3 bg-[var(--bg-primary)] border rounded-lg text-[#c8d6e5] placeholder-[#5a7a8a] focus:outline-none focus:ring-2 focus:ring-[#00ff88] focus:border-transparent transition-all font-mono ${errors.confirm_password ? 'border-[#ff6b6b]' : 'border-[var(--border)]'}`}
                  placeholder="••••••••"
                  disabled={isLoading}
                />
                <button
                  type="button"
                  onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                  className="absolute right-3 top-1/2 transform -translate-y-1/2 text-[#5a7a8a] hover:text-[#00ff88] transition-colors"
                  disabled={isLoading}
                >
                  {showConfirmPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
              {errors.confirm_password && (
                <p className="mt-1 text-xs text-[#ff6b6b]">{errors.confirm_password}</p>
              )}
            </div>

            {/* Submit Button */}
            <button
              type="submit"
              disabled={isLoading}
              className="w-full py-3 px-4 bg-gradient-to-r from-[#00ff88] to-[#00e5ff] text-[#050a0e] font-bold rounded-lg hover:shadow-lg hover:shadow-cyan-500/25 transition-all duration-200 transform hover:scale-[1.02] disabled:opacity-50 disabled:cursor-not-allowed disabled:transform-none flex items-center justify-center gap-2 font-mono uppercase tracking-wider"
            >
              {isLoading ? (
                <>
                  <Loader2 size={18} className="animate-spin" />
                  Creating Account...
                </>
              ) : (
                <>
                  <UserPlus size={18} />
                  Create Account
                </>
              )}
            </button>
          </form>

          {/* Divider */}
          <div className="my-6 flex items-center">
            <div className="flex-1 border-t border-[var(--border)]"></div>
            <span className="px-4 text-xs text-[#5a7a8a] font-mono">OR</span>
            <div className="flex-1 border-t border-[var(--border)]"></div>
          </div>

          {/* Links */}
          <div className="text-center space-y-3">
            <p className="text-sm text-[#94a3b8]">
              Already have an account?{' '}
              <Link to="/login" className="text-[#00ff88] hover:text-[#00e5ff] font-semibold transition-colors">
                Sign in
              </Link>
            </p>
            <p className="text-sm text-[#94a3b8]">
              <Link to="/pricing" className="text-[#00ff88] hover:text-[#00e5ff] font-semibold transition-colors">
                View plans
              </Link>
            </p>
          </div>
        </div>

        {/* Footer */}
        <div className="text-center mt-8">
          <p className="text-xs text-[#5a7a8a] font-mono">
            © 2026 Sentinel Bridge. All rights reserved.
          </p>
        </div>
      </div>
    </div>
  );
}
