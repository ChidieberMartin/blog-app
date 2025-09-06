import React, { useState } from 'react';
import { Lock, Mail, Eye, EyeOff } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../../AuthContext/AuthContext';
import {toast, ToastContainer} from 'react-toastify';

const Login = ({ setCurrentPage }) => {
  const { login } = useAuth(); // ✅ use real login from AuthContext
  const [formData, setFormData] = useState({
    email: '',
    password: '',
    rememberMe: false
  });
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState({ text: '', type: '' });
  const [showPassword, setShowPassword] = useState(false);

  const navigate = useNavigate();

  const handleInputChange = (e) => {
    const { name, value, type, checked } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value
    }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setMessage({ text: '', type: '' });

    // Basic validation
    if (!formData.email || !formData.password) {
      setMessage({ text: 'Please fill in all fields', type: 'error' });
      setLoading(false);
      return;
    }

    // Email format validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(formData.email)) {
      setMessage({ text: 'Please enter a valid email address', type: 'error' });
      setLoading(false);
      return;
    }

    try {
      // ✅ Call backend login via AuthContext
      const result = await login(
        formData.email,
        formData.password,
        formData.rememberMe
      );

      if (result.success) {
        setMessage({ text: 'Login successful! Redirecting...', type: 'success' });
        toast.success('Login successful! Redirecting...');  
        setTimeout(() => {
          navigate('/home');
        }, 1500);
      } else {
        setMessage({ text: result.message || 'Login failed', type: 'error' });
      }
    } catch (error) {
      setMessage({ text: 'An unexpected error occurred. Please try again.', type: 'error' });
    } finally {
      setLoading(false);
    }
  };

  const handleForgotPassword = () => {
    setCurrentPage('forgotPassword');
  };

  const isEmailVerificationError = message.text.toLowerCase().includes('verify');

  return (
    <div
      className="w-100 min-vh-100 d-flex flex-column justify-content-center py-5"
      style={{
        background: 'linear-gradient(135deg, #f8fafc 0%, #e0e7ff 100%)'
      }}
    >
      <ToastContainer position="top-right" autoClose={3000} hideProgressBar={false} newestOnTop={false} closeOnClick rtl={false} pauseOnFocusLoss draggable pauseOnHover />
      <div className="container">
        <div className="row justify-content-center">
          <div className="col-sm-10 col-md-8 col-lg-6 col-xl-4">
            {/* Header Section */}
            <div className="text-center mb-4">
              <div
                className="d-inline-flex justify-content-center align-items-center rounded-circle shadow-lg mb-4"
                style={{
                  background: 'linear-gradient(135deg, #2563eb 0%, #4f46e5 100%)',
                  width: '80px',
                  height: '80px'
                }}
              >
                <Lock className="text-white" style={{ fontSize: '2rem' }} />
              </div>

              <h2 className="fw-bold mb-3" style={{ fontSize: '2rem' }}>
                Sign in to your account
              </h2>

              <p className="text-muted">
                Or{' '}
                <button
                  onClick={() => navigate('/signup')}
                  className="btn btn-link p-0 fw-medium text-decoration-none"
                  style={{ color: '#2563eb' }}
                  onMouseEnter={(e) => (e.target.style.color = '#1d4ed8')}
                  onMouseLeave={(e) => (e.target.style.color = '#2563eb')}
                >
                  create a new account
                </button>
              </p>
            </div>

            {/* Form Card */}
            <div className="card shadow-lg border-0">
              <div className="card-body p-4 p-sm-5">
                {/* Alert Messages */}
                {message.text && (
                  <div
                    className={`alert ${
                      message.type === 'error' ? 'alert-danger' : 'alert-success'
                    } d-flex align-items-start mb-4`}
                  >
                    <div className="flex-grow-1">
                      <p className="fw-medium mb-0 small">{message.text}</p>

                      {message.type === 'error' && isEmailVerificationError && (
                        <button
                          onClick={() => setCurrentPage('resendVerification')}
                          className="btn btn-link p-0 mt-2 small text-decoration-underline"
                          style={{ color: '#2563eb' }}
                        >
                          Resend verification email
                        </button>
                      )}
                    </div>
                  </div>
                )}

                <form onSubmit={handleSubmit}>
                  {/* Email Field */}
                  <div className="mb-4">
                    <label htmlFor="email" className="form-label fw-medium text-dark">
                      Email address
                    </label>
                    <div className="position-relative">
                      <span className="position-absolute top-50 start-0 translate-middle-y ms-3 text-muted">
                        <Mail size={20} />
                      </span>
                      <input
                        id="email"
                        name="email"
                        type="email"
                        autoComplete="email"
                        required
                        className="form-control form-control-lg ps-5"
                        placeholder="Enter your email"
                        value={formData.email}
                        onChange={handleInputChange}
                      />
                    </div>
                  </div>

                  {/* Password Field */}
                  <div className="mb-4">
                    <label htmlFor="password" className="form-label fw-medium text-dark">
                      Password
                    </label>
                    <div className="position-relative">
                      <span className="position-absolute top-50 start-0 translate-middle-y ms-3 text-muted">
                        <Lock size={20} />
                      </span>
                      <input
                        id="password"
                        name="password"
                        type={showPassword ? 'text' : 'password'}
                        autoComplete="current-password"
                        required
                        className="form-control form-control-lg ps-5 pe-5"
                        placeholder="Enter your password"
                        value={formData.password}
                        onChange={handleInputChange}
                      />
                      <button
                        type="button"
                        className="btn position-absolute top-50 end-0 translate-middle-y me-3 p-0 border-0 bg-transparent text-muted"
                        onClick={() => setShowPassword(!showPassword)}
                        style={{ zIndex: 10 }}
                      >
                        {showPassword ? <EyeOff size={20} /> : <Eye size={20} />}
                      </button>
                    </div>
                  </div>

                  {/* Remember Me & Forgot Password */}
                  <div className="d-flex justify-content-between align-items-center mb-4">
                    <div className="form-check">
                      <input
                        id="remember-me"
                        name="rememberMe"
                        type="checkbox"
                        className="form-check-input"
                        checked={formData.rememberMe}
                        onChange={handleInputChange}
                      />
                      <label
                        htmlFor="remember-me"
                        className="form-check-label small text-dark"
                      >
                        Remember me
                      </label>
                    </div>

                    <button
                      type="button"
                      onClick={handleForgotPassword}
                      className="btn btn-link p-0 text-decoration-none fw-medium small"
                      style={{ color: '#2563eb' }}
                    >
                      Forgot password?
                    </button>
                  </div>

                  {/* Submit Button */}
                  <div className="mb-4">
                    <button
                      type="submit"
                      disabled={loading}
                      className="btn btn-lg w-100 text-white fw-medium shadow-lg"
                      style={{
                        background: loading
                          ? '#9ca3af'
                          : 'linear-gradient(135deg, #2563eb 0%, #4f46e5 100%)',
                        border: 'none'
                      }}
                    >
                      {loading && (
                        <span
                          className="spinner-border spinner-border-sm me-2"
                          role="status"
                        >
                          <span className="visually-hidden">Loading...</span>
                        </span>
                      )}
                      {loading ? 'Signing in...' : 'Sign in'}
                    </button>
                  </div>
                </form>

                {/* Divider */}
                <div className="position-relative my-4">
                  <div className="position-absolute top-50 start-0 w-100 border-top border-secondary-subtle"></div>
                  <div className="position-relative text-center">
                    <span className="bg-white px-3 text-muted small">
                      New to BlogSpace?
                    </span>
                  </div>
                </div>

                {/* Create Account Button */}
                <button
                  onClick={() => navigate('/signup')}
                  className="btn btn-outline-secondary w-100 py-3 fw-medium"
                >
                  Create your account
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Login;
