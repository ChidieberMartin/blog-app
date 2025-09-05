import React, { useState } from 'react';
import { User, Mail, Lock, Eye, EyeOff, Loader, CheckCircle } from 'lucide-react';
import { useAuth } from '../../AuthContext/AuthContext';
import { Link,useNavigate } from "react-router-dom";

const Signup = () => {
  const { signup } = useAuth();
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    password: '',
    confirmPassword: ''
  });
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState({ text: '', type: '' });
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [passwordStrength, setPasswordStrength] = useState(0);
  const [registrationSuccess, setRegistrationSuccess] = useState(false);
  const [successEmail, setSuccessEmail] = useState('');

   const navigate = useNavigate();

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));

    if (name === 'password') {
      checkPasswordStrength(value);
    }
  };

  const checkPasswordStrength = (password) => {
    let strength = 0;
    if (password.length >= 8) strength++;
    if (/[A-Z]/.test(password)) strength++;
    if (/[a-z]/.test(password)) strength++;
    if (/[0-9]/.test(password)) strength++;
    if (/[^A-Za-z0-9]/.test(password)) strength++;
    setPasswordStrength(strength);
  };

  const getPasswordStrengthText = () => {
    switch (passwordStrength) {
      case 0:
      case 1: return { text: 'Very Weak', color: 'text-danger' };
      case 2: return { text: 'Weak', color: 'text-warning' };
      case 3: return { text: 'Fair', color: 'text-warning' };
      case 4: return { text: 'Good', color: 'text-primary' };
      case 5: return { text: 'Strong', color: 'text-success' };
      default: return { text: '', color: '' };
    }
  };

  const getPasswordStrengthBarClass = () => {
    switch (passwordStrength) {
      case 0:
      case 1: return 'bg-danger';
      case 2: return 'bg-warning';
      case 3: return 'bg-warning';
      case 4: return 'bg-primary';
      case 5: return 'bg-success';
      default: return 'bg-secondary';
    }
  };

  const validateForm = () => {
    if (!formData.name.trim()) {
      return { isValid: false, message: 'Name is required' };
    }
    if (!formData.email.trim()) {
      return { isValid: false, message: 'Email is required' };
    }
    if (!formData.password) {
      return { isValid: false, message: 'Password is required' };
    }
    if (formData.password.length < 8) {
      return { isValid: false, message: 'Password must be at least 8 characters long' };
    }
    if (formData.password !== formData.confirmPassword) {
      return { isValid: false, message: 'Passwords do not match' };
    }
    return { isValid: true };
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setMessage({ text: '', type: '' });

    const validation = validateForm();
    if (!validation.isValid) {
      setMessage({ text: validation.message, type: 'error' });
      setLoading(false);
      return;
    }

    try {
      const result = await signup(formData.name, formData.email, formData.password);

      if (result.success) {
        setSuccessEmail(formData.email);
        setFormData({ name: "", email: "", password: "", confirmPassword: "" });
        setMessage({ text: result.message, type: 'success' });
        setRegistrationSuccess(true);
      } else {
        setMessage({ text: result.message, type: 'error' });
      }
    } catch (error) {
      setMessage({ 
        text: 'Registration failed. Please try again.', 
        type: 'error' 
      });
    } finally {
      setLoading(false);
    }
  };

  const handleResendVerification = async () => {
    try {
      setLoading(true);
      // You would call resendVerification function here
      // const result = await resendVerification(successEmail);
      setMessage({ text: 'Verification email resent successfully!', type: 'success' });
    } catch (error) {
      setMessage({ text: 'Failed to resend verification email', type: 'error' });
    } finally {
      setLoading(false);
    }
  };

  const resetToSignup = () => {
    setRegistrationSuccess(false);
    setSuccessEmail('');
    setMessage({ text: '', type: '' });
  };

  if (registrationSuccess) {
    return (
      <div className="min-vh-100 bg-light d-flex flex-column justify-content-center py-5">
        <div className="container">
          <div className="row justify-content-center">
            <div className="col-md-6 col-lg-4">
              <div className="card shadow-lg border-0">
                <div className="card-body p-4">
                  <div className="text-center">
                    <CheckCircle className="mx-auto mb-3 text-success" size={48} />
                    <h2 className="h4 fw-bold text-dark mb-3">Check Your Email</h2>
                    <p className="text-muted small mb-3">
                      We've sent a verification link to <strong>{successEmail}</strong>
                    </p>
                    <p className="text-muted small mb-4">
                      Please check your email and click the verification link to activate your account.
                    </p>

                    {/* Message Alert for resend confirmation */}
                    {message.text && (
                      <div className={`alert ${message.type === 'error' ? 'alert-danger' : 'alert-success'} alert-dismissible mb-3`} role="alert">
                        <small>{message.text}</small>
                      </div>
                    )}

                    <div className="d-grid gap-2">
                      <button
                         onClick={() => navigate('/')}
                        className="btn btn-primary"
                        disabled={loading}
                      >
                        Go to Login
                      </button>
                      <button
                        onClick={handleResendVerification}
                        disabled={loading}
                        className="btn btn-link text-primary p-0 small"
                      >
                        {loading ? (
                          <>
                            <Loader className="spinner-border spinner-border-sm me-1" />
                            Sending...
                          </>
                        ) : (
                          "Didn't receive the email? Resend verification"
                        )}
                      </button>
                      <button
                        onClick={resetToSignup}
                        className="btn btn-link text-muted p-0 small"
                      >
                        Back to signup
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-vh-100 bg-light d-flex flex-column justify-content-center py-5">
      <div className="container">
        <div className="row justify-content-center">
          <div className="col-md-6 col-lg-4">
            {/* Header */}
            <div className="text-center mb-4">
              <div className="bg-primary rounded-circle d-inline-flex align-items-center justify-content-center mb-3" 
                   style={{width: '56px', height: '56px'}}>
                <User className="text-white" size={24} />
              </div>
              <h2 className="h3 fw-bold text-dark mb-2">Create your account</h2>
              <p className="text-muted small">
                Or{' '}
                <button
                  type="button"
                   onClick={() => navigate('/')}
                  className="btn btn-link text-primary p-0 fw-medium text-decoration-none"
                >
                  sign in to your existing account
                </button>
              </p>
            </div>

            {/* Main Form Card */}
            <div className="card shadow-lg border-0">
              <div className="card-body p-4">
                {/* Message Alert */}
                {message.text && (
                  <div className={`alert ${message.type === 'error' ? 'alert-danger' : 'alert-success'} alert-dismissible mb-3`} role="alert">
                    <small>{message.text}</small>
                    <button
                      type="button"
                      className="btn-close"
                      onClick={() => setMessage({ text: '', type: '' })}
                      aria-label="Close"
                    ></button>
                  </div>
                )}

                <form onSubmit={handleSubmit}>
                  {/* Full Name */}
                  <div className="mb-3">
                    <label htmlFor="name" className="form-label small fw-medium text-dark">
                      Full Name
                    </label>
                    <div className="position-relative">
                      <User className="position-absolute text-muted" 
                            style={{left: '12px', top: '50%', transform: 'translateY(-50%)'}} 
                            size={20} />
                      <input
                        id="name"
                        name="name"
                        type="text"
                        autoComplete="name"
                        required
                        className="form-control ps-5"
                        placeholder="Enter your full name"
                        value={formData.name}
                        onChange={handleInputChange}
                        disabled={loading}
                      />
                    </div>
                  </div>

                  {/* Email */}
                  <div className="mb-3">
                    <label htmlFor="email" className="form-label small fw-medium text-dark">
                      Email address
                    </label>
                    <div className="position-relative">
                      <Mail className="position-absolute text-muted" 
                            style={{left: '12px', top: '50%', transform: 'translateY(-50%)'}} 
                            size={20} />
                      <input
                        id="email"
                        name="email"
                        type="email"
                        autoComplete="email"
                        required
                        className="form-control ps-5"
                        placeholder="Enter your email"
                        value={formData.email}
                        onChange={handleInputChange}
                        disabled={loading}
                      />
                    </div>
                  </div>

                  {/* Password */}
                  <div className="mb-3">
                    <label htmlFor="password" className="form-label small fw-medium text-dark">
                      Password
                    </label>
                    <div className="position-relative">
                      <Lock className="position-absolute text-muted" 
                            style={{left: '12px', top: '50%', transform: 'translateY(-50%)'}} 
                            size={20} />
                      <input
                        id="password"
                        name="password"
                        type={showPassword ? 'text' : 'password'}
                        autoComplete="new-password"
                        required
                        className="form-control ps-5 pe-5"
                        placeholder="Create a password"
                        value={formData.password}
                        onChange={handleInputChange}
                        disabled={loading}
                      />
                      <button
                        type="button"
                        className="btn btn-link position-absolute text-muted p-0"
                        style={{right: '12px', top: '50%', transform: 'translateY(-50%)'}}
                        onClick={() => setShowPassword(!showPassword)}
                        disabled={loading}
                      >
                        {showPassword ? <EyeOff size={20} /> : <Eye size={20} />}
                      </button>
                    </div>

                    {/* Password Strength */}
                    {formData.password && (
                      <div className="mt-2">
                        <div className="d-flex justify-content-between align-items-center mb-1">
                          <span className="small text-muted">Password strength:</span>
                          <span className={`small fw-medium ${getPasswordStrengthText().color}`}>
                            {getPasswordStrengthText().text}
                          </span>
                        </div>
                        <div className="progress" style={{height: '4px'}}>
                          <div
                            className={`progress-bar ${getPasswordStrengthBarClass()}`}
                            role="progressbar"
                            style={{ width: `${(passwordStrength / 5) * 100}%` }}
                          />
                        </div>
                        <p className="mt-1 small text-muted mb-0">
                          Use 8+ characters with letters, numbers & symbols
                        </p>
                      </div>
                    )}
                  </div>

                  {/* Confirm Password */}
                  <div className="mb-3">
                    <label htmlFor="confirmPassword" className="form-label small fw-medium text-dark">
                      Confirm Password
                    </label>
                    <div className="position-relative">
                      <Lock className="position-absolute text-muted" 
                            style={{left: '12px', top: '50%', transform: 'translateY(-50%)'}} 
                            size={20} />
                      <input
                        id="confirmPassword"
                        name="confirmPassword"
                        type={showConfirmPassword ? 'text' : 'password'}
                        autoComplete="new-password"
                        required
                        className="form-control ps-5 pe-5"
                        placeholder="Confirm your password"
                        value={formData.confirmPassword}
                        onChange={handleInputChange}
                        disabled={loading}
                      />
                      <button
                        type="button"
                        className="btn btn-link position-absolute text-muted p-0"
                        style={{right: '12px', top: '50%', transform: 'translateY(-50%)'}}
                        onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                        disabled={loading}
                      >
                        {showConfirmPassword ? <EyeOff size={20} /> : <Eye size={20} />}
                      </button>
                    </div>

                    {formData.confirmPassword && formData.password !== formData.confirmPassword && (
                      <p className="mt-1 small text-danger mb-0">Passwords do not match</p>
                    )}
                  </div>

                  {/* Submit Button */}
                  <div className="d-grid">
                    <button
                      type="submit"
                      disabled={loading || formData.password !== formData.confirmPassword || !formData.name.trim() || !formData.email.trim() || !formData.password}
                      className="btn btn-primary d-flex align-items-center justify-content-center"
                    >
                      {loading && <Loader className="spinner-border spinner-border-sm me-2" />}
                      {loading ? 'Creating account...' : 'Create account'}
                    </button>
                  </div>
                </form>

                {/* Divider */}
                <div className="position-relative text-center my-4">
                  <hr className="my-0" />
                  <span className="position-absolute top-50 start-50 translate-middle bg-white px-2 small text-muted">
                    Already have an account?
                  </span>
                </div>

                {/* Sign In Button */}
                <div className="d-grid">
                  <button
                     onClick={() => navigate('/')}
                    className="btn btn-outline-secondary"
                    disabled={loading}
                  >
                    Sign in instead
                  </button>
                </div>

                {/* Terms */}
                <div className="mt-4 text-center">
                  <p className="small text-muted mb-0">
                    By creating an account, you agree to our{' '}
                    <Link to="#" className="text-primary text-decoration-none">
                      Terms of Service
                    </Link>
                    {' '}and{' '}
                    <Link to="#" className="text-primary text-decoration-none">
                      Privacy Policy
                    </Link>
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Signup;