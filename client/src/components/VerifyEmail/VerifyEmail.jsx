import React, { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { CheckCircle, AlertCircle, Loader, Mail, Home, ArrowLeft } from "lucide-react";
import { useAuth } from "../../AuthContext/AuthContext";

const API_BASE_URL = "http://localhost:4000/api";

const VerifyEmail = () => {
  const { token } = useParams();
  const navigate = useNavigate();
  const { checkAuthStatus, resendVerification } = useAuth();
  const [status, setStatus] = useState({ 
    loading: true, 
    success: false, 
    message: "",
    countdown: 3,
    userEmail: ""
  });

  useEffect(() => {
    if (!token) {
      setStatus({
        loading: false,
        success: false,
        message: "Invalid verification link. No token provided.",
        countdown: 0,
        userEmail: ""
      });
      return;
    }

    const verify = async () => {
      try {
        const response = await fetch(`${API_BASE_URL}/users/verify-email/${token}`);
        const data = await response.json();

        if (data.success) {
          // Save token and user data
          localStorage.setItem("token", data.token);
          if (data.user) {
            localStorage.setItem("user", JSON.stringify(data.user));
          }

          // Update auth context if available
          if (checkAuthStatus) {
            await checkAuthStatus();
          }

          setStatus({ 
            loading: false, 
            success: true, 
            message: data.message || "Email verified successfully!",
            countdown: 3,
            userEmail: data.user?.email || ""
          });

          // Start countdown and redirect
          let count = 3;
          const countdownInterval = setInterval(() => {
            count -= 1;
            setStatus(prev => ({ ...prev, countdown: count }));
            
            if (count === 0) {
              clearInterval(countdownInterval);
              navigate("/home", { replace: true });
            }
          }, 1000);

          return () => clearInterval(countdownInterval);

        } else {
          setStatus({ 
            loading: false, 
            success: false, 
            message: data.message || "Email verification failed",
            countdown: 0,
            userEmail: ""
          });
        }
      } catch (error) {
        console.error("Email verification error:", error);
        setStatus({ 
          loading: false, 
          success: false, 
          message: "Verification failed. Please check your internet connection and try again.",
          countdown: 0,
          userEmail: ""
        });
      }
    };

    verify();
  }, [token, navigate, checkAuthStatus]);

  const handleGoHome = () => {
    navigate("/home", { replace: true });
  };

  const handleGoBack = () => {
    navigate("/", { replace: true });
  };

  const handleResendVerification = async () => {
    if (!status.userEmail) {
      navigate("/resend-verification");
      return;
    }

    try {
      const result = await resendVerification(status.userEmail);
      if (result.success) {
        alert("Verification email sent successfully! Please check your inbox.");
      } else {
        alert(result.message || "Failed to send verification email");
      }
    } catch (error) {
      alert("Failed to send verification email. Please try again.");
    }
  };

  if (status.loading) {
    return (
      <div className="min-vh-100 bg-light d-flex flex-column justify-content-center py-5">
        <div className="container">
          <div className="row justify-content-center">
            <div className="col-md-6 col-lg-4">
              <div className="card shadow-lg border-0">
                <div className="card-body p-4 text-center">
                  <Loader className="mx-auto mb-3 text-primary" size={48} />
                  <div className="spinner-border text-primary mb-3" role="status">
                    <span className="visually-hidden">Loading...</span>
                  </div>
                  <h2 className="h4 fw-bold text-dark mb-3">Verifying Your Email</h2>
                  <p className="text-muted">Please wait while we verify your email address...</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  if (status.success) {
    return (
      <div className="min-vh-100 bg-light d-flex flex-column justify-content-center py-5">
        <div className="container">
          <div className="row justify-content-center">
            <div className="col-md-6 col-lg-4">
              <div className="card shadow-lg border-0">
                <div className="card-body p-4 text-center">
                  <CheckCircle className="mx-auto mb-3 text-success" size={48} />
                  <h2 className="h4 fw-bold text-dark mb-3">Email Verified!</h2>
                  <p className="text-muted mb-4">{status.message}</p>
                  
                  <div className="alert alert-success mb-4" role="alert">
                    <p className="mb-0">
                      Redirecting to your dashboard in {status.countdown} second{status.countdown !== 1 ? 's' : ''}...
                    </p>
                  </div>

                  <div className="d-grid gap-2">
                    <button
                      onClick={handleGoHome}
                      className="btn btn-primary d-flex align-items-center justify-content-center"
                    >
                      <Home className="me-2" size={20} />
                      Go to Dashboard Now
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // Error state
  return (
    <div className="min-vh-100 bg-light d-flex flex-column justify-content-center py-5">
      <div className="container">
        <div className="row justify-content-center">
          <div className="col-md-6 col-lg-4">
            <div className="card shadow-lg border-0">
              <div className="card-body p-4 text-center">
                <AlertCircle className="mx-auto mb-3 text-danger" size={48} />
                <h2 className="h4 fw-bold text-dark mb-3">Verification Failed</h2>
                <p className="text-muted mb-4">{status.message}</p>

                <div className="d-grid gap-2">
                  <button
                    onClick={handleResendVerification}
                    className="btn btn-primary d-flex align-items-center justify-content-center"
                  >
                    <Mail className="me-2" size={20} />
                    Resend Verification Email
                  </button>
                  <button
                    onClick={handleGoBack}
                    className="btn btn-outline-secondary d-flex align-items-center justify-content-center"
                  >
                    <ArrowLeft className="me-2" size={20} />
                    Back to Login
                  </button>
                </div>

                <div className="mt-4">
                  <p className="small text-muted">
                    Having trouble? Contact our support team for assistance.
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

export default VerifyEmail;