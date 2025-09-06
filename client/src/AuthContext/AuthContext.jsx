import React, { createContext, useContext, useState, useEffect } from 'react';

// services/api.js
const API_BASE_URL = process.env.REACT_APP_API_URL || 
  (process.env.NODE_ENV === 'production' 
    ? 'https://blog-app-7u5b.onrender.com/api'
    : 'http://localhost:4000/api');

const AuthContext = createContext();

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    checkAuthStatus();
  }, []);

  const checkAuthStatus = async () => {
    try {
      const token = localStorage.getItem('token');
      if (!token) {
        setLoading(false);
        return;
      }

      const response = await fetch(`${API_BASE_URL}/users/verify-token`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      if (response.ok) {
        const data = await response.json();
        setUser(data.user);
      } else {
        // Token is invalid, clear it
        localStorage.removeItem('token');
        localStorage.removeItem('user');
        setUser(null);
      }
    } catch (error) {
      console.error('Auth check failed:', error);
      localStorage.removeItem('token');
      localStorage.removeItem('user');
      setUser(null);
    } finally {
      setLoading(false);
    }
  };

  const login = async (email, password, rememberMe = false) => {
    try {
      const response = await fetch(`${API_BASE_URL}/users/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ email, password, rememberMe })
      });

      const data = await response.json();
      
      if (data.success) {
        localStorage.setItem('token', data.token);
        localStorage.setItem('user', JSON.stringify(data.user));
        setUser(data.user);
        return { success: true, user: data.user };
      } else {
        return { 
          success: false, 
          message: data.message,
          requiresVerification: data.requiresVerification 
        };
      }
    } catch (error) {
      console.error('Login error:', error);
      return { success: false, message: 'Login failed. Please try again.' };
    }
  };

  const signup = async (name, email, password) => {
    try {
      const response = await fetch(`${API_BASE_URL}/users/signup`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ name, email, password })
      });

      const data = await response.json();
      
      // Even if signup is successful, don't auto-login until email is verified
      // The backend returns a token but the user should verify email first
      if (data.success && data.verificationRequired) {
        // Don't set user in context yet, wait for email verification
        return {
          success: true,
          message: data.message,
          verificationRequired: true,
          email: email
        };
      }
      
      return data;
    } catch (error) {
      console.error('Signup error:', error);
      return { success: false, message: 'Registration failed. Please try again.' };
    }
  };

  // New method for email verification
  const verifyEmail = async (token) => {
    try {
      const response = await fetch(`${API_BASE_URL}/users/verify-email/${token}`);
      const data = await response.json();
      
      if (data.success) {
        // Now set the user and token after successful verification
        localStorage.setItem('token', data.token);
        localStorage.setItem('user', JSON.stringify(data.user));
        setUser(data.user);
        return { success: true, message: data.message, user: data.user };
      }
      
      return { success: false, message: data.message };
    } catch (error) {
      console.error('Email verification error:', error);
      return { success: false, message: 'Email verification failed.' };
    }
  };

  const logout = async () => {
    try {
      const token = localStorage.getItem('token');
      if (token) {
        // Send logout request to server
        await fetch(`${API_BASE_URL}/users/logout`, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ userId: user?._id })
        });
      }
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      // Always clear local state regardless of server response
      localStorage.removeItem('token');
      localStorage.removeItem('user');
      setUser(null);
    }
  };

  const forgotPassword = async (email) => {
    try {
      const response = await fetch(`${API_BASE_URL}/users/forgot-password`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ email })
      });

      const data = await response.json();
      return data;
    } catch (error) {
      console.error('Forgot password error:', error);
      return { success: false, message: 'Failed to send reset email' };
    }
  };

  const resetPassword = async (token, password) => {
    try {
      const response = await fetch(`${API_BASE_URL}/users/reset-password/${token}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ password })
      });

      const data = await response.json();
      return data;
    } catch (error) {
      console.error('Reset password error:', error);
      return { success: false, message: 'Failed to reset password' };
    }
  };

  const resendVerification = async (email) => {
    try {
      const response = await fetch(`${API_BASE_URL}/users/resend-verification`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ email })
      });

      const data = await response.json();
      return data;
    } catch (error) {
      console.error('Resend verification error:', error);
      return { success: false, message: 'Failed to resend verification email' };
    }
  };

  const updateProfile = async (userData) => {
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`${API_BASE_URL}/users/${user._id}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(userData)
      });

      const data = await response.json();
      if (data.success) {
        setUser(data.user);
        localStorage.setItem('user', JSON.stringify(data.user));
      }
      return data;
    } catch (error) {
      console.error('Update profile error:', error);
      return { success: false, message: 'Failed to update profile' };
    }
  };

  const changePassword = async (currentPassword, newPassword) => {
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`${API_BASE_URL}/users/${user._id}/change-password`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ currentPassword, newPassword })
      });

      const data = await response.json();
      return data;
    } catch (error) {
      console.error('Change password error:', error);
      return { success: false, message: 'Failed to change password' };
    }
  };

  const value = {
    user,
    loading,
    login,
    signup,
    logout,
    forgotPassword,
    resetPassword,
    resendVerification,
    updateProfile,
    changePassword,
    checkAuthStatus,
    verifyEmail // Add the new method
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};