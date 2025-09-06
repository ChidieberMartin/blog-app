import React, { createContext, useContext, useState, useEffect } from 'react';

// ✅ FIXED Updated API base URL to match your backend port and configuration
const API_BASE_URL = process.env.REACT_APP_API_URL || 
  (process.env.NODE_ENV === 'production' 
    ? 'https://blog-app-7u5b.onrender.com/api'  // ✅ Your production backend URL
    : 'http://localhost:4001/api');  // ✅ Fixed port from 4000 to 4001

const AuthContext = createContext();

// ✅ Default fetch configuration with proper CORS handling
const defaultFetchConfig = {
  headers: {
    'Content-Type': 'application/json',
  },
  credentials: 'include'  // ✅ Include credentials for CORS
};

// ✅ Helper function to handle API responses consistently
const handleResponse = async (response) => {
  const data = await response.json();
  
  if (!response.ok) {
    console.error('API Error:', {
      status: response.status,
      statusText: response.statusText,
      data: data
    });
    throw new Error(data.message || `HTTP ${response.status}: ${response.statusText}`);
  }
  
  return data;
};

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
        ...defaultFetchConfig,
        headers: {
          ...defaultFetchConfig.headers,
          'Authorization': `Bearer ${token}`
        }
      });

      if (response.ok) {
        const data = await handleResponse(response);
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
        ...defaultFetchConfig,
        method: 'POST',
        body: JSON.stringify({ email, password, rememberMe })
      });

      const data = await handleResponse(response);
      
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
      return { success: false, message: error.message || 'Login failed. Please try again.' };
    }
  };

  const signup = async (name, email, password) => {
    try {
      const response = await fetch(`${API_BASE_URL}/users/signup`, {
        ...defaultFetchConfig,
        method: 'POST',
        body: JSON.stringify({ name, email, password })
      });

      const data = await handleResponse(response);
      
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
      return { success: false, message: error.message || 'Registration failed. Please try again.' };
    }
  };

  // Email verification
  const verifyEmail = async (token) => {
    try {
      const response = await fetch(`${API_BASE_URL}/users/verify-email/${token}`, {
        ...defaultFetchConfig,
        method: 'GET'
      });
      
      const data = await handleResponse(response);
      
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
      return { success: false, message: error.message || 'Email verification failed.' };
    }
  };

  const logout = async () => {
    try {
      const token = localStorage.getItem('token');
      if (token) {
        // Send logout request to server
        await fetch(`${API_BASE_URL}/users/logout`, {
          ...defaultFetchConfig,
          method: 'POST',
          headers: {
            ...defaultFetchConfig.headers,
            'Authorization': `Bearer ${token}`
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
        ...defaultFetchConfig,
        method: 'POST',
        body: JSON.stringify({ email })
      });

      return await handleResponse(response);
    } catch (error) {
      console.error('Forgot password error:', error);
      return { success: false, message: error.message || 'Failed to send reset email' };
    }
  };

  const resetPassword = async (token, password) => {
    try {
      const response = await fetch(`${API_BASE_URL}/users/reset-password/${token}`, {
        ...defaultFetchConfig,
        method: 'POST',
        body: JSON.stringify({ password })
      });

      return await handleResponse(response);
    } catch (error) {
      console.error('Reset password error:', error);
      return { success: false, message: error.message || 'Failed to reset password' };
    }
  };

  const resendVerification = async (email) => {
    try {
      const response = await fetch(`${API_BASE_URL}/users/resend-verification`, {
        ...defaultFetchConfig,
        method: 'POST',
        body: JSON.stringify({ email })
      });

      return await handleResponse(response);
    } catch (error) {
      console.error('Resend verification error:', error);
      return { success: false, message: error.message || 'Failed to resend verification email' };
    }
  };

  const updateProfile = async (userData) => {
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`${API_BASE_URL}/users/${user._id}`, {
        ...defaultFetchConfig,
        method: 'PUT',
        headers: {
          ...defaultFetchConfig.headers,
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(userData)
      });

      const data = await handleResponse(response);
      if (data.success) {
        setUser(data.user);
        localStorage.setItem('user', JSON.stringify(data.user));
      }
      return data;
    } catch (error) {
      console.error('Update profile error:', error);
      return { success: false, message: error.message || 'Failed to update profile' };
    }
  };

  const changePassword = async (currentPassword, newPassword) => {
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`${API_BASE_URL}/users/${user._id}/change-password`, {
        ...defaultFetchConfig,
        method: 'PUT',
        headers: {
          ...defaultFetchConfig.headers,
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ currentPassword, newPassword })
      });

      return await handleResponse(response);
    } catch (error) {
      console.error('Change password error:', error);
      return { success: false, message: error.message || 'Failed to change password' };
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
    verifyEmail
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

// ✅ Export API base URL for debugging
export { API_BASE_URL };