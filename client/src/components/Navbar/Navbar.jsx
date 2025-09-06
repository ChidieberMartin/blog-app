import React, { useState } from 'react';
import { User, Plus, LogOut, Home, BookOpen, Menu, X, Settings } from 'lucide-react';
import { useAuth } from '../../AuthContext/AuthContext';
import { useNavigate } from 'react-router-dom';
// import Logout from '../Logout/Logout';

const Header = () => {
  const { user, logout } = useAuth();
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [showUserMenu, setShowUserMenu] = useState(false);
  const navigate = useNavigate();
  console.log("Current User:", user);

  const handleLogout = async () => {
    await logout();
    navigate('/');
    setShowUserMenu(false);
    setIsMobileMenuOpen(false);
  };

  const navigation = [
    {
      name: 'Home',
      page: 'home',
      icon: Home,
      show: true
    },
   
    {
      name: 'My Blogs',
      page: 'home', // Added proper page route
      icon: BookOpen,
      show: !!user
    }
  ];

  const userMenuItems = [
    {
      name: 'Profile',
      page: 'profile',
      icon: User
    },
    {
      name: 'Settings',
      page: 'settings',
      icon: Settings
    }
  ];

  // Get current page from URL for active state
  const getCurrentPage = () => {
    const path = window.location.pathname;
    if (path === '/home' || path === '/') return 'home';
    if (path === '/home') return 'my-blogs';
    if (path === '/profile') return 'profile';
    if (path === '/settings') return 'settings';
    return '';
  };

  const currentPage = getCurrentPage();

  return (
    <header className="shadow-sm border-bottom sticky-top bg-white">
      <nav className="navbar navbar-expand-lg navbar-light bg-white">
        <div className="container">
          {/* Logo */}
          <button
            className="navbar-brand d-flex align-items-center border-0 bg-transparent p-0"
            onClick={() => navigate('/home-page')}
            style={{ textDecoration: 'none', color: 'inherit' }}
          >
            <BookOpen className="me-2 text-primary" size={28} />
            <strong>BlogSpace</strong>
          </button>

          {/* Mobile toggle button */}
          <button
            className="navbar-toggler"
            type="button"
            onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
          >
            {isMobileMenuOpen ? (
              <X className="bi bi-x-lg" size={24} />
            ) : (
              <Menu className="bi bi-list" size={24} />
            )}
          </button>

          {/* Desktop navigation */}
          <div className={`collapse navbar-collapse ${isMobileMenuOpen ? "show" : ""}`}>
            <ul className="navbar-nav me-auto mb-2 mb-lg-0">
              {navigation.filter(item => item.show).map((item) => {
                const Icon = item.icon;
                return (
                  <li className="nav-item" key={item.name}>
                    <button
                      className={`nav-link d-flex align-items-center ${
                        currentPage === item.page ? "active text-primary fw-bold" : ""
                      }`}
                      onClick={() => {
                        navigate(`/${item.page}`);
                        setIsMobileMenuOpen(false);
                      }}
                    >
                      <Icon className="me-1" size={16} />
                      {item.name}
                    </button>
                  </li>
                );
              })}
            </ul>

            {/* Right side user actions */}
            <div className="d-flex align-items-center">
              {user ? (
                <>
                  {/* Create Blog */}
                  <button
                    className="btn btn-primary me-3 d-flex align-items-center"
                    onClick={() => navigate('/create-blog')}
                  >
                    <Plus className="me-1" size={16} /> New Blog
                  </button>

                  {/* User dropdown */}
                  <div className="dropdown">
                    <button
                      className="btn btn-light dropdown-toggle d-flex align-items-center"
                      onClick={() => setShowUserMenu(!showUserMenu)}
                    >
                      <div className="rounded-circle bg-primary d-flex align-items-center justify-content-center me-2" style={{width: "32px", height: "32px"}}>
                        <User className="text-white" size={18} />
                      </div>
                      {user.name}
                    </button>

                    {showUserMenu && (
                      <ul className="dropdown-menu dropdown-menu-end show">
                        <li className="dropdown-item text-muted small">{user.email}</li>
                        <li><hr className="dropdown-divider" /></li>

                        {userMenuItems.map((item) => {
                          const Icon = item.icon;
                          return (
                            <li key={item.name}>
                              <button
                                className="dropdown-item d-flex align-items-center"
                                onClick={() => {
                                  navigate(`/${item.page}`);
                                  setShowUserMenu(false);
                                }}
                              >
                                <Icon className="me-2" size={16} /> {item.name}
                              </button>
                            </li>
                          );
                        })}

                        <li><hr className="dropdown-divider" /></li>
                        <li>
                          <button
                            className="dropdown-item text-danger d-flex align-items-center"
                            onClick={handleLogout}
                          >
                            <LogOut className="me-2" size={16} /> Logout
                          </button>
                        </li>
                      </ul>
                    )}
                  </div>
                </>
              ) : (
                <>
                  <button
                    className="btn btn-outline-secondary me-2"
                    onClick={() => navigate('/login')}
                  >
                    Login
                  </button>
                  <button
                    className="btn btn-primary"
                    onClick={() => navigate('/signup')}
                  >
                    Sign Up
                  </button>
                </>
              )}
            </div>
          </div>
        </div>
      </nav>

      {/* Overlay for user menu click outside */}
      {showUserMenu && (
        <div
          className="position-fixed top-0 start-0 w-100 h-100"
          style={{ zIndex: 10 }}
          onClick={() => setShowUserMenu(false)}
        />
      )}
    </header>
  );
};

export default Header;