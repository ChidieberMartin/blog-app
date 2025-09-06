import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Home, ArrowLeft, BookOpen, Search } from 'lucide-react';
import './NotFound.css';

const NotFound = () => {
  const navigate = useNavigate();

  const handleGoHome = () => {
    navigate('/');
  };

  const handleGoBack = () => {
    navigate(-1);
  };

  return (
    <div className="notfound-container min-vh-100 d-flex align-items-center justify-content-center bg-light">
      <div className="container">
        <div className="row justify-content-center">
          <div className="col-lg-8 col-xl-6">
            <div className="text-center">
              {/* 404 Number */}
              <div className="mb-4">
                <h1 className="notfound-number display-1 fw-bold text-primary mb-0">
                  404
                </h1>
              </div>

              {/* Icon */}
              <div className="mb-4">
                <div className="notfound-icon bg-primary bg-opacity-10 rounded-circle d-inline-flex align-items-center justify-content-center mb-3">
                  <Search className="text-primary" size={50} />
                </div>
              </div>

              {/* Main Message */}
              <h2 className="h1 fw-bold mb-3">Page Not Found</h2>
              <p className="lead text-muted mb-4">
                Oops! The page you're looking for doesn't exist. It might have been moved, deleted, or you entered the wrong URL.
              </p>

              {/* Suggestions */}
              <div className="notfound-suggestions bg-white rounded-4 shadow-sm p-4 mb-4 text-start">
                <h5 className="fw-bold mb-3">Here's what you can try:</h5>
                <ul className="list-unstyled">
                  <li className="d-flex align-items-center mb-2">
                    <div className="notfound-step bg-primary bg-opacity-10 rounded-circle d-flex align-items-center justify-content-center me-3">
                      <span className="text-primary fw-bold small">1</span>
                    </div>
                    Check the URL for any typos or errors
                  </li>
                  <li className="d-flex align-items-center mb-2">
                    <div className="notfound-step bg-primary bg-opacity-10 rounded-circle d-flex align-items-center justify-content-center me-3">
                      <span className="text-primary fw-bold small">2</span>
                    </div>
                    Go back to the previous page
                  </li>
                  <li className="d-flex align-items-center mb-2">
                    <div className="notfound-step bg-primary bg-opacity-10 rounded-circle d-flex align-items-center justify-content-center me-3">
                      <span className="text-primary fw-bold small">3</span>
                    </div>
                    Visit our homepage to start fresh
                  </li>
                  <li className="d-flex align-items-center">
                    <div className="notfound-step bg-primary bg-opacity-10 rounded-circle d-flex align-items-center justify-content-center me-3">
                      <span className="text-primary fw-bold small">4</span>
                    </div>
                    Contact us if you think this is an error
                  </li>
                </ul>
              </div>

              {/* Action Buttons */}
              <div className="d-flex justify-content-center gap-3 flex-wrap mb-4">
                <button 
                  className="notfound-btn btn btn-primary btn-lg px-4 py-2 d-flex align-items-center"
                  onClick={handleGoHome}
                >
                  <Home className="me-2" size={20} />
                  Go to Homepage
                </button>
                <button 
                  className="notfound-btn btn btn-outline-primary btn-lg px-4 py-2 d-flex align-items-center"
                  onClick={handleGoBack}
                >
                  <ArrowLeft className="me-2" size={20} />
                  Go Back
                </button>
              </div>

              {/* Brand Footer */}
              <div className="pt-4 border-top">
                <div className="d-flex align-items-center justify-content-center text-muted">
                  <BookOpen className="me-2 text-primary" size={20} />
                  <span className="small">
                    Return to <strong className="text-primary">BlogSpace</strong> - Your stories matter
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Background Decoration */}
      <div className="notfound-bg position-fixed top-0 start-0 w-100 h-100">
        <div className="notfound-circle notfound-circle-1"></div>
        <div className="notfound-circle notfound-circle-2"></div>
        <div className="notfound-circle notfound-circle-3"></div>
      </div>
    </div>
  );
};

export default NotFound;