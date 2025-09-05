import React from "react";
import { NavLink, useNavigate } from "react-router-dom";

const Navbar = () => {
    const navigate = useNavigate();

    const handleLogout = () => {
        localStorage.removeItem("token"); // clear auth token
        navigate("/"); // redirect back to login
    };

    return (
        <nav className="navbar navbar-expand-lg navbar-dark bg-dark">
            <div className="container-fluid">
                {/* Brand / Logo */}
                <NavLink className="navbar-brand" to="/home">
                    MyBlog
                </NavLink>

                {/* Toggle button for mobile */}
                <button
                    className="navbar-toggler"
                    type="button"
                    data-bs-toggle="collapse"
                    data-bs-target="#navbarNav"
                    aria-controls="navbarNav"
                    aria-expanded="false"
                    aria-label="Toggle navigation"
                >
                    <span className="navbar-toggler-icon"></span>
                </button>

                {/* Navbar Links */}
                <div className="collapse navbar-collapse" id="navbarNav">
                    <ul className="navbar-nav me-auto mb-2 mb-lg-0">
                        <li className="nav-item">
                            <NavLink
                                className={({ isActive }) =>
                                    `nav-link ${isActive ? "active fw-bold" : ""}`
                                }
                                to="/home"
                            >
                                Home
                            </NavLink>
                        </li>
                        <li className="nav-item">
                            <NavLink
                                className={({ isActive }) =>
                                    `nav-link ${isActive ? "active fw-bold" : ""}`
                                }
                                to="/home-page"
                            >
                                Blog
                            </NavLink>
                        </li>
                        <li className="nav-item">
                            <NavLink
                                className={({ isActive }) =>
                                    `nav-link ${isActive ? "active fw-bold" : ""}`
                                }
                                to="/create-blog"
                            >
                                Create Blog
                            </NavLink>
                        </li>
                    </ul>

                    {/* Logout button */}
                    <button className="btn btn-danger" onClick={handleLogout}>
                        Logout
                    </button>
                </div>
            </div>
        </nav>
    );
};

export default Navbar;
