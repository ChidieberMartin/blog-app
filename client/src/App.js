import React from 'react';
import { Routes, Route } from "react-router-dom";
import { AuthProvider } from './AuthContext/AuthContext';
import Login from './pages/Login/Login';
import Signup from './pages/Signup/Signup';
import BlogList from "./pages/BlogList/BlogList";
import BlogDetails from "./components/BlogDetails/BlogDetails";
import Layout from './components/Layout/Layout';
import Homepage from './pages/Homepage/Homepage';
import CreateBlog from './pages/CreateBlog/CreateBlog';
import VerifyEmail from './components/VerifyEmail/VerifyEmail';
import PrivateRoute from './components/PrivateRoute/PrivateRoute';
import NotFoundpage from './pages/NotFound/NotFoundpage';

const App = () => {
  const token = localStorage.getItem("token");

  return (
    <AuthProvider>
      <Routes>
        {/* Public routes */}
        <Route path="/login" element={<Login />} />
        <Route path="/signup" element={<Signup />} />
        <Route path="/verify-email/:token" element={<VerifyEmail />} />
        <Route path="/" element={<Homepage />} />

        {/* Protected routes with Layout */}
        <Route element={<Layout />}>
          <Route 
            path="/home" 
            element={
              <PrivateRoute>
                <BlogList />
              </PrivateRoute>
            } 
          />
          <Route 
            path="/create-blog" 
            element={
              <PrivateRoute>
                <CreateBlog token={token} />
              </PrivateRoute>
            } 
          />
          <Route 
            path="/blogs/:id" 
            element={
              <PrivateRoute>
                <BlogDetails />
              </PrivateRoute>
            } 
          />
        </Route>

        {/* Catch-all route */}
        <Route path="*" element={<NotFoundpage/>} />
      </Routes>
    </AuthProvider>
  );
};

export default App;