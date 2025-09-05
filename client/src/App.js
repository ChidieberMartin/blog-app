import React from 'react';
import {Routes, Route } from "react-router-dom";
import { AuthProvider } from './AuthContext/AuthContext';
import Login from './pages/Login/Login';
import Signup from './pages/Signup/Signup';
import BlogList from "./pages/BlogList/BlogList";
import BlogDetails from "./components/BlogDetails/BlogDetails";
import BlogCard from "./components/BlogCard/BlogCard";
import Layout from './components/Layout/Layout'; // import layout
import Homepage from'./pages/Homepage/Homepage';
import CreateBlog from'./pages/CreateBlog/CreateBlog'
import Headers from'./components/Headers/Header'
import VerifyEmail from './components/VerifyEmail/VerifyEmail';



const App = () => {
  const token = localStorage.getItem("token");

  return (
      <AuthProvider>
        <Routes>
          {/* Public routes */}
          <Route path="/" element={<Login />} />
          <Route path="/signup" element={<Signup />} />
          <Route path="/verify-email/:token" element={<VerifyEmail/>} />
          <Route path="/home-page" element={<Homepage />} />
          <Route path="/head" element={<Headers/>} />
          <Route path="/card" element={<BlogCard/>} />

          {/* Protected routes with Navbar */}
          <Route element={<Layout />}>
            <Route path="/home" element={<BlogList />} />
            <Route path="/create-blog" element={<CreateBlog token={token} />} />
            <Route path="/blogs/:id" element={<BlogDetails />} />
          </Route>

          {/* Catch-all */}
          <Route path="*" element={<div>404 Not Found</div>} />
        </Routes>
      </AuthProvider>
  );
};

export default App;
