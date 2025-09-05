import React from "react";
import Navbar from "../Navbar/Navbar"; // make sure you have Navbar component
import { Outlet } from "react-router-dom";

const Layout = () => {
  return (
    <div className="min-h-screen flex flex-col">
      <Navbar />
      <main className="flex-grow">
        <Outlet />
      </main>
    </div>
  );
};

export default Layout;
