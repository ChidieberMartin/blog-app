import React, { useEffect, useState } from "react";
import { useParams, Link, useNavigate } from "react-router-dom";
import { getBlogById, getAllBlogs } from "../../utils/blogApi";

const BlogDetails = () => {
  const { id } = useParams();
  const navigate = useNavigate();

  const [blog, setBlog] = useState(null);
  const [blogs, setBlogs] = useState([]);

  useEffect(() => {
  console.log("Blog data:", blog);
  }, [blog]);


  useEffect(() => {
    // Load current blog
    getBlogById(id)
      .then((res) => setBlog(res.blog))
      .catch((err) => console.error(err));

    // Load all blogs for navigation
    getAllBlogs()
      .then((res) => {
        if (res && res.blogs) {
          setBlogs(res.blogs);
        }
      })
      .catch((err) => console.error(err));
  }, [id]);

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleDateString("en-US", {
      year: "numeric",
      month: "short",
      day: "numeric",
    });
  };

  if (!blog) return <p className="text-center mt-5">Loading...</p>;

  // Find current blog index
  const currentIndex = blogs.findIndex((b) => b._id === blog._id);
  const prevBlog = currentIndex > 0 ? blogs[currentIndex - 1] : null;
  const nextBlog =
    currentIndex !== -1 && currentIndex < blogs.length - 1
      ? blogs[currentIndex + 1]
      : null;

  return (
    <div className="container mt-4 mb-5">
      {/* Sticky Back Button */}
      <div
        className="position-sticky top-0 bg-white py-2 mb-3 border-bottom"
        style={{ zIndex: 1000 }}
      >
        <Link to="/home" className="btn btn-outline-secondary">
          <i className="bi bi-arrow-left me-2"></i>
          Back to Blogs
        </Link>
      </div>

      {/* Blog Details */}
      <h1 className="fw-bold">{blog.title}</h1>

      {blog.image && (
        <img
          src={blog.image}
          alt={blog.title}
          className="img-fluid my-4 rounded shadow-sm"
        />
      )}

      <p className="lead">{blog.description}</p>

      <div className="mt-3 mb-5">
        <div className="fw-medium">
          {blog.user && blog.user.name ? blog.user.name : "Unknown Author"}
        </div>
        {blog.createdAt && (
          <div className="text-muted">{formatDate(blog.createdAt)}</div>
        )}
      </div>

      {/* Navigation Buttons */}
      <div className="d-flex justify-content-between mt-4">
        {prevBlog ? (
          <button
            className="btn btn-outline-primary"
            onClick={() => navigate(`/blogs/${prevBlog._id}`)}
          >
            <i className="bi bi-arrow-left me-2"></i> Previous
          </button>
        ) : (
          <div></div>
        )}

        {nextBlog && (
          <button
            className="btn btn-outline-primary"
            onClick={() => navigate(`/blogs/${nextBlog._id}`)}
          >
            Next <i className="bi bi-arrow-right ms-2"></i>
          </button>
        )}
      </div>
    </div>
  );
};

export default BlogDetails;
