import React, { useEffect, useState } from "react";
import { getAllBlogs } from "../../utils/blogApi";
import { Link } from "react-router-dom";
import BlogCard from "../../components/BlogCard/BlogCard"; // Import the BlogCard component

const BlogList = () => {
  const [blogs, setBlogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [filteredBlogs, setFilteredBlogs] = useState([]);

  useEffect(() => {
    loadBlogs();
  }, []);

  console.log("all blogs", getAllBlogs);

  useEffect(() => {
    // Filter blogs based on search term
    if (searchTerm.trim() === '') {
      setFilteredBlogs(blogs);
    } else {
      const filtered = blogs.filter(blog => 
        blog.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
        blog.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
        (blog.user?.name && blog.user.name.toLowerCase().includes(searchTerm.toLowerCase()))
      );
      setFilteredBlogs(filtered);
    }
  }, [blogs, searchTerm]);

  const loadBlogs = async () => {
    try {
      setLoading(true);
      setError(null);
      
      const response = await getAllBlogs();
      console.log('API Response:', response);
      
      if (response && response.blogs) {
        setBlogs(response.blogs);
      } else if (Array.isArray(response)) {
        // Handle case where API returns blogs array directly
        setBlogs(response);
      } else {
        setError('No blogs data received');
      }
    } catch (err) {
      console.error('Error loading blogs:', err);
      setError(err.message || 'Failed to load blogs');
    } finally {
      setLoading(false);
    }
  };

  const handleSearch = (e) => {
    e.preventDefault();
    // Search is handled by useEffect above
  };

  const clearSearch = () => {
    setSearchTerm('');
  };

  if (loading) {
    return (
      <div className="container mt-5">
        <div className="text-center">
          <div className="spinner-border text-primary" role="status">
            <span className="visually-hidden">Loading...</span>
          </div>
          <p className="mt-3">Loading blogs...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="container mt-5">
        <div className="alert alert-danger" role="alert">
          <h4 className="alert-heading">Error Loading Blogs</h4>
          <p>{error}</p>
          <button 
            className="btn btn-outline-danger"
            onClick={loadBlogs}
          >
            Try Again
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="container mt-4 mb-5">
      <div className="row justify-content-center">
        <div className="col-lg-10">
          {/* Header */}
          <div className="d-flex justify-content-between align-items-center mb-4">
            <div>
              <h2 className="fw-bold mb-1">All Blogs</h2>
              <p className="text-muted mb-0">
                {searchTerm ? `Search results for "${searchTerm}"` : 'Discover amazing stories from our community'}
              </p>
            </div>
            <div className="text-muted">
              {filteredBlogs.length} blog{filteredBlogs.length !== 1 ? 's' : ''}
            </div>
          </div>

          {/* Search Section */}
          <div className="card shadow-sm mb-4">
            <div className="card-body">
              <form onSubmit={handleSearch}>
                <div className="row g-3">
                  <div className="col-md-8">
                    <div className="position-relative">
                      <input
                        type="text"
                        className="form-control"
                        placeholder="Search blogs by title, content, or author..."
                        value={searchTerm}
                        onChange={(e) => setSearchTerm(e.target.value)}
                      />
                      {searchTerm && (
                        <button
                          type="button"
                          className="btn btn-sm position-absolute top-50 end-0 translate-middle-y me-2 p-0"
                          onClick={clearSearch}
                          style={{ background: 'none', border: 'none', fontSize: '1.2rem' }}
                        >
                          ×
                        </button>
                      )}
                    </div>
                  </div>
                  <div className="col-md-4">
                    <div className="d-flex gap-2">
                      <button type="button" className="btn btn-primary flex-grow-1">
                        <i className="bi bi-search me-2"></i>
                        Search ({filteredBlogs.length})
                      </button>
                      <Link to="/create-blog" className="btn btn-outline-primary">
                        Write Blog
                      </Link>
                    </div>
                  </div>
                </div>
              </form>
            </div>
          </div>

          {/* Blog List */}
          {filteredBlogs.length === 0 ? (
            <div className="card shadow-sm">
              <div className="card-body text-center py-5">
                <div className="mb-3">
                  <i className="bi bi-journal-x display-1 text-muted"></i>
                </div>
                <h3 className="fw-bold mb-2">
                  {searchTerm ? 'No blogs found' : 'No blogs available'}
                </h3>
                <p className="text-muted mb-4">
                  {searchTerm 
                    ? `No blogs match your search for "${searchTerm}". Try different keywords.`
                    : 'Be the first to write a blog and share your story!'}
                </p>
                <div className="d-flex justify-content-center gap-2">
                  {searchTerm && (
                    <button 
                      className="btn btn-outline-primary"
                      onClick={clearSearch}
                    >
                      Clear Search
                    </button>
                  )}
                  <Link to="/create-blog" className="btn btn-primary">
                    <i className="bi bi-plus-circle me-2"></i>
                    Write Your First Blog
                  </Link>
                </div>
              </div>
            </div>
          ) : (
            <div className="row">
              {filteredBlogs.map((blog) => (
                <BlogCard key={blog._id} blog={blog} />
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default BlogList;