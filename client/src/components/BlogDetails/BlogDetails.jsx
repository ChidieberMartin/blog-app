import React, { useEffect, useState } from "react";
import { useParams, Link, useNavigate } from "react-router-dom";
import { getBlogById, getAllBlogs, toggleLike, shareBlog } from "../../utils/blogApi";
import CommentsSection from "../CommentsSection/CommentsSection";
import ShareModal from "../ShareModal/ShareModal";

const BlogDetails = () => {
  const { id } = useParams();
  const navigate = useNavigate();

  const [blog, setBlog] = useState(null);
  const [blogs, setBlogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  
  // Social interaction states
  const [isLiked, setIsLiked] = useState(false);
  const [likesCount, setLikesCount] = useState(0);
  const [sharesCount, setSharesCount] = useState(0);
  const [showShareModal, setShowShareModal] = useState(false);
  const [isProcessing, setIsProcessing] = useState(false);

  const isLoggedIn = !!localStorage.getItem('token');

  useEffect(() => {
    console.log("Blog data:", blog);
  }, [blog]);

  useEffect(() => {
    loadBlogData();
  }, [id]);

  const loadBlogData = async () => {
    try {
      setLoading(true);
      setError(null);

      // Load current blog
      const blogResponse = await getBlogById(id);
      if (blogResponse && blogResponse.blog) {
        setBlog(blogResponse.blog);
        setIsLiked(blogResponse.blog.isLikedByUser || false);
        setLikesCount(blogResponse.blog.likesCount || 0);
        setSharesCount(blogResponse.blog.sharesCount || 0);
      } else {
        setError("Blog not found");
      }

      // Load all blogs for navigation
      const blogsResponse = await getAllBlogs();
      if (blogsResponse && blogsResponse.blogs) {
        setBlogs(blogsResponse.blogs);
      }
    } catch (err) {
      console.error("Error loading blog:", err);
      setError(err.message || "Failed to load blog");
    } finally {
      setLoading(false);
    }
  };

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleDateString("en-US", {
      year: "numeric",
      month: "short",
      day: "numeric",
    });
  };

  const formatCount = (count) => {
    if (count >= 1000000) {
      return (count / 1000000).toFixed(1) + 'M';
    } else if (count >= 1000) {
      return (count / 1000).toFixed(1) + 'K';
    }
    return count.toString();
  };

  const handleLike = async () => {
    if (!isLoggedIn) {
      alert('Please login to like blogs');
      return;
    }
    
    if (isProcessing) return;
    
    try {
      setIsProcessing(true);
      const response = await toggleLike(blog._id);
      
      setIsLiked(response.isLiked);
      setLikesCount(response.likesCount);
    } catch (error) {
      console.error('Error toggling like:', error);
      alert(error.message || 'Failed to like blog');
    } finally {
      setIsProcessing(false);
    }
  };

  const handleShare = async (shareMessage = '') => {
    if (!isLoggedIn) {
      alert('Please login to share blogs');
      return;
    }
    
    if (isProcessing) return;
    
    try {
      setIsProcessing(true);
      const response = await shareBlog(blog._id, shareMessage);
      
      setSharesCount(response.sharesCount);
      setShowShareModal(false);
      
      // Show success message
      alert('Blog shared successfully!');
    } catch (error) {
      console.error('Error sharing blog:', error);
      alert(error.message || 'Failed to share blog');
    } finally {
      setIsProcessing(false);
    }
  };

  if (loading) {
    return (
      <div className="container mt-5">
        <div className="text-center">
          <div className="spinner-border text-primary" role="status">
            <span className="visually-hidden">Loading...</span>
          </div>
          <p className="mt-3">Loading blog...</p>
        </div>
      </div>
    );
  }

  if (error || !blog) {
    return (
      <div className="container mt-5">
        <div className="alert alert-danger" role="alert">
          <h4 className="alert-heading">Error</h4>
          <p>{error || "Blog not found"}</p>
          <button 
            className="btn btn-outline-danger me-2"
            onClick={loadBlogData}
          >
            Try Again
          </button>
          <Link to="/home" className="btn btn-primary">
            Back to Blogs
          </Link>
        </div>
      </div>
    );
  }

  // Find current blog index for navigation
  const currentIndex = blogs.findIndex((b) => b._id === blog._id);
  const prevBlog = currentIndex > 0 ? blogs[currentIndex - 1] : null;
  const nextBlog =
    currentIndex !== -1 && currentIndex < blogs.length - 1
      ? blogs[currentIndex + 1]
      : null;

  return (
    <>
      <div className="container mt-4 mb-5">
        {/* Sticky Back Button */}
        <div
          className="position-sticky top-0 bg-white py-2 mb-4 border-bottom"
          style={{ zIndex: 1000 }}
        >
          <div className="d-flex justify-content-between align-items-center">
            <Link to="/home" className="btn btn-outline-secondary">
              <i className="bi bi-arrow-left me-2"></i>
              Back to Blogs
            </Link>
            
            {/* Social interaction buttons */}
            <div className="d-flex gap-2">
              <button
                className={`btn ${isLiked ? 'btn-danger' : 'btn-outline-danger'}`}
                onClick={handleLike}
                disabled={isProcessing}
                title={isLiked ? 'Unlike' : 'Like'}
              >
                <i className={`bi ${isLiked ? 'bi-heart-fill' : 'bi-heart'} me-1`}></i>
                {formatCount(likesCount)}
              </button>

              <button
                className="btn btn-outline-primary"
                onClick={() => setShowShareModal(true)}
                disabled={isProcessing}
                title="Share"
              >
                <i className="bi bi-share me-1"></i>
                {formatCount(sharesCount)}
              </button>
            </div>
          </div>
        </div>

        <div className="row justify-content-center">
          <div className="col-lg-8">
            {/* Blog Header */}
            <div className="mb-4">
              <h1 className="fw-bold display-6 mb-3">{blog.title}</h1>

              {/* Author and Date Info */}
              <div className="d-flex align-items-center mb-4">
                <div className="rounded-circle bg-primary text-white d-flex align-items-center justify-content-center me-3"
                     style={{ width: '50px', height: '50px', fontSize: '1.2rem' }}>
                  {blog.user?.name?.charAt(0).toUpperCase() || 'U'}
                </div>
                <div className="flex-grow-1">
                  <div className="fw-medium fs-5">
                    {blog.user && blog.user.name ? blog.user.name : "Unknown Author"}
                  </div>
                  {blog.createdAt && (
                    <div className="text-muted">
                      <i className="bi bi-calendar3 me-1"></i>
                      Published on {formatDate(blog.createdAt)}
                    </div>
                  )}
                </div>
              </div>

              {/* Social Stats Bar */}
              <div className="card mb-4">
                <div className="card-body py-3">
                  <div className="row text-center">
                    <div className="col-4">
                      <div className="d-flex align-items-center justify-content-center">
                        <i className="bi bi-heart-fill text-danger me-2"></i>
                        <span className="fw-medium">{formatCount(likesCount)}</span>
                        <span className="text-muted ms-1">likes</span>
                      </div>
                    </div>
                    <div className="col-4">
                      <div className="d-flex align-items-center justify-content-center">
                        <i className="bi bi-chat-dots text-primary me-2"></i>
                        <span className="fw-medium">{formatCount(blog.commentsCount || 0)}</span>
                        <span className="text-muted ms-1">comments</span>
                      </div>
                    </div>
                    <div className="col-4">
                      <div className="d-flex align-items-center justify-content-center">
                        <i className="bi bi-share text-success me-2"></i>
                        <span className="fw-medium">{formatCount(sharesCount)}</span>
                        <span className="text-muted ms-1">shares</span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Blog Image */}
            {blog.image && (
              <div className="mb-4">
                <img
                  src={blog.image}
                  alt={blog.title}
                  className="img-fluid rounded shadow-sm w-100"
                  style={{ maxHeight: '500px', objectFit: 'cover' }}
                />
              </div>
            )}

            {/* Blog Content */}
            <div className="mb-5">
              <div className="fs-5 lh-base" style={{ whiteSpace: 'pre-line' }}>
                {blog.description}
              </div>
            </div>

            {/* Social Action Buttons */}
            <div className="card mb-5">
              <div className="card-body">
                <div className="d-flex justify-content-center gap-3">
                  <button
                    className={`btn ${isLiked ? 'btn-danger' : 'btn-outline-danger'} btn-lg`}
                    onClick={handleLike}
                    disabled={isProcessing}
                  >
                    <i className={`bi ${isLiked ? 'bi-heart-fill' : 'bi-heart'} me-2`}></i>
                    {isLiked ? 'Liked' : 'Like'} ({formatCount(likesCount)})
                  </button>

                  <button
                    className="btn btn-outline-primary btn-lg"
                    onClick={() => document.querySelector('.comments-section').scrollIntoView({ behavior: 'smooth' })}
                  >
                    <i className="bi bi-chat-dots me-2"></i>
                    Comment ({formatCount(blog.commentsCount || 0)})
                  </button>

                  <button
                    className="btn btn-outline-success btn-lg"
                    onClick={() => setShowShareModal(true)}
                    disabled={isProcessing}
                  >
                    <i className="bi bi-share me-2"></i>
                    Share ({formatCount(sharesCount)})
                  </button>
                </div>
              </div>
            </div>

            {/* Comments Section */}
            <CommentsSection 
              blogId={blog._id} 
              initialCommentsCount={blog.commentsCount || 0}
            />

            {/* Navigation Buttons */}
            <div className="d-flex justify-content-between mt-5 pt-4 border-top">
              {prevBlog ? (
                <div className="text-start" style={{ maxWidth: '45%' }}>
                  <p className="text-muted small mb-1">
                    <i className="bi bi-arrow-left me-1"></i>
                    Previous Post
                  </p>
                  <button
                    className="btn btn-link p-0 text-start fw-medium"
                    onClick={() => navigate(`/blogs/${prevBlog._id}`)}
                    style={{ textDecoration: 'none' }}
                  >
                    {prevBlog.title.length > 50 ? `${prevBlog.title.slice(0, 50)}...` : prevBlog.title}
                  </button>
                </div>
              ) : (
                <div></div>
              )}

              {nextBlog && (
                <div className="text-end" style={{ maxWidth: '45%' }}>
                  <p className="text-muted small mb-1">
                    Next Post
                    <i className="bi bi-arrow-right ms-1"></i>
                  </p>
                  <button
                    className="btn btn-link p-0 text-end fw-medium"
                    onClick={() => navigate(`/blogs/${nextBlog._id}`)}
                    style={{ textDecoration: 'none' }}
                  >
                    {nextBlog.title.length > 50 ? `${nextBlog.title.slice(0, 50)}...` : nextBlog.title}
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Share Modal */}
      {showShareModal && (
        <ShareModal
          blog={blog}
          onShare={handleShare}
          onClose={() => setShowShareModal(false)}
          isProcessing={isProcessing}
        />
      )}
    </>
  );
};

export default BlogDetails;