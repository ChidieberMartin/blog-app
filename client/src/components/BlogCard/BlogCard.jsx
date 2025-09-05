import React from 'react';
import { Link } from 'react-router-dom';

const BlogCard = ({ blog }) => {
  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric'
    });
  };

  return (
    <div className="col-md-6 col-lg-4 mb-4">
      <div className="card h-100 shadow-sm">
        {/* Blog Image */}
        {blog.image && (
          <div style={{ height: '200px', overflow: 'hidden' }}>
            <img 
              src={blog.image} 
              className="card-img-top w-100 h-100"
              style={{ objectFit: 'cover' }}
              alt={blog.title}
              onError={(e) => {
                e.target.style.display = 'none';
              }}
            />
          </div>
        )}
        
        <div className="card-body d-flex flex-column">
          {/* Title */}
          <h5 className="card-title fw-bold">{blog.title}</h5>
          
          {/* Description */}
          <p className="card-text text-muted flex-grow-1">
            {blog.description?.length > 32 
              ? `${blog.description.slice(0, 32)}...` 
              : blog.description}
          </p>
          
          {/* Author and Date */}
          <div className="d-flex align-items-center text-muted small mb-3">
            <div className="rounded-circle bg-primary text-white d-flex align-items-center justify-content-center me-3"
                 style={{ width: '32px', height: '32px', fontSize: '0.8rem' }}>
              {blog.user?.name?.charAt(0).toUpperCase() || 'U'}
            </div>
            <div className="flex-grow-1">
              <div className="fw-medium text-dark">
                {blog.user && blog.user.name ? blog.user.name : 'Unknown Author'}
              </div>
              {blog.createdAt && (
                <div className="text-muted">
                  {formatDate(blog.createdAt)}
                </div>
              )}
            </div>
          </div>
          
          {/* Action Button */}
          <div className="mt-auto">
            <Link 
              to={`/blogs/${blog._id}`} 
              className="btn btn-primary w-100"
            >
              <i className="bi bi-eye me-2"></i>
              Read Full Blog
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
};

export default BlogCard;