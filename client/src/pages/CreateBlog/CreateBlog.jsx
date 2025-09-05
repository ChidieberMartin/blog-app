import React, { useState } from 'react';
import { createBlog } from '../../utils/blogApi';
import { useAuth } from '../../AuthContext/AuthContext';
import { useNavigate } from 'react-router-dom';

const CreateBlog = () => {
  const { user } = useAuth();
  const [formData, setFormData] = useState({
    title: '',
    description: '',
    image: ''
  });
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState({ text: '', type: '' });
  const [preview, setPreview] = useState(false);
  const navigate = useNavigate();

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
  };

  const validateForm = () => {
    if (!formData.title.trim()) {
      return { isValid: false, message: 'Title is required' };
    }
    if (!formData.description.trim()) {
      return { isValid: false, message: 'Description is required' };
    }
    if (formData.title.length > 200) {
      return { isValid: false, message: 'Title must be less than 200 characters' };
    }
    if (formData.description.length > 500) {
      return { isValid: false, message: 'Description must be less than 500 characters' };
    }
    return { isValid: true };
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setMessage({ text: '', type: '' });

    const validation = validateForm();
    if (!validation.isValid) {
      setMessage({ text: validation.message, type: 'error' });
      setLoading(false);
      return;
    }

    try {
      const blogData = {
        title: formData.title.trim(),
        description: formData.description.trim(),
        image: formData.image.trim(),
        user: user._id
      };

      const response = await createBlog(blogData);

      if (response && response.blog) {
        setMessage({
          text: 'Blog created successfully!',
          type: 'success'
        });

        setFormData({
          title: '',
          description: '',
          image: ''
        });

        setTimeout(() => {
          navigate('/home');
        }, 2000);
      } else {
        setMessage({
          text: response?.message || 'Failed to create blog',
          type: 'error'
        });
      }
    } catch (error) {
      console.error('Create blog error:', error);
      setMessage({
        text: error.message || 'Failed to create blog. Please try again.',
        type: 'error'
      });
    } finally {
      setLoading(false);
    }
  };

  const handleCancel = () => {
    if (window.confirm('Are you sure you want to cancel? All unsaved changes will be lost.')) {
      navigate('/home');
    }
  };

  if (!user) {
    return (
      <div className="container mt-5">
        <div className="row justify-content-center">
          <div className="col-md-6">
            <div className="alert alert-warning text-center">
              <h4>Authentication Required</h4>
              <p>You must be logged in to create a blog.</p>
              <button
                className="btn btn-primary me-2"
                onClick={() => navigate('/')}
              >
                Login
              </button>
              <button
                className="btn btn-outline-primary"
                onClick={() => navigate('/signup')}
              >
                Sign Up
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="container mt-4 mb-5">
      <div className="row justify-content-center">
        <div className="col-lg-8">
          <div className="d-flex justify-content-between align-items-center mb-4">
            <div>
              <h2 className="fw-bold mb-1">Create New Blog</h2>
              <p className="text-muted mb-0">Share your story with the world</p>
            </div>
            <div className="d-flex gap-2">
              <button
                className="btn btn-outline-secondary"
                onClick={() => setPreview(!preview)}
              >
                {preview ? 'Edit' : 'Preview'}
              </button>
            </div>
          </div>

          {message.text && (
            <div className={`alert ${message.type === 'error' ? 'alert-danger' : 'alert-success'} alert-dismissible`} role="alert">
              {message.text}
              <button
                type="button"
                className="btn-close"
                onClick={() => setMessage({ text: '', type: '' })}
                aria-label="Close"
              ></button>
            </div>
          )}

          {!preview ? (
            <div className="card shadow-sm">
              <div className="card-body">
                <div className="mb-4">
                  <label htmlFor="title" className="form-label fw-semibold">
                    Blog Title <span className="text-danger">*</span>
                  </label>
                  <input
                    type="text"
                    className="form-control form-control-lg"
                    id="title"
                    name="title"
                    placeholder="Enter an engaging title for your blog"
                    value={formData.title}
                    onChange={handleInputChange}
                    maxLength={200}
                    required
                  />
                  <div className="form-text">
                    {formData.title.length}/200 characters
                  </div>
                </div>

                <div className="mb-4">
                  <label htmlFor="description" className="form-label fw-semibold">
                    Blog Description <span className="text-danger">*</span>
                  </label>
                  <textarea
                    className="form-control"
                    id="description"
                    name="description"
                    rows={3}
                    placeholder="Write a brief description of your blog"
                    value={formData.description}
                    onChange={handleInputChange}
                    maxLength={500}
                    required
                  />
                  <div className="form-text">
                    {formData.description.length}/500 characters
                  </div>
                </div>

                <div className="mb-4">
                  <label htmlFor="image" className="form-label fw-semibold">
                    Featured Image URL
                  </label>
                  <input
                    type="url"
                    className="form-control"
                    id="image"
                    name="image"
                    placeholder="https://example.com/image.jpg"
                    value={formData.image}
                    onChange={handleInputChange}
                  />
                </div>

                <div className="d-flex justify-content-between">
                  <button
                    type="button"
                    className="btn btn-outline-secondary"
                    onClick={handleCancel}
                    disabled={loading}
                  >
                    Cancel
                  </button>

                  <div className="d-flex gap-2">
                    <button
                      type="submit"
                      className="btn btn-primary"
                      onClick={handleSubmit}
                      disabled={loading || !formData.title || !formData.description}
                    >
                      {loading ? (
                        <>
                          <span className="spinner-border spinner-border-sm me-2" role="status"></span>
                          Creating...
                        </>
                      ) : (
                        'Publish Blog'
                      )}
                    </button>
                  </div>
                </div>
              </div>
            </div>
          ) : (
            <div className="card shadow-sm">
              <div className="card-header bg-light">
                <div className="d-flex justify-content-between align-items-center">
                  <h5 className="mb-0">Blog Preview</h5>
                  <button
                    className="btn btn-sm btn-outline-secondary"
                    onClick={() => setPreview(false)}
                  >
                    Back to Edit
                  </button>
                </div>
              </div>

              <div className="card-body">
                <div className="mb-4">
                  <h1 className="display-5 fw-bold mb-3">{formData.title || 'Blog Title'}</h1>
                  <div className="d-flex align-items-center text-muted mb-3">
                    <div className="rounded-circle bg-primary text-white d-flex align-items-center justify-content-center me-3"
                         style={{ width: '40px', height: '40px' }}>
                      {user.name?.charAt(0).toUpperCase() || 'U'}
                    </div>
                    <div>
                      <div className="fw-medium text-dark">{user.name}</div>
                      <small>Just now</small>
                    </div>
                  </div>
                  {formData.description && (
                    <p className="fs-5 text-muted">{formData.description}</p>
                  )}
                </div>

                {formData.image && (
                  <div className="text-center mb-4">
                    <img
                      src={formData.image}
                      alt={formData.title || 'Featured image'}
                      className="img-fluid rounded"
                      style={{ maxHeight: '400px' }}
                      onError={(e) => { e.target.style.display = 'none'; }}
                    />
                  </div>
                )}

                <div className="mt-4 pt-4 border-top text-center">
                  <button
                    className="btn btn-primary me-3"
                    onClick={handleSubmit}
                    disabled={loading || !formData.title || !formData.description}
                  >
                    {loading ? (
                      <>
                        <span className="spinner-border spinner-border-sm me-2" role="status"></span>
                        Publishing...
                      </>
                    ) : (
                      'Publish Blog'
                    )}
                  </button>

                  <button
                    className="btn btn-outline-secondary"
                    onClick={() => setPreview(false)}
                  >
                    Continue Editing
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default CreateBlog;
