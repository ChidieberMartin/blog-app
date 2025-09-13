import React, { useState } from 'react';

const ShareModal = ({ blog, onShare, onClose, isProcessing }) => {
  const [shareMessage, setShareMessage] = useState('');
  const [showCopySuccess, setShowCopySuccess] = useState(false);

  const handleSubmit = (e) => {
    e.preventDefault();
    onShare(shareMessage);
  };

  const copyToClipboard = async () => {
    try {
      const blogUrl = `${window.location.origin}/blogs/${blog._id}`;
      await navigator.clipboard.writeText(blogUrl);
      setShowCopySuccess(true);
      setTimeout(() => setShowCopySuccess(false), 2000);
    } catch (error) {
      console.error('Failed to copy to clipboard:', error);
    }
  };

  const shareToSocial = (platform) => {
    const blogUrl = `${window.location.origin}/blogs/${blog._id}`;
    const title = encodeURIComponent(blog.title);
    const description = encodeURIComponent(blog.description);
    
    const urls = {
      facebook: `https://www.facebook.com/sharer/sharer.php?u=${encodeURIComponent(blogUrl)}`,
      twitter: `https://twitter.com/intent/tweet?url=${encodeURIComponent(blogUrl)}&text=${title}`,
      linkedin: `https://www.linkedin.com/sharing/share-offsite/?url=${encodeURIComponent(blogUrl)}`,
      whatsapp: `https://wa.me/?text=${title}%20${encodeURIComponent(blogUrl)}`,
      telegram: `https://t.me/share/url?url=${encodeURIComponent(blogUrl)}&text=${title}`
    };

    if (urls[platform]) {
      window.open(urls[platform], '_blank', 'width=600,height=400');
    }
  };

  return (
    <div className="modal show d-block" style={{ backgroundColor: 'rgba(0,0,0,0.5)' }}>
      <div className="modal-dialog modal-dialog-centered">
        <div className="modal-content">
          <div className="modal-header">
            <h5 className="modal-title">
              <i className="bi bi-share me-2"></i>
              Share Blog Post
            </h5>
            <button 
              type="button" 
              className="btn-close" 
              onClick={onClose}
              disabled={isProcessing}
            ></button>
          </div>

          <div className="modal-body">
            {/* Blog Preview */}
            <div className="card mb-3">
              <div className="card-body p-3">
                <div className="d-flex">
                  {blog.image && (
                    <img 
                      src={blog.image} 
                      alt={blog.title}
                      className="rounded me-3"
                      style={{ width: '80px', height: '60px', objectFit: 'cover' }}
                    />
                  )}
                  <div className="flex-grow-1">
                    <h6 className="mb-1 fw-bold">{blog.title}</h6>
                    <p className="mb-1 text-muted small">
                      {blog.description?.length > 80 
                        ? `${blog.description.slice(0, 80)}...` 
                        : blog.description}
                    </p>
                    <small className="text-muted">
                      By {blog.user?.name || 'Unknown Author'}
                    </small>
                  </div>
                </div>
              </div>
            </div>

            {/* Share Message */}
            <form onSubmit={handleSubmit}>
              <div className="mb-3">
                <label htmlFor="shareMessage" className="form-label">
                  Add a message (optional)
                </label>
                <textarea
                  id="shareMessage"
                  className="form-control"
                  rows="3"
                  placeholder="Share your thoughts about this blog..."
                  value={shareMessage}
                  onChange={(e) => setShareMessage(e.target.value)}
                  maxLength="500"
                  disabled={isProcessing}
                />
                <div className="form-text text-end">
                  {shareMessage.length}/500 characters
                </div>
              </div>

              {/* Share to Platform Buttons */}
              <div className="mb-3">
                <label className="form-label">Share to social media</label>
                <div className="d-flex flex-wrap gap-2">
                  <button
                    type="button"
                    className="btn btn-outline-primary btn-sm"
                    onClick={() => shareToSocial('facebook')}
                  >
                    <i className="bi bi-facebook me-1"></i>
                    Facebook
                  </button>
                  <button
                    type="button"
                    className="btn btn-outline-info btn-sm"
                    onClick={() => shareToSocial('twitter')}
                  >
                    <i className="bi bi-twitter me-1"></i>
                    Twitter
                  </button>
                  <button
                    type="button"
                    className="btn btn-outline-primary btn-sm"
                    onClick={() => shareToSocial('linkedin')}
                  >
                    <i className="bi bi-linkedin me-1"></i>
                    LinkedIn
                  </button>
                  <button
                    type="button"
                    className="btn btn-outline-success btn-sm"
                    onClick={() => shareToSocial('whatsapp')}
                  >
                    <i className="bi bi-whatsapp me-1"></i>
                    WhatsApp
                  </button>
                  <button
                    type="button"
                    className="btn btn-outline-info btn-sm"
                    onClick={() => shareToSocial('telegram')}
                  >
                    <i className="bi bi-telegram me-1"></i>
                    Telegram
                  </button>
                </div>
              </div>

              {/* Copy Link */}
              <div className="mb-3">
                <label className="form-label">Or copy link</label>
                <div className="input-group">
                  <input
                    type="text"
                    className="form-control"
                    value={`${window.location.origin}/blogs/${blog._id}`}
                    readOnly
                  />
                  <button
                    type="button"
                    className={`btn ${showCopySuccess ? 'btn-success' : 'btn-outline-secondary'}`}
                    onClick={copyToClipboard}
                  >
                    {showCopySuccess ? (
                      <>
                        <i className="bi bi-check me-1"></i>
                        Copied!
                      </>
                    ) : (
                      <>
                        <i className="bi bi-clipboard me-1"></i>
                        Copy
                      </>
                    )}
                  </button>
                </div>
              </div>

              {/* Modal Footer */}
              <div className="d-flex justify-content-end gap-2">
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={onClose}
                  disabled={isProcessing}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="btn btn-primary"
                  disabled={isProcessing}
                >
                  {isProcessing ? (
                    <>
                      <span className="spinner-border spinner-border-sm me-2" role="status"></span>
                      Sharing...
                    </>
                  ) : (
                    <>
                      <i className="bi bi-share me-2"></i>
                      Share
                    </>
                  )}
                </button>
              </div>
            </form>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ShareModal;