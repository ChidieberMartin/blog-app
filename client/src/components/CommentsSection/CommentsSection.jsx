import React, { useState, useEffect } from 'react';
import { getBlogComments, addComment, deleteComment, replyToComment } from '../../utils/blogApi';

const CommentsSection = ({ blogId, initialCommentsCount = 0 }) => {
  const [comments, setComments] = useState([]);
  const [loading, setLoading] = useState(true);
  const [newComment, setNewComment] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [replyingTo, setReplyingTo] = useState(null);
  const [replyText, setReplyText] = useState('');
  const [showReplies, setShowReplies] = useState({});

  const currentUser = JSON.parse(localStorage.getItem('user') || '{}');
  const isLoggedIn = !!localStorage.getItem('token');

  useEffect(() => {
    loadComments();
  }, [blogId]);

  const loadComments = async () => {
    try {
      setLoading(true);
      const response = await getBlogComments(blogId);
      setComments(response.comments || []);
    } catch (error) {
      console.error('Error loading comments:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleAddComment = async (e) => {
    e.preventDefault();
    if (!newComment.trim() || submitting) return;

    try {
      setSubmitting(true);
      const response = await addComment(blogId, newComment.trim());
      
      // Add new comment to the beginning of the list
      setComments(prev => [response.comment, ...prev]);
      setNewComment('');
    } catch (error) {
      console.error('Error adding comment:', error);
      alert(error.message || 'Failed to add comment');
    } finally {
      setSubmitting(false);
    }
  };

  const handleDeleteComment = async (commentId) => {
    if (!window.confirm('Are you sure you want to delete this comment?')) return;

    try {
      await deleteComment(commentId);
      setComments(prev => prev.filter(comment => comment._id !== commentId));
    } catch (error) {
      console.error('Error deleting comment:', error);
      alert(error.message || 'Failed to delete comment');
    }
  };

  const handleReply = async (commentId) => {
    if (!replyText.trim() || submitting) return;

    try {
      setSubmitting(true);
      const response = await replyToComment(commentId, replyText.trim());
      
      // Update the comment with the new reply
      setComments(prev => 
        prev.map(comment => 
          comment._id === commentId
            ? { ...comment, replies: [...(comment.replies || []), response.reply] }
            : comment
        )
      );
      
      setReplyText('');
      setReplyingTo(null);
    } catch (error) {
      console.error('Error adding reply:', error);
      alert(error.message || 'Failed to add reply');
    } finally {
      setSubmitting(false);
    }
  };

  const toggleReplies = (commentId) => {
    setShowReplies(prev => ({
      ...prev,
      [commentId]: !prev[commentId]
    }));
  };

  const formatDate = (dateString) => {
    const date = new Date(dateString);
    const now = new Date();
    const diffMs = now - date;
    const diffMins = Math.floor(diffMs / (1000 * 60));
    const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
    const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));

    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    if (diffDays < 7) return `${diffDays}d ago`;
    
    return date.toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric'
    });
  };

  if (loading) {
    return (
      <div className="text-center py-4">
        <div className="spinner-border spinner-border-sm" role="status">
          <span className="visually-hidden">Loading comments...</span>
        </div>
        <p className="mt-2 mb-0 text-muted">Loading comments...</p>
      </div>
    );
  }

  return (
    <div className="comments-section">
      <div className="d-flex align-items-center justify-content-between mb-4">
        <h5 className="mb-0">
          <i className="bi bi-chat-dots me-2"></i>
          Comments ({comments.length})
        </h5>
      </div>

      {/* Add Comment Form */}
      {isLoggedIn ? (
        <div className="card mb-4">
          <div className="card-body">
            <form onSubmit={handleAddComment}>
              <div className="d-flex">
                <div className="rounded-circle bg-primary text-white d-flex align-items-center justify-content-center me-3"
                     style={{ width: '40px', height: '40px', fontSize: '1rem', flexShrink: 0 }}>
                  {currentUser.name?.charAt(0).toUpperCase() || 'U'}
                </div>
                <div className="flex-grow-1">
                  <textarea
                    className="form-control"
                    rows="3"
                    placeholder="Write a comment..."
                    value={newComment}
                    onChange={(e) => setNewComment(e.target.value)}
                    disabled={submitting}
                    maxLength="1000"
                  />
                  <div className="d-flex justify-content-between align-items-center mt-2">
                    <small className="text-muted">
                      {newComment.length}/1000 characters
                    </small>
                    <button
                      type="submit"
                      className="btn btn-primary btn-sm"
                      disabled={!newComment.trim() || submitting}
                    >
                      {submitting ? (
                        <>
                          <span className="spinner-border spinner-border-sm me-2" role="status"></span>
                          Posting...
                        </>
                      ) : (
                        <>
                          <i className="bi bi-send me-2"></i>
                          Post Comment
                        </>
                      )}
                    </button>
                  </div>
                </div>
              </div>
            </form>
          </div>
        </div>
      ) : (
        <div className="card mb-4">
          <div className="card-body text-center">
            <p className="mb-2">
              <i className="bi bi-lock me-2"></i>
              Please log in to leave a comment
            </p>
            <button 
              className="btn btn-primary btn-sm"
              onClick={() => window.location.href = '/login'}
            >
              Login to Comment
            </button>
          </div>
        </div>
      )}

      {/* Comments List */}
      {comments.length === 0 ? (
        <div className="text-center py-5">
          <i className="bi bi-chat display-1 text-muted"></i>
          <h6 className="mt-3 text-muted">No comments yet</h6>
          <p className="text-muted">Be the first to share your thoughts!</p>
        </div>
      ) : (
        <div className="comments-list">
          {comments.map((comment) => (
            <div key={comment._id} className="card mb-3">
              <div className="card-body">
                {/* Comment Header */}
                <div className="d-flex justify-content-between align-items-start mb-2">
                  <div className="d-flex align-items-center">
                    <div className="rounded-circle bg-secondary text-white d-flex align-items-center justify-content-center me-3"
                         style={{ width: '36px', height: '36px', fontSize: '0.9rem' }}>
                      {comment.user?.name?.charAt(0).toUpperCase() || 'U'}
                    </div>
                    <div>
                      <div className="fw-medium">
                        {comment.user?.name || 'Unknown User'}
                      </div>
                      <small className="text-muted">
                        {formatDate(comment.createdAt)}
                      </small>
                    </div>
                  </div>

                  {/* Delete button (only for comment author or blog owner) */}
                  {isLoggedIn && (comment.user?._id === currentUser.id) && (
                    <button
                      className="btn btn-sm btn-outline-danger"
                      onClick={() => handleDeleteComment(comment._id)}
                      title="Delete comment"
                    >
                      <i className="bi bi-trash"></i>
                    </button>
                  )}
                </div>

                {/* Comment Text */}
                <p className="mb-2">{comment.text}</p>

                {/* Comment Actions */}
                <div className="d-flex align-items-center gap-3 text-muted">
                  {isLoggedIn && (
                    <button
                      className="btn btn-sm btn-link p-0 text-muted"
                      onClick={() => setReplyingTo(replyingTo === comment._id ? null : comment._id)}
                    >
                      <i className="bi bi-reply me-1"></i>
                      Reply
                    </button>
                  )}

                  {comment.replies && comment.replies.length > 0 && (
                    <button
                      className="btn btn-sm btn-link p-0 text-muted"
                      onClick={() => toggleReplies(comment._id)}
                    >
                      <i className={`bi ${showReplies[comment._id] ? 'bi-chevron-up' : 'bi-chevron-down'} me-1`}></i>
                      {showReplies[comment._id] ? 'Hide' : 'Show'} {comment.replies.length} {comment.replies.length === 1 ? 'reply' : 'replies'}
                    </button>
                  )}
                </div>

                {/* Reply Form */}
                {replyingTo === comment._id && (
                  <div className="mt-3 ps-4">
                    <div className="d-flex">
                      <div className="rounded-circle bg-primary text-white d-flex align-items-center justify-content-center me-3"
                           style={{ width: '32px', height: '32px', fontSize: '0.8rem', flexShrink: 0 }}>
                        {currentUser.name?.charAt(0).toUpperCase() || 'U'}
                      </div>
                      <div className="flex-grow-1">
                        <textarea
                          className="form-control form-control-sm"
                          rows="2"
                          placeholder="Write a reply..."
                          value={replyText}
                          onChange={(e) => setReplyText(e.target.value)}
                          disabled={submitting}
                          maxLength="1000"
                        />
                        <div className="d-flex justify-content-between align-items-center mt-2">
                          <small className="text-muted">
                            {replyText.length}/1000 characters
                          </small>
                          <div className="d-flex gap-2">
                            <button
                              type="button"
                              className="btn btn-sm btn-outline-secondary"
                              onClick={() => {
                                setReplyingTo(null);
                                setReplyText('');
                              }}
                              disabled={submitting}
                            >
                              Cancel
                            </button>
                            <button
                              type="button"
                              className="btn btn-sm btn-primary"
                              onClick={() => handleReply(comment._id)}
                              disabled={!replyText.trim() || submitting}
                            >
                              {submitting ? (
                                <>
                                  <span className="spinner-border spinner-border-sm me-1" role="status"></span>
                                  Replying...
                                </>
                              ) : (
                                'Reply'
                              )}
                            </button>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                )}

                {/* Replies */}
                {comment.replies && comment.replies.length > 0 && showReplies[comment._id] && (
                  <div className="mt-3 ps-4 border-start border-2">
                    {comment.replies.map((reply, index) => (
                      <div key={index} className="d-flex mb-3">
                        <div className="rounded-circle bg-info text-white d-flex align-items-center justify-content-center me-3"
                             style={{ width: '32px', height: '32px', fontSize: '0.8rem', flexShrink: 0 }}>
                          {reply.user?.name?.charAt(0).toUpperCase() || 'U'}
                        </div>
                        <div className="flex-grow-1">
                          <div className="d-flex align-items-center mb-1">
                            <span className="fw-medium me-2">
                              {reply.user?.name || 'Unknown User'}
                            </span>
                            <small className="text-muted">
                              {formatDate(reply.createdAt)}
                            </small>
                          </div>
                          <p className="mb-0 small">{reply.text}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default CommentsSection;