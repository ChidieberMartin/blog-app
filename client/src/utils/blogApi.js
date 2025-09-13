// services/api.js
const API_BASE_URL = process.env.REACT_APP_API_URL || 
  (process.env.NODE_ENV === 'production' 
    ? 'https://blog-app-7u5b.onrender.com/api'  // ✅ Make sure this matches your backend URL
    : 'http://localhost:4001/api');  // ✅ Updated to match your backend port

// ✅ Default fetch configuration with proper headers
const defaultFetchConfig = {
    headers: {
        'Content-Type': 'application/json',
    },
    // Include credentials for CORS
    credentials: 'include'
};

// ✅ Helper function to get auth headers
const getAuthHeaders = () => {
    const token = localStorage.getItem('token');
    return {
        ...defaultFetchConfig.headers,
        'Authorization': token ? `Bearer ${token}` : ''
    };
};

// ✅ Helper function to handle API responses
const handleResponse = async (response) => {
    const data = await response.json();
    
    if (!response.ok) {
        // Log the full error for debugging
        console.error('API Error:', {
            status: response.status,
            statusText: response.statusText,
            data: data
        });
        throw new Error(data.message || `HTTP ${response.status}: ${response.statusText}`);
    }
    
    return data;
};

// Get all blogs with pagination and search
export const getAllBlogs = async (page = 1, limit = 10, search = '') => {
    try {
        let url = `${API_BASE_URL}/blogs?page=${page}&limit=${limit}`;
        if (search) {
            url += `&search=${encodeURIComponent(search)}`;
        }

        console.log('Fetching from URL:', url); // Debug log

        const response = await fetch(url, {
            ...defaultFetchConfig,
            method: 'GET',
            headers: getAuthHeaders() // Include auth for user-specific data like isLikedByUser
        });
        
        const data = await handleResponse(response);
        console.log('Raw API response:', data); // Debug log

        // Log each blog's user data for debugging
        if (data.blogs) {
            console.log('Number of blogs:', data.blogs.length);
            data.blogs.forEach((blog, index) => {
                console.log(`Blog ${index + 1} user:`, blog.user);
            });
        }

        return data;
    } catch (error) {
        console.error('Get all blogs error:', error);
        throw error;
    }
}

// Alternative function to try the simple endpoint
export const getAllBlogsSimple = async () => {
    try {
        const url = `${API_BASE_URL}/blogs/simple-blog`;
        console.log('Fetching from simple URL:', url);

        const response = await fetch(url, {
            ...defaultFetchConfig,
            method: 'GET'
        });
        
        const data = await handleResponse(response);
        console.log('Simple API response:', data);

        return data;
    } catch (error) {
        console.error('Get simple blogs error:', error);
        throw error;
    }
}

// Get blog by ID
export const getBlogById = async (id) => {
    try {
        const response = await fetch(`${API_BASE_URL}/blogs/${id}`, {
            ...defaultFetchConfig,
            method: 'GET',
            headers: getAuthHeaders() // Include auth for user-specific data
        });
        
        return await handleResponse(response);
    } catch (error) {
        console.error('Get blog by ID error:', error);
        throw error;
    }
}

// Create new blog
export const createBlog = async (blogData) => {
    try {
        const token = localStorage.getItem('token');
        if (!token) {
            throw new Error('Authentication token not found');
        }

        const response = await fetch(`${API_BASE_URL}/blogs/create`, {
            ...defaultFetchConfig,
            method: 'POST',
            headers: getAuthHeaders(),
            body: JSON.stringify(blogData)
        });

        return await handleResponse(response);
    } catch (error) {
        console.error('Create blog error:', error);
        throw error;
    }
}

// Update blog
export const updateBlog = async (id, blogData) => {
    try {
        const token = localStorage.getItem('token');
        if (!token) {
            throw new Error('Authentication token not found');
        }

        const response = await fetch(`${API_BASE_URL}/blogs/${id}`, {
            ...defaultFetchConfig,
            method: 'PUT',
            headers: getAuthHeaders(),
            body: JSON.stringify(blogData)
        });

        return await handleResponse(response);
    } catch (error) {
        console.error('Update blog error:', error);
        throw error;
    }
}

// Delete blog
export const deleteBlog = async (id) => {
    try {
        const token = localStorage.getItem('token');
        if (!token) {
            throw new Error('Authentication token not found');
        }

        const response = await fetch(`${API_BASE_URL}/blogs/${id}`, {
            ...defaultFetchConfig,
            method: 'DELETE',
            headers: getAuthHeaders()
        });

        return await handleResponse(response);
    } catch (error) {
        console.error('Delete blog error:', error);
        throw error;
    }
}

// Get blogs by user ID
export const getUserBlogs = async (userId) => {
    try {
        const response = await fetch(`${API_BASE_URL}/blogs/user/${userId}`, {
            ...defaultFetchConfig,
            method: 'GET'
        });
        
        return await handleResponse(response);
    } catch (error) {
        console.error('Get user blogs error:', error);
        throw error;
    }
}

// Search blogs
export const searchBlogs = async (searchTerm, page = 1, limit = 10) => {
    try {
        const response = await fetch(
            `${API_BASE_URL}/blogs?search=${encodeURIComponent(searchTerm)}&page=${page}&limit=${limit}`,
            {
                ...defaultFetchConfig,
                method: 'GET'
            }
        );
        
        return await handleResponse(response);
    } catch (error) {
        console.error('Search blogs error:', error);
        throw error;
    }
}

// ========== SOCIAL FEATURES API FUNCTIONS ==========

// Like/Unlike a blog
export const toggleLike = async (blogId) => {
    try {
        const token = localStorage.getItem('token');
        if (!token) {
            throw new Error('Please login to like blogs');
        }

        const response = await fetch(`${API_BASE_URL}/blogs/${blogId}/like`, {
            ...defaultFetchConfig,
            method: 'POST',
            headers: getAuthHeaders()
        });

        return await handleResponse(response);
    } catch (error) {
        console.error('Toggle like error:', error);
        throw error;
    }
}

// Get blog likes
export const getBlogLikes = async (blogId) => {
    try {
        const response = await fetch(`${API_BASE_URL}/blogs/${blogId}/likes`, {
            ...defaultFetchConfig,
            method: 'GET'
        });

        return await handleResponse(response);
    } catch (error) {
        console.error('Get blog likes error:', error);
        throw error;
    }
}

// Add comment to blog
export const addComment = async (blogId, text) => {
    try {
        const token = localStorage.getItem('token');
        if (!token) {
            throw new Error('Please login to comment');
        }

        const response = await fetch(`${API_BASE_URL}/blogs/${blogId}/comment`, {
            ...defaultFetchConfig,
            method: 'POST',
            headers: getAuthHeaders(),
            body: JSON.stringify({ text })
        });

        return await handleResponse(response);
    } catch (error) {
        console.error('Add comment error:', error);
        throw error;
    }
}

// Get blog comments
export const getBlogComments = async (blogId, page = 1, limit = 10) => {
    try {
        const response = await fetch(`${API_BASE_URL}/blogs/${blogId}/comments?page=${page}&limit=${limit}`, {
            ...defaultFetchConfig,
            method: 'GET'
        });

        return await handleResponse(response);
    } catch (error) {
        console.error('Get blog comments error:', error);
        throw error;
    }
}

// Reply to comment
export const replyToComment = async (commentId, text) => {
    try {
        const token = localStorage.getItem('token');
        if (!token) {
            throw new Error('Please login to reply');
        }

        const response = await fetch(`${API_BASE_URL}/blogs/comment/${commentId}/reply`, {
            ...defaultFetchConfig,
            method: 'POST',
            headers: getAuthHeaders(),
            body: JSON.stringify({ text })
        });

        return await handleResponse(response);
    } catch (error) {
        console.error('Reply to comment error:', error);
        throw error;
    }
}

// Delete comment
export const deleteComment = async (commentId) => {
    try {
        const token = localStorage.getItem('token');
        if (!token) {
            throw new Error('Please login to delete comments');
        }

        const response = await fetch(`${API_BASE_URL}/blogs/comment/${commentId}`, {
            ...defaultFetchConfig,
            method: 'DELETE',
            headers: getAuthHeaders()
        });

        return await handleResponse(response);
    } catch (error) {
        console.error('Delete comment error:', error);
        throw error;
    }
}

// Share blog
export const shareBlog = async (blogId, shareMessage = '') => {
    try {
        const token = localStorage.getItem('token');
        if (!token) {
            throw new Error('Please login to share blogs');
        }

        const response = await fetch(`${API_BASE_URL}/blogs/${blogId}/share`, {
            ...defaultFetchConfig,
            method: 'POST',
            headers: getAuthHeaders(),
            body: JSON.stringify({ shareMessage })
        });

        return await handleResponse(response);
    } catch (error) {
        console.error('Share blog error:', error);
        throw error;
    }
}

// ✅ Export API base URL for debugging
export { API_BASE_URL };