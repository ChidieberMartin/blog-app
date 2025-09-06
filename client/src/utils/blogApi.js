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
            method: 'GET'
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
            method: 'GET'
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
            headers: {
                ...defaultFetchConfig.headers,
                'Authorization': `Bearer ${token}`
            },
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
            headers: {
                ...defaultFetchConfig.headers,
                'Authorization': `Bearer ${token}`
            },
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
            headers: {
                ...defaultFetchConfig.headers,
                'Authorization': `Bearer ${token}`
            }
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

// ✅ Export API base URL for debugging
export { API_BASE_URL };