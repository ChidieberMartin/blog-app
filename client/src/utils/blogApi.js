
// API Base URL - Update this to match your backend
const API_BASE_URL = 'http://localhost:4000/api';

// Get all blogs with pagination and search
export const getAllBlogs = async (page = 1, limit = 10, search = '') => {
    try {
        let url = `${API_BASE_URL}/blogs?page=${page}&limit=${limit}`;
        if (search) {
            url += `&search=${encodeURIComponent(search)}`;
        }

        console.log('Fetching from URL:', url); // Debug log

        const response = await fetch(url, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                // Add any auth headers if needed
            }
        });
        
        const data = await response.json();
        console.log('Raw API response:', data); // Debug log

        if (!response.ok) {
            throw new Error(data.message || 'Failed to fetch blogs');
        }

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
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
            }
        });
        
        const data = await response.json();
        console.log('Simple API response:', data);

        if (!response.ok) {
            throw new Error(data.message || 'Failed to fetch blogs');
        }

        return data;
    } catch (error) {
        console.error('Get simple blogs error:', error);
        throw error;
    }
}

// Get blog by ID
export const getBlogById = async (id) => {
    try {
        const response = await fetch(`${API_BASE_URL}/blogs/${id}`);
        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.message || 'Failed to fetch blog');
        }

        return data;
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
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify(blogData)
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.message || 'Failed to create blog');
        }

        return data;
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
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify(blogData)
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.message || 'Failed to update blog');
        }

        return data;
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
            method: 'DELETE',
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.message || 'Failed to delete blog');
        }

        return data;
    } catch (error) {
        console.error('Delete blog error:', error);
        throw error;
    }
}

// Get blogs by user ID
export const getUserBlogs = async (userId) => {
    try {
        const response = await fetch(`${API_BASE_URL}/blogs/user/${userId}`);
        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.message || 'Failed to fetch user blogs');
        }

        return data;
    } catch (error) {
        console.error('Get user blogs error:', error);
        throw error;
    }
}

// Search blogs
export const searchBlogs = async (searchTerm, page = 1, limit = 10) => {
    try {
        const response = await fetch(
            `${API_BASE_URL}/blogs?search=${encodeURIComponent(searchTerm)}&page=${page}&limit=${limit}`
        );
        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.message || 'Failed to search blogs');
        }

        return data;
    } catch (error) {
        console.error('Search blogs error:', error);
        throw error;
    }
}
