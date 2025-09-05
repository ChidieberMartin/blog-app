import React, { useState, useEffect,useCallback } from 'react';
import { Search, BookOpen, TrendingUp, Users, Star, ArrowRight, Filter, Loader, ChevronLeft, ChevronRight } from 'lucide-react';

// Mock components and context for demo
const useAuth = () => ({ user: { name: 'John Doe', email: 'john@example.com' } });

const blogAPI = {
  getAllBlogs: async (page = 1, limit = 9, search = '') => {
    // Mock API response
    const mockBlogs = [
      {
        _id: '1',
        title: 'Getting Started with React Hooks',
        content: 'React Hooks have revolutionized how we write React components...',
        author: { name: 'Alice Johnson', email: 'alice@example.com' },
        createdAt: '2024-08-25T10:00:00Z',
        tags: ['React', 'JavaScript', 'Frontend'],
        likes: 42
      },
      {
        _id: '2',
        title: 'The Future of Web Development',
        content: 'As we look ahead to the next decade of web development...',
        author: { name: 'Bob Smith', email: 'bob@example.com' },
        createdAt: '2024-08-24T15:30:00Z',
        tags: ['Web Development', 'Technology', 'Future'],
        likes: 28
      },
      {
        _id: '3',
        title: 'Building Scalable APIs with Node.js',
        content: 'Creating robust and scalable APIs is crucial for modern applications...',
        author: { name: 'Carol Davis', email: 'carol@example.com' },
        createdAt: '2024-08-23T09:15:00Z',
        tags: ['Node.js', 'Backend', 'API'],
        likes: 35
      },
      {
        _id: '4',
        title: 'CSS Grid vs Flexbox: When to Use What',
        content: 'Understanding the differences between CSS Grid and Flexbox...',
        author: { name: 'David Wilson', email: 'david@example.com' },
        createdAt: '2024-08-22T14:20:00Z',
        tags: ['CSS', 'Layout', 'Frontend'],
        likes: 51
      },
      {
        _id: '5',
        title: 'Machine Learning for Beginners',
        content: 'Dive into the fascinating world of machine learning...',
        author: { name: 'Eva Martinez', email: 'eva@example.com' },
        createdAt: '2024-08-21T11:45:00Z',
        tags: ['Machine Learning', 'AI', 'Python'],
        likes: 67
      },
      {
        _id: '6',
        title: 'The Art of Clean Code',
        content: 'Writing clean, maintainable code is more art than science...',
        author: { name: 'Frank Brown', email: 'frank@example.com' },
        createdAt: '2024-08-20T16:00:00Z',
        tags: ['Programming', 'Best Practices', 'Clean Code'],
        likes: 39
      }
    ];

    // Filter by search term if provided
    let filteredBlogs = search
      ? mockBlogs.filter(blog =>
        blog.title.toLowerCase().includes(search.toLowerCase()) ||
        blog.content.toLowerCase().includes(search.toLowerCase()) ||
        blog.tags.some(tag => tag.toLowerCase().includes(search.toLowerCase()))
      )
      : mockBlogs;

    return {
      blogs: filteredBlogs.slice((page - 1) * limit, page * limit),
      pagination: {
        totalPages: Math.ceil(filteredBlogs.length / limit),
        currentPage: page,
        totalBlogs: filteredBlogs.length
      }
    };
  },
  deleteBlog: async (id) => {
    // Mock delete
    return { success: true };
  }
};

const BlogCard = ({ blog, onView, onEdit, onDelete, featured = false }) => {
  const { user } = useAuth();
  const isOwner = user && blog.author.email === user.email;

  const formatDate = (dateString) => {
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric'
    });
  };

  return (
    <div className={`bg-white rounded-lg shadow-md hover:shadow-lg transition-shadow duration-300 overflow-hidden ${featured ? 'border-2 border-yellow-200' : ''}`}>
      {featured && (
        <div className="bg-yellow-50 px-4 py-2 border-b">
          <div className="flex items-center text-sm text-yellow-700">
            <Star className="w-4 h-4 mr-1 fill-current" />
            Featured
          </div>
        </div>
      )}

      <div className="p-6">
        <h3 className="text-xl font-semibold text-gray-900 mb-2 line-clamp-2">
          {blog.title}
        </h3>

        <p className="text-gray-600 mb-4 line-clamp-3">
          {blog.content}
        </p>

        <div className="d-flex flex-wrap gap-2 mb-4">
          {blog.tags.slice(0, 3).map((tag, index) => (
            <span
              key={index}
              className="inline-block bg-blue-100 text-blue-800 text-xs px-2 py-1 rounded-full"
            >
              {tag}
            </span>
          ))}
          {blog.tags.length > 3 && (
            <span className="text-xs text-gray-500">+{blog.tags.length - 3} more</span>
          )}
        </div>

        <div className="flex items-center justify-between text-sm text-gray-500 mb-4">
          <div className="flex items-center">
            <div className="w-8 h-8 bg-gray-300 rounded-full flex items-center justify-center mr-2">
              {blog.author.name.charAt(0).toUpperCase()}
            </div>
            <div>
              <p className="font-medium text-gray-900">{blog.author.name}</p>
              <p>{formatDate(blog.createdAt)}</p>
            </div>
          </div>

          <div className="flex items-center">
            <Star className="w-4 h-4 mr-1" />
            <span>{blog.likes}</span>
          </div>
        </div>

        <div className="flex gap-2">
          <button
            onClick={() => onView(blog)}
            className="flex-1 bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700 transition-colors text-sm font-medium"
          >
            Read More
          </button>

          {isOwner && (
            <>
              <button
                onClick={() => onEdit(blog)}
                className="px-4 py-2 border border-gray-300 text-gray-700 rounded-md hover:bg-gray-50 transition-colors text-sm"
              >
                Edit
              </button>
              <button
                onClick={() => onDelete(blog)}
                className="px-4 py-2 border border-red-300 text-red-700 rounded-md hover:bg-red-50 transition-colors text-sm"
              >
                Delete
              </button>
            </>
          )}
        </div>
      </div>
    </div>
  );
};

const Home = ({ setCurrentPage, setSelectedBlog }) => {
  const { user } = useAuth();
  const [blogs, setBlogs] = useState([]);
  const [featuredBlogs, setFeaturedBlogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [currentPage, setCurrentPageNum] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [sortBy, setSortBy] = useState('newest');
  const [showFilters, setShowFilters] = useState(false);


   const loadBlogs = useCallback(async () => {
    try {
      setLoading(true);
      const data = await blogAPI.getAllBlogs(currentPage, 9, searchTerm);

      if (data.blogs) {
        setBlogs(data.blogs);
        setTotalPages(data.pagination?.totalPages || 1);
      }
    } catch (error) {
      console.error('Failed to load blogs:', error);
    } finally {
      setLoading(false);
    }
  }, [currentPage, searchTerm]); // 👈 dependencies

  const loadFeaturedBlogs = useCallback(async () => {
    try {
      const data = await blogAPI.getAllBlogs(1, 3);
      if (data.blogs) {
        setFeaturedBlogs(data.blogs.slice(0, 3));
      }
    } catch (error) {
      console.error('Failed to load featured blogs:', error);
    }
  }, []);

  useEffect(() => {
    loadBlogs();
    loadFeaturedBlogs();
  }, [loadBlogs, loadFeaturedBlogs]);;

  // const loadBlogs = async () => {
  //   try {
  //     setLoading(true);
  //     const data = await blogAPI.getAllBlogs(currentPage, 9, searchTerm);

  //     if (data.blogs) {
  //       setBlogs(data.blogs);
  //       setTotalPages(data.pagination?.totalPages || 1);
  //     }
  //   } catch (error) {
  //     console.error('Failed to load blogs:', error);
  //   } finally {
  //     setLoading(false);
  //   }
  // };

  // const loadFeaturedBlogs = async () => {
  //   try {
  //     // Get recent blogs as featured (you could modify this logic)
  //     const data = await blogAPI.getAllBlogs(1, 3);
  //     if (data.blogs) {
  //       setFeaturedBlogs(data.blogs.slice(0, 3));
  //     }
  //   } catch (error) {
  //     console.error('Failed to load featured blogs:', error);
  //   }
  // };

  const handleSearch = async () => {
    setCurrentPageNum(1);
    await loadBlogs();
  };

  const handleView = (blog) => {
    setSelectedBlog(blog);
    setCurrentPage('viewBlog');
  };

  const handleEdit = (blog) => {
    setCurrentPage('editBlog');
    // You'll need to pass the blog data to the edit component
  };

  const handleDelete = async (blog) => {
    if (!window.confirm('Are you sure you want to delete this blog?')) {
      return;
    }

    try {
      await blogAPI.deleteBlog(blog._id);
      await loadBlogs(); // Refresh the list
    } catch (error) {
      console.error('Failed to delete blog:', error);
      alert('Failed to delete blog');
    }
  };

  const sortOptions = [
    { value: 'newest', label: 'Newest First' },
    { value: 'oldest', label: 'Oldest First' },
    { value: 'title', label: 'Title A-Z' }
  ];

  const getSortedBlogs = () => {
    let sortedBlogs = [...blogs];

    switch (sortBy) {
      case 'oldest':
        return sortedBlogs.reverse();
      case 'title':
        return sortedBlogs.sort((a, b) => a.title.localeCompare(b.title));
      default:
        return sortedBlogs;
    }
  };

  const handlePageChange = (newPage) => {
    if (newPage >= 1 && newPage <= totalPages) {
      setCurrentPageNum(newPage);
    }
  };

  return (
   <div className="min-vh-100 bg-light">
  {/* Hero Section */}
  <section className="bg-primary text-white py-5 text-center">
    <div className="container">
      <h1 className="display-4 fw-bold mb-3">Welcome to BlogSpace</h1>
      <p className="lead mb-4">
        Discover amazing stories, share your thoughts, and connect with writers from around the world.
      </p>

      {!user ? (
        <div className="d-flex flex-column flex-sm-row gap-3 justify-content-center">
          <button
            onClick={() => setCurrentPage("signup")}
            className="btn btn-light text-primary fw-semibold px-4 py-2 shadow"
          >
            Get Started
          </button>
          <button
            onClick={() => setCurrentPage("allBlogs")}
            className="btn btn-outline-light fw-semibold px-4 py-2"
          >
            Explore Blogs
          </button>
        </div>
      ) : (
        <div className="d-flex flex-column flex-sm-row gap-3 justify-content-center">
          <button
            onClick={() => setCurrentPage("createBlog")}
            className="btn btn-light text-primary fw-semibold px-4 py-2 d-flex align-items-center shadow"
          >
            <BookOpen className="me-2" />
            Write a Blog
          </button>
          <button
            onClick={() => setCurrentPage("myBlogs")}
            className="btn btn-outline-light fw-semibold px-4 py-2 d-flex align-items-center"
          >
            <Users className="me-2" />
            My Blogs
          </button>
        </div>
      )}
    </div>
  </section>

  {/* Search and Filter Section */}
  <section className="container py-5">
    <div className="card shadow-sm">
      <div className="card-body">
        <div className="row g-3">
          <div className="col-md">
            <div className="input-group">
              <span className="input-group-text">
                <Search className="text-secondary" />
              </span>
              <input
                type="text"
                placeholder="Search for blogs, topics, or authors..."
                className="form-control"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
              />
            </div>
          </div>

          <div className="col-md-auto d-flex gap-2">
            <button
              type="button"
              onClick={() => setShowFilters(!showFilters)}
              className="btn btn-outline-secondary d-flex align-items-center"
            >
              <Filter className="me-2" /> Filters
            </button>
            <button
              type="button"
              onClick={handleSearch}
              className="btn btn-primary"
            >
              Search
            </button>
          </div>
        </div>

        {showFilters && (
          <div className="mt-4 border-top pt-3">
            <div className="row g-3">
              <div className="col-md-4">
                <label className="form-label">Sort By</label>
                <select
                  value={sortBy}
                  onChange={(e) => setSortBy(e.target.value)}
                  className="form-select"
                >
                  {sortOptions.map((option) => (
                    <option key={option.value} value={option.value}>
                      {option.label}
                    </option>
                  ))}
                </select>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  </section>

  {/* Featured Blogs Section */}
  {featuredBlogs.length > 0 && (
    <section className="container py-5">
      <div className="d-flex justify-content-between align-items-center mb-4">
        <h2 className="h4 fw-bold text-dark d-flex align-items-center">
          <Star className="me-2 text-warning" />
          Featured Blogs
        </h2>
        <button
          onClick={() => setCurrentPage("allBlogs")}
          className="btn btn-link text-primary fw-semibold"
        >
          View all blogs <ArrowRight className="ms-1" />
        </button>
      </div>

      <div className="row g-4">
        {featuredBlogs.map((blog) => (
          <div className="col-md-6 col-lg-4" key={blog._id}>
            <BlogCard
              blog={blog}
              onView={handleView}
              onEdit={handleEdit}
              onDelete={handleDelete}
              featured={true}
            />
          </div>
        ))}
      </div>
    </section>
  )}

  {/* Recent Blogs Section */}
  <section className="container py-5">
    <div className="d-flex justify-content-between align-items-center mb-4">
      <h2 className="h4 fw-bold text-dark d-flex align-items-center">
        <TrendingUp className="me-2 text-success" />
        Recent Blogs
      </h2>
      <div className="text-muted small">
        Showing {blogs.length} of {totalPages * 9} blogs
      </div>
    </div>

    {loading ? (
      <div className="text-center py-5">
        <div className="spinner-border text-primary mb-3"></div>
        <p className="text-muted">Loading blogs...</p>
      </div>
    ) : blogs.length === 0 ? (
      <div className="text-center py-5">
        <BookOpen className="mb-3 text-secondary" size={48} />
        <h5>No blogs found</h5>
        <p className="text-muted">
          {searchTerm ? `No blogs match "${searchTerm}"` : "Be the first to write a blog!"}
        </p>
        {user && (
          <button
            onClick={() => setCurrentPage("createBlog")}
            className="btn btn-primary d-inline-flex align-items-center"
          >
            <BookOpen className="me-2" />
            Create Your First Blog
          </button>
        )}
      </div>
    ) : (
      <>
        <div className="row g-4">
          {getSortedBlogs().map((blog) => (
            <div className="col-md-6 col-lg-4" key={blog._id}>
              <BlogCard
                blog={blog}
                onView={handleView}
                onEdit={handleEdit}
                onDelete={handleDelete}
              />
            </div>
          ))}
        </div>

        {totalPages > 1 && (
          <nav className="mt-4">
            <ul className="pagination justify-content-center">
              <li className={`page-item ${currentPage === 1 ? "disabled" : ""}`}>
                <button
                  className="page-link"
                  onClick={() => handlePageChange(currentPage - 1)}
                >
                  <ChevronLeft />
                </button>
              </li>

              {Array.from({ length: totalPages }, (_, i) => i + 1).map((page) => (
                <li
                  key={page}
                  className={`page-item ${page === currentPage ? "active" : ""}`}
                >
                  <button
                    className="page-link"
                    onClick={() => handlePageChange(page)}
                  >
                    {page}
                  </button>
                </li>
              ))}

              <li className={`page-item ${currentPage === totalPages ? "disabled" : ""}`}>
                <button
                  className="page-link"
                  onClick={() => handlePageChange(currentPage + 1)}
                >
                  <ChevronRight />
                </button>
              </li>
            </ul>
          </nav>
        )}
      </>
    )}
  </section>

  {/* Stats */}
  <section className="bg-white py-5">
    <div className="container text-center">
      <div className="row g-4">
        <div className="col-md">
          <h3 className="text-primary fw-bold">500+</h3>
          <p className="text-muted">Published Blogs</p>
        </div>
        <div className="col-md">
          <h3 className="text-success fw-bold">150+</h3>
          <p className="text-muted">Active Writers</p>
        </div>
        <div className="col-md">
          <h3 className="text-purple fw-bold">10k+</h3>
          <p className="text-muted">Monthly Readers</p>
        </div>
      </div>
    </div>
  </section>

  {/* CTA */}
  <section className="bg-dark text-white py-5 text-center">
    <div className="container">
      <h2 className="h3 fw-bold mb-3">Ready to Share Your Story?</h2>
      <p className="lead text-light mb-4">
        Join our community of passionate writers and readers. Start your blogging journey today.
      </p>

      {!user ? (
        <button
          onClick={() => setCurrentPage("signup")}
          className="btn btn-primary btn-lg shadow"
        >
          Join BlogSpace Today
        </button>
      ) : (
        <button
          onClick={() => setCurrentPage("createBlog")}
          className="btn btn-primary btn-lg shadow d-inline-flex align-items-center"
        >
          <BookOpen className="me-2" />
          Start Writing
        </button>
      )}
    </div>
  </section>
</div>

  );
};

export default Home;