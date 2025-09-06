import React from 'react';
import { BookOpen, Users, Globe, TrendingUp, Star, ArrowRight, CheckCircle, Edit3, Share2, BarChart3 } from 'lucide-react';
import Navbar from '../../components/Navbar/Navbar';

const Homepage = () => {
  const features = [
    {
      icon: Edit3,
      title: "Rich Text Editor",
      description: "Write and format your blogs with our powerful, intuitive editor with real-time preview."
    },
    {
      icon: Share2,
      title: "Easy Sharing",
      description: "Share your content across social platforms and reach a wider audience effortlessly."
    },
    {
      icon: BarChart3,
      title: "Analytics Dashboard",
      description: "Track your blog performance with detailed analytics and engagement metrics."
    },
    {
      icon: Users,
      title: "Community Driven",
      description: "Connect with fellow writers and readers in our vibrant blogging community."
    },
    {
      icon: Globe,
      title: "Global Reach",
      description: "Publish to the world and build your audience across different countries and cultures."
    },
    {
      icon: TrendingUp,
      title: "SEO Optimized",
      description: "Built-in SEO tools to help your content rank higher and reach more readers."
    }
  ];

  const testimonials = [
    {
      name: "Sarah Johnson",
      role: "Travel Blogger",
      content: "BlogSpace has transformed how I share my travel experiences. The editor is incredibly user-friendly!",
      rating: 5
    },
    {
      name: "Michael Chen",
      role: "Tech Writer",
      content: "The analytics features help me understand my audience better. My readership has grown 300%!",
      rating: 5
    },
    {
      name: "Emma Davis",
      role: "Food Blogger",
      content: "Finally, a platform that makes blogging enjoyable. The community here is amazing and supportive.",
      rating: 5
    }
  ];

  const stats = [
    { number: "10K+", label: "Active Bloggers" },
    { number: "50K+", label: "Published Blogs" },
    { number: "1M+", label: "Monthly Readers" },
    { number: "25+", label: "Countries" }
  ];

  return (
    <div>
      <Navbar/>
      
      {/* Hero Section */}
      <section className="bg-gradient-primary text-white py-5" style={{
        background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
        minHeight: '80vh',
        display: 'flex',
        alignItems: 'center'
      }}>
        <div className="container">
          <div className="row align-items-center">
            <div className="col-lg-6">
              <h1 className="display-3 fw-bold mb-4">
                Share Your Stories with the World
              </h1>
              <p className="lead mb-4 fs-4">
                BlogSpace is the perfect platform for writers, creators, and storytellers. 
                Create beautiful blogs, connect with readers, and grow your audience.
              </p>
              <div className="d-flex flex-wrap gap-3">
                <button 
                  className="btn btn-light btn-lg px-4 py-2 d-flex align-items-center"
                  onClick={() => window.location.href = '/signup'}
                >
                  Get Started Free <ArrowRight className="ms-2" size={20} />
                </button>
                <button 
                  className="btn btn-outline-light btn-lg px-4 py-2"
                  onClick={() => window.location.href = '#features'}
                >
                  Learn More
                </button>
              </div>
              <div className="mt-4 d-flex align-items-center">
                <div className="d-flex me-3">
                  {[1,2,3,4,5].map(star => (
                    <Star key={star} className="text-warning" size={20} fill="currentColor" />
                  ))}
                </div>
                <span className="small">Trusted by 10,000+ bloggers worldwide</span>
              </div>
            </div>
            <div className="col-lg-6">
              <div className="position-relative">
                <div className="bg-white rounded-4 shadow-lg p-4 mb-4">
                  <div className="d-flex align-items-center mb-3">
                    <div className="bg-primary rounded-circle p-2 me-3">
                      <BookOpen className="text-white" size={24} />
                    </div>
                    <div>
                      <h5 className="mb-1 text-dark">My Latest Blog Post</h5>
                      <p className="text-muted small mb-0">Published 2 hours ago</p>
                    </div>
                  </div>
                  <h6 className="text-dark mb-2">10 Tips for Better Content Writing</h6>
                  <p className="text-muted small mb-3">Discover the secrets to creating engaging content that keeps your readers coming back for more...</p>
                  <div className="d-flex justify-content-between align-items-center">
                    <div className="d-flex align-items-center">
                      <span className="badge bg-primary me-2">Writing Tips</span>
                      <span className="text-muted small">5 min read</span>
                    </div>
                    <div className="d-flex align-items-center text-muted small">
                      <Users size={16} className="me-1" />
                      1.2k views
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Stats Section */}
      <section className="py-4 bg-light">
        <div className="container">
          <div className="row text-center">
            {stats.map((stat, index) => (
              <div key={index} className="col-6 col-md-3 mb-3 mb-md-0">
                <h3 className="fw-bold text-primary mb-1">{stat.number}</h3>
                <p className="text-muted mb-0">{stat.label}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section id="features" className="py-5">
        <div className="container">
          <div className="row mb-5">
            <div className="col-lg-6 mx-auto text-center">
              <h2 className="display-5 fw-bold mb-3">Everything You Need to Blog</h2>
              <p className="lead text-muted">
                Powerful tools and features designed to help you create, share, and grow your blog
              </p>
            </div>
          </div>
          
          <div className="row g-4">
            {features.map((feature, index) => {
              const Icon = feature.icon;
              return (
                <div key={index} className="col-md-6 col-lg-4">
                  <div className="card border-0 shadow-sm h-100 hover-card">
                    <div className="card-body p-4 text-center">
                      <div className="bg-primary bg-opacity-10 rounded-circle d-inline-flex align-items-center justify-content-center mb-3" 
                           style={{width: '60px', height: '60px'}}>
                        <Icon className="text-primary" size={28} />
                      </div>
                      <h5 className="card-title mb-3">{feature.title}</h5>
                      <p className="card-text text-muted">{feature.description}</p>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </section>

      {/* How It Works Section */}
      <section className="py-5 bg-light">
        <div className="container">
          <div className="row mb-5">
            <div className="col-lg-6 mx-auto text-center">
              <h2 className="display-5 fw-bold mb-3">Start Blogging in 3 Simple Steps</h2>
            </div>
          </div>
          
          <div className="row g-4">
            <div className="col-md-4 text-center">
              <div className="position-relative mb-4">
                <div className="bg-primary rounded-circle d-inline-flex align-items-center justify-content-center text-white fw-bold" 
                     style={{width: '60px', height: '60px', fontSize: '24px'}}>
                  1
                </div>
              </div>
              <h5 className="fw-bold mb-3">Sign Up Free</h5>
              <p className="text-muted">Create your account in seconds and join our community of writers</p>
            </div>
            
            <div className="col-md-4 text-center">
              <div className="position-relative mb-4">
                <div className="bg-primary rounded-circle d-inline-flex align-items-center justify-content-center text-white fw-bold" 
                     style={{width: '60px', height: '60px', fontSize: '24px'}}>
                  2
                </div>
              </div>
              <h5 className="fw-bold mb-3">Write & Publish</h5>
              <p className="text-muted">Use our powerful editor to create beautiful, engaging blog posts</p>
            </div>
            
            <div className="col-md-4 text-center">
              <div className="position-relative mb-4">
                <div className="bg-primary rounded-circle d-inline-flex align-items-center justify-content-center text-white fw-bold" 
                     style={{width: '60px', height: '60px', fontSize: '24px'}}>
                  3
                </div>
              </div>
              <h5 className="fw-bold mb-3">Grow Your Audience</h5>
              <p className="text-muted">Share your content and connect with readers from around the world</p>
            </div>
          </div>
        </div>
      </section>

      {/* Testimonials Section */}
      <section className="py-5">
        <div className="container">
          <div className="row mb-5">
            <div className="col-lg-6 mx-auto text-center">
              <h2 className="display-5 fw-bold mb-3">What Our Bloggers Say</h2>
              <p className="lead text-muted">Join thousands of satisfied bloggers who love BlogSpace</p>
            </div>
          </div>
          
          <div className="row g-4">
            {testimonials.map((testimonial, index) => (
              <div key={index} className="col-lg-4">
                <div className="card border-0 shadow-sm h-100">
                  <div className="card-body p-4">
                    <div className="d-flex mb-3">
                      {[...Array(testimonial.rating)].map((_, i) => (
                        <Star key={i} className="text-warning me-1" size={16} fill="currentColor" />
                      ))}
                    </div>
                    <p className="card-text mb-4">"{testimonial.content}"</p>
                    <div className="d-flex align-items-center">
                      <div className="bg-primary rounded-circle d-flex align-items-center justify-content-center me-3" 
                           style={{width: '40px', height: '40px'}}>
                        <span className="text-white fw-bold">{testimonial.name.charAt(0)}</span>
                      </div>
                      <div>
                        <h6 className="mb-0">{testimonial.name}</h6>
                        <small className="text-muted">{testimonial.role}</small>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-5 bg-primary text-white">
        <div className="container text-center">
          <div className="row">
            <div className="col-lg-8 mx-auto">
              <h2 className="display-5 fw-bold mb-3">Ready to Start Your Blogging Journey?</h2>
              <p className="lead mb-4">
                Join BlogSpace today and start sharing your stories with the world. It's completely free to get started!
              </p>
              <div className="d-flex justify-content-center gap-3 flex-wrap">
                <button 
                  className="btn btn-light btn-lg px-4 py-2 d-flex align-items-center"
                  onClick={() => window.location.href = '/signup'}
                >
                  <CheckCircle className="me-2" size={20} />
                  Start Free Today
                </button>
                <button 
                  className="btn btn-outline-light btn-lg px-4 py-2"
                  onClick={() => window.location.href = '/login'}
                >
                  Already a member? Sign In
                </button>
              </div>
              <p className="mt-3 mb-0 small opacity-75">
                No credit card required • Free forever plan available
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="bg-dark text-white py-4">
        <div className="container">
          <div className="row align-items-center">
            <div className="col-md-6">
              <div className="d-flex align-items-center">
                <BookOpen className="me-2 text-primary" size={24} />
                <span className="fw-bold">BlogSpace</span>
              </div>
              <p className="text-muted small mt-2 mb-0">
                © 2025 BlogSpace. All rights reserved. Empowering writers worldwide.
              </p>
            </div>
            <div className="col-md-6 text-md-end mt-3 mt-md-0">
              <div className="d-flex justify-content-md-end justify-content-center gap-4">
                <button 
                  className="btn btn-link text-white-50 text-decoration-none small p-0 border-0"
                  onClick={() => console.log('Privacy Policy clicked')}
                >
                  Privacy Policy
                </button>
                <button 
                  className="btn btn-link text-white-50 text-decoration-none small p-0 border-0"
                  onClick={() => console.log('Terms of Service clicked')}
                >
                  Terms of Service
                </button>
                <button 
                  className="btn btn-link text-white-50 text-decoration-none small p-0 border-0"
                  onClick={() => console.log('Contact Us clicked')}
                >
                  Contact Us
                </button>
              </div>
            </div>
          </div>
        </div>
      </footer>

      <style jsx>{`
        .hover-card {
          transition: transform 0.2s ease-in-out;
        }
        .hover-card:hover {
          transform: translateY(-5px);
        }
        
        .bg-gradient-primary {
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }
        
        @keyframes fadeInUp {
          from {
            opacity: 0;
            transform: translateY(30px);
          }
          to {
            opacity: 1;
            transform: translateY(0);
          }
        }
        
        .card {
          animation: fadeInUp 0.6s ease-out;
        }
      `}</style>
    </div>
  );
};

export default Homepage;