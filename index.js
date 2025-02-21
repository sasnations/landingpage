import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import mysql from 'mysql2/promise';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';

dotenv.config();

const app = express();

// Configure CORS
const corsOptions = {
  origin: process.env.FRONTEND_URL || 'http://localhost:5173',
  credentials: true,
  optionsSuccessStatus: 200
};

app.use(cors(corsOptions));
app.use(express.json());

// MySQL connection pool
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Test database connection
async function testConnection() {
  try {
    const connection = await pool.getConnection();
    console.log('\x1b[32m%s\x1b[0m', '✓ Database connection successful');
    console.log('Connected to MySQL database at:', process.env.DB_HOST);
    connection.release();
    return true;
  } catch (error) {
    console.error('\x1b[31m%s\x1b[0m', '✗ Database connection failed');
    console.error('Error details:', error.message);
    return false;
  }
}

// Test connection on startup
testConnection();

// Database status endpoint
app.get('/api/status', async (req, res) => {
  const isConnected = await testConnection();
  res.json({
    status: isConnected ? 'connected' : 'disconnected',
    database: process.env.DB_NAME,
    host: process.env.DB_HOST
  });
});

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// Middleware to check if user is admin
const isAdmin = async (req, res, next) => {
  try {
    const [users] = await pool.query(
      'SELECT role FROM users WHERE id = ?',
      [req.user.id]
    );

    if (users.length === 0 || users[0].role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    next();
  } catch (error) {
    console.error('Error checking admin status:', error);
    res.status(500).json({ error: 'Server error' });
  }
};

// Auth routes
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const [users] = await pool.query(
      'SELECT id, email, password, role FROM users WHERE email = ?',
      [email]
    );
    
    if (users.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = users[0];
    const validPassword = await bcrypt.compare(password, user.password);
    
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { id: user.id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// User management routes (admin only)
app.post('/api/users', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { email, password, role = 'user' } = req.body;

    // Only admin can create other admins
    if (role === 'admin' && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Unauthorized to create admin users' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const [result] = await pool.query(
      'INSERT INTO users (email, password, role) VALUES (?, ?, ?)',
      [email, hashedPassword, role]
    );

    const [user] = await pool.query(
      'SELECT id, email, role, created_at FROM users WHERE id = ?',
      [result.insertId]
    );

    res.status(201).json(user[0]);
  } catch (error) {
    console.error('Error creating user:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get all users (admin only)
app.get('/api/users', authenticateToken, isAdmin, async (req, res) => {
  try {
    const [users] = await pool.query(
      'SELECT id, email, role, created_at FROM users ORDER BY created_at DESC'
    );
    res.json(users);
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Delete user (admin only)
app.delete('/api/users/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    // Prevent deleting the last admin
    const [admins] = await pool.query(
      'SELECT COUNT(*) as count FROM users WHERE role = "admin"'
    );
    const [user] = await pool.query(
      'SELECT role FROM users WHERE id = ?',
      [req.params.id]
    );

    if (
      admins[0].count === 1 &&
      user.length > 0 &&
      user[0].role === 'admin'
    ) {
      return res.status(400).json({ error: 'Cannot delete the last admin user' });
    }

    await pool.query('DELETE FROM users WHERE id = ?', [req.params.id]);
    res.status(204).send();
  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Landing pages routes
app.get('/api/pages', authenticateToken, async (req, res) => {
  try {
    const query = req.user.role === 'admin'
      ? 'SELECT * FROM landing_pages ORDER BY created_at DESC'
      : 'SELECT * FROM landing_pages WHERE user_id = ? ORDER BY created_at DESC';
    
    const params = req.user.role === 'admin' ? [] : [req.user.id];
    const [pages] = await pool.query(query, params);
    
    res.json(pages);
  } catch (error) {
    console.error('Error fetching pages:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/pages', authenticateToken, async (req, res) => {
  try {
    const { title, slug } = req.body;
    const [result] = await pool.query(
      'INSERT INTO landing_pages (user_id, title, slug) VALUES (?, ?, ?)',
      [req.user.id, title, slug]
    );
    
    const [page] = await pool.query(
      'SELECT * FROM landing_pages WHERE id = ?',
      [result.insertId]
    );
    
    res.status(201).json(page[0]);
  } catch (error) {
    console.error('Error creating page:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/pages/:slug', async (req, res) => {
  try {
    const [pages] = await pool.query(
      'SELECT * FROM landing_pages WHERE slug = ?',
      [req.params.slug]
    );
    
    if (pages.length === 0) {
      return res.status(404).json({ error: 'Page not found' });
    }

    const page = pages[0];
    const [sections] = await pool.query(
      'SELECT * FROM sections WHERE landing_page_id = ? ORDER BY `order`',
      [page.id]
    );

    res.json({ page, sections });
  } catch (error) {
    console.error('Error fetching page:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/pages/:id', authenticateToken, async (req, res) => {
  try {
    const { title, theme } = req.body;
    await pool.query(
      'UPDATE landing_pages SET title = ?, theme = ? WHERE id = ? AND user_id = ?',
      [title, JSON.stringify(theme), req.params.id, req.user.id]
    );
    
    const [pages] = await pool.query(
      'SELECT * FROM landing_pages WHERE id = ?',
      [req.params.id]
    );
    
    res.json(pages[0]);
  } catch (error) {
    console.error('Error updating page:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/pages/:id', authenticateToken, async (req, res) => {
  try {
    await pool.query(
      'DELETE FROM landing_pages WHERE id = ? AND user_id = ?',
      [req.params.id, req.user.id]
    );
    res.status(204).send();
  } catch (error) {
    console.error('Error deleting page:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Sections routes
app.get('/api/pages/:pageId/sections', async (req, res) => {
  try {
    const [sections] = await pool.query(
      'SELECT * FROM sections WHERE landing_page_id = ? ORDER BY `order`',
      [req.params.pageId]
    );
    res.json(sections);
  } catch (error) {
    console.error('Error fetching sections:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/sections', authenticateToken, async (req, res) => {
  try {
    const { landing_page_id, type, content, order } = req.body;
    
    // Verify user owns the landing page
    const [pages] = await pool.query(
      'SELECT * FROM landing_pages WHERE id = ? AND user_id = ?',
      [landing_page_id, req.user.id]
    );
    
    if (pages.length === 0) {
      return res.status(403).json({ error: 'Unauthorized' });
    }

    const [result] = await pool.query(
      'INSERT INTO sections (landing_page_id, type, content, `order`) VALUES (?, ?, ?, ?)',
      [landing_page_id, type, JSON.stringify(content), order]
    );
    
    const [section] = await pool.query(
      'SELECT * FROM sections WHERE id = ?',
      [result.insertId]
    );
    
    res.status(201).json(section[0]);
  } catch (error) {
    console.error('Error creating section:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
