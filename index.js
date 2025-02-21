import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import mysql from 'mysql2/promise';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';

dotenv.config();

const app = express();

// Configure CORS for production
const corsOptions = {
  origin: process.env.FRONTEND_URL || 'http://localhost:5173',
  credentials: true,
  optionsSuccessStatus: 200
};

app.use(cors(corsOptions));
app.use(express.json());

// MySQL connection pool with SSL for production
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  ssl: process.env.NODE_ENV === 'production' ? {
    rejectUnauthorized: true
  } : undefined
});

// Health check endpoint for Render
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'healthy' });
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

// Auth routes
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const [users] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    
    if (users.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = users[0];
    const validPassword = await bcrypt.compare(password, user.password);
    
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '24h' });
    res.json({ token, user: { id: user.id, email: user.email } });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// User management routes
app.get('/api/users', authenticateToken, async (req, res) => {
  try {
    // Only super admin can list users
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Unauthorized' });
    }

    const [users] = await pool.query(
      'SELECT id, email, created_at FROM users ORDER BY created_at DESC'
    );
    res.json(users);
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/users', authenticateToken, async (req, res) => {
  try {
    // Only super admin can create users
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Unauthorized' });
    }

    const { email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    const [result] = await pool.query(
      'INSERT INTO users (email, password) VALUES (?, ?)',
      [email, hashedPassword]
    );

    const [user] = await pool.query(
      'SELECT id, email, created_at FROM users WHERE id = ?',
      [result.insertId]
    );

    res.status(201).json(user[0]);
  } catch (error) {
    console.error('Error creating user:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/users/:id', authenticateToken, async (req, res) => {
  try {
    // Only super admin can delete users
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Unauthorized' });
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
    const [pages] = await pool.query(
      'SELECT * FROM landing_pages WHERE user_id = ? ORDER BY created_at DESC',
      [req.user.id]
    );
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