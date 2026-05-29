const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { WebSocketServer } = require('ws');
const http = require('http');
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);
const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });
const clients = new Set();

app.use(cors());
app.use(express.json());

wss.on('connection', ws => {
  clients.add(ws);
  ws.on('close', () => clients.delete(ws));
});

function broadcast(type, data) {
  const msg = JSON.stringify({ type, data });
  clients.forEach(c => { if (c.readyState === 1) c.send(msg); });
}

function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Please log in' });
  try { req.user = jwt.verify(token, process.env.JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Session expired, please log in again' }); }
}

// LOGIN
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const { data: users } = await supabase.from('users').select('*').eq('username', username);
  if (!users?.length) return res.status(401).json({ error: 'Username not found' });
  const user = users[0];
  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(401).json({ error: 'Wrong password' });
  const token = jwt.sign({ id: user.id, name: user.name, role: user.role, am_id: user.am_id, sm_id: user.sm_id }, process.env.JWT_SECRET, { expiresIn: '8h' });
  res.json({ token, user: { name: user.name, role: user.role, am_id: user.am_id } });
});

// WEEKLY DATA
app.get('/api/weekly', auth, async (req, res) => {
  let query = supabase.from('weekly_data').select('*').order('created_at', { ascending: false });
  if (req.user.role === 'am') query = query.eq('am_id', req.user.am_id);
  if (req.user.role === 'sm') query = query.eq('sm_id', req.user.sm_id);
  const { data, error } = await query;
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/weekly', auth, async (req, res) => {
  const row = { ...req.body, am_id: req.user.am_id, sm_id: req.user.sm_id };
  const { data, error } = await supabase.from('weekly_data').insert(row).select();
  if (error) return res.status(500).json({ error: error.message });
  broadcast('weekly_updated', data[0]);
  res.json(data[0]);
});

// MONTHLY DATA
app.get('/api/monthly', auth, async (req, res) => {
  let query = supabase.from('monthly_data').select('*').order('year').order('month');
  if (req.user.role === 'am') query = query.eq('am_id', req.user.am_id);
  if (req.user.role === 'sm') query = query.eq('sm_id', req.user.sm_id);
  const { data, error } = await query;
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/monthly', auth, async (req, res) => {
  const { data, error } = await supabase.from('monthly_data').insert(req.body).select();
  if (error) return res.status(500).json({ error: error.message });
  broadcast('monthly_updated', data[0]);
  res.json(data[0]);
});

// TARGETS
app.get('/api/targets', auth, async (req, res) => {
  const { data, error } = await supabase.from('am_targets').select('*');
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// CREATE USER (admin only)
app.post('/api/users', auth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admins only' });
  const hashed = await bcrypt.hash(req.body.password, 10);
  const { data, error } = await supabase.from('users').insert({ ...req.body, password: hashed }).select();
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true, id: data[0].id });
});

const PORT = process.env.PORT || 3001;
server.listen(PORT, () => console.log('Tata IIS server running on port', PORT));