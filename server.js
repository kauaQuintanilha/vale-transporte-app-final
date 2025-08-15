import express from 'express';
import dotenv from 'dotenv';
import mysql from 'mysql2/promise';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import path from 'path';
import { fileURLToPath } from 'url';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function main() {
  const app = express();
  app.use(express.json());
  app.use(express.static('public'));

  const db = await mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME
  });

  const authMiddleware = async (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token' });
    try {
      req.user = jwt.verify(token, process.env.JWT_SECRET);
      next();
    } catch {
      res.status(401).json({ error: 'Invalid token' });
    }
  };

  app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
  });

  app.post('/register', async (req, res) => {
    const { name, email, password } = req.body;
    try {
      const hash = await bcrypt.hash(password, 10);
      const [result] = await db.execute(
        'INSERT INTO users (name,email,password_hash) VALUES (?,?,?)',
        [name, email, hash]
      );
      await db.execute('INSERT INTO wallets (user_id, balance) VALUES (?,0)', [result.insertId]);
      res.json({ message: 'Cadastro realizado com sucesso!' });
    } catch (e) {
      res.status(400).json({ error: e.message });
    }
  });

  app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    try {
      const [rows] = await db.execute('SELECT * FROM users WHERE email=?', [email]);
      if (!rows[0]) return res.status(400).json({ error: 'Usuário não encontrado' });
      const valid = await bcrypt.compare(password, rows[0].password_hash);
      if (!valid) return res.status(400).json({ error: 'Senha incorreta' });
      const token = jwt.sign({ id: rows[0].id }, process.env.JWT_SECRET);
      res.json({ token });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  app.get('/api/wallet', authMiddleware, async (req, res) => {
    const [rows] = await db.execute('SELECT balance FROM wallets WHERE user_id=?', [req.user.id]);
    res.json(rows[0]);
  });

  app.post('/api/wallet/recharge', authMiddleware, async (req, res) => {
    const { amount } = req.body;
    try {
      await db.execute('UPDATE wallets SET balance = balance + ? WHERE user_id=?', [amount, req.user.id]);
      const [[wallet]] = await db.execute('SELECT id FROM wallets WHERE user_id=?', [req.user.id]);
      await db.execute('INSERT INTO transactions (wallet_id,type,amount) VALUES (?,?,?)', [wallet.id, 'recharge', amount]);
      res.json({ message: 'Recarga realizada!' });
    } catch (e) {
      res.status(400).json({ error: e.message });
    }
  });

  app.get('/api/wallet/history', authMiddleware, async (req, res) => {
    const [[wallet]] = await db.execute('SELECT id FROM wallets WHERE user_id=?', [req.user.id]);
    const [rows] = await db.execute(
      'SELECT id,type,amount,created_at FROM transactions WHERE wallet_id=? ORDER BY created_at DESC',
      [wallet.id]
    );
    res.json(rows);
  });

  const PORT = process.env.PORT || 8080;
  app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
}

main().catch(err => console.error(err));
