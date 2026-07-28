const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());
app.use(cors()); // 모든 프론트엔드 통신 허용

// 💡 아까 만든 Render DB와 연결
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// 💡 텅 빈 DB에 유저 테이블을 자동으로 생성 (DBeaver 같은 프로그램 불필요)
pool.query(`
  CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL
  );
`).then(() => console.log("DB 테이블 준비 완료!"))
  .catch(err => console.error("테이블 생성 실패", err));

// 회원가입 엔드포인트
app.post('/api/auth/register', async (req, res) => {
    const { email, password } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = await pool.query(
            'INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id, email',
            [email, hashedPassword]
        );
        res.status(201).json({ message: "회원가입 완료", user: newUser.rows[0] });
    } catch (err) {
        res.status(500).json({ error: "이미 가입된 이메일이거나 서버 에러입니다." });
    }
});

// 로그인 엔드포인트
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const userResult = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (userResult.rows.length === 0) return res.status(401).json({ error: "존재하지 않는 유저입니다." });
        
        const validPassword = await bcrypt.compare(password, userResult.rows[0].password);
        if (!validPassword) return res.status(401).json({ error: "비밀번호가 틀렸습니다." });
        
        const token = jwt.sign({ userId: userResult.rows[0].id }, process.env.JWT_SECRET, { expiresIn: '24h' });
        res.json({ message: "로그인 성공!", token: token });
    } catch (err) {
        res.status(500).json({ error: "서버 에러입니다." });
    }
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`서버가 ${PORT}번 포트에서 돌아갑니다.`));
