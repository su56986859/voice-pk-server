// 优先加载环境变量（生产环境推荐系统环境变量，而非.env）
require('dotenv').config();

const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const sqlite3 = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto'); // 内置模块，无需安装

// 配置项
const PORT = process.env.PORT || 3000;

// 安全生成JWT密钥（生产环境从环境变量读取，开发环境自动生成）
let JWT_SECRET;
if (process.env.NODE_ENV === 'production' && process.env.JWT_SECRET) {
    JWT_SECRET = process.env.JWT_SECRET;
    console.log('✅ 生产环境 - 使用环境变量配置的JWT密钥');
} else {
    // 开发环境生成32字节随机密钥（256位）
    JWT_SECRET = crypto.randomBytes(32).toString('hex');
    console.warn('⚠️  开发环境 - 使用临时随机JWT密钥：', JWT_SECRET);
    console.warn('⚠️  生产环境请设置 JWT_SECRET 环境变量！');
}

const ADMIN_DEFAULT_ACCOUNT = 'admin';
const ADMIN_DEFAULT_PASSWORD = 'admin123';

// 初始化服务
const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });
const db = sqlite3('./voice_system.db');

// 开启SQLite WAL模式提升性能和稳定性（备份/恢复更安全）
db.pragma('journal_mode = WAL');
db.pragma('synchronous = NORMAL');

// 中间件配置
app.use(cors({
    // 生产环境指定具体域名，禁止通配符
    origin: process.env.NODE_ENV === 'production' 
        ? process.env.ALLOWED_ORIGIN || 'https://yourdomain.com' 
        : '*',
    credentials: true
}));
app.use(express.json({ limit: '1mb' })); // 限制请求体大小，防止攻击
app.use(express.static(path.join(__dirname, 'public')));

// 接口限流（防止注销/登录接口被恶意刷）
const rateLimit = new Map();
app.use((req, res, next) => {
    const ip = req.ip || req.connection.remoteAddress;
    const now = Date.now();
    const limitKey = `${ip}:${req.path}`;
    
    // 限制：1分钟最多10次请求
    if (rateLimit.has(limitKey)) {
        const lastTime = rateLimit.get(limitKey);
        if (now - lastTime < 60 * 1000 && rateLimit.get(`${limitKey}:count`) >= 10) {
            return res.status(429).json({ msg: '请求过于频繁，请1分钟后重试' });
        }
        // 更新计数
        rateLimit.set(`${limitKey}:count`, (rateLimit.get(`${limitKey}:count`) || 0) + 1);
    } else {
        rateLimit.set(limitKey, now);
        rateLimit.set(`${limitKey}:count`, 1);
    }
    
    // 清理过期记录（每小时执行一次）
    if (Math.random() < 0.01) { // 1%概率触发，避免性能损耗
        for (const [key, time] of rateLimit) {
            if (now - time > 60 * 1000) {
                rateLimit.delete(key);
                rateLimit.delete(`${key}:count`);
            }
        }
    }
    
    next();
});

// 初始化数据库表
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'user',
    status INTEGER DEFAULT 1,
    create_time DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS voice_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    avg_pitch REAL,
    min_pitch REAL,
    max_pitch REAL,
    stability REAL,
    voice_type TEXT,
    score INTEGER,
    create_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS pk_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    room_id TEXT,
    user1_id INTEGER,
    user2_id INTEGER,
    user1_score INTEGER,
    user2_score INTEGER,
    winner_id INTEGER,
    status TEXT DEFAULT 'waiting',
    create_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    end_time DATETIME
  );

  -- 新增操作日志表，记录注销等关键操作
  CREATE TABLE IF NOT EXISTS operation_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    operation TEXT NOT NULL,
    ip TEXT,
    user_agent TEXT,
    status TEXT DEFAULT 'success',
    create_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`);

// 初始化默认管理员账号
const adminExist = db.prepare('SELECT * FROM users WHERE username = ?').get(ADMIN_DEFAULT_ACCOUNT);
if (!adminExist) {
    const hashPwd = bcrypt.hashSync(ADMIN_DEFAULT_PASSWORD, 10);
    db.prepare('INSERT INTO users (username, password, role) VALUES (?, ?, ?)').run(ADMIN_DEFAULT_ACCOUNT, hashPwd, 'admin');
    console.log('✅ 默认管理员账号创建成功：账号 admin 密码 admin123');
}

// JWT鉴权中间件
const auth = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ msg: '未登录，请先登录' });
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (e) {
        console.error('JWT验证失败：', e.message);
        return res.status(401).json({ msg: '登录已失效，请重新登录' });
    }
};

// 管理员鉴权中间件
const adminAuth = (req, res, next) => {
    auth(req, res, () => {
        if (req.user.role !== 'admin') return res.status(403).json({ msg: '无管理员权限' });
        next();
    });
};

// ==================== 用户接口 ====================
// 注册
app.post('/api/register', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ msg: '账号密码不能为空' });
    if (username.length < 3 || password.length < 6) return res.status(400).json({ msg: '账号至少3位，密码至少6位' });

    try {
        const hashPwd = bcrypt.hashSync(password, 10);
        db.prepare('INSERT INTO users (username, password) VALUES (?, ?)').run(username, hashPwd);
        res.json({ msg: '注册成功' });
    } catch (e) {
        res.status(400).json({ msg: '账号已存在' });
    }
});

// 登录（JWT过期时间缩短为2小时，提升安全性）
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    if (!user) return res.status(400).json({ msg: '账号不存在' });
    if (user.status !== 1) return res.status(400).json({ msg: '账号已被封禁' });
    if (!bcrypt.compareSync(password, user.password)) return res.status(400).json({ msg: '密码错误' });

    const token = jwt.sign(
        { id: user.id, username: user.username, role: user.role },
        JWT_SECRET,
        { expiresIn: '2h' } // 生产环境建议2小时过期
    );
    
    // 记录登录日志
    db.prepare(`
        INSERT INTO operation_logs (user_id, operation, ip, user_agent)
        VALUES (?, 'login', ?, ?)
    `).run(user.id, req.ip, req.headers['user-agent']);

    res.json({ token, username: user.username, role: user.role, msg: '登录成功' });
});

// 保存音色分析记录
app.post('/api/save-record', auth, (req, res) => {
    const { avg_pitch, min_pitch, max_pitch, stability, voice_type, score } = req.body;
    db.prepare(`
        INSERT INTO voice_records (user_id, avg_pitch, min_pitch, max_pitch, stability, voice_type, score)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(req.user.id, avg_pitch, min_pitch, max_pitch, stability, voice_type, score);
    res.json({ msg: '记录保存成功' });
});

// 获取我的记录
app.get('/api/my-records', auth, (req, res) => {
    const records = db.prepare('SELECT * FROM voice_records WHERE user_id = ? ORDER BY create_time DESC LIMIT 20').all(req.user.id);
    res.json(records);
});

// 排行榜
app.get('/api/rank', auth, (req, res) => {
    const rank = db.prepare(`
        SELECT u.username, MAX(v.score) as max_score, COUNT(v.id) as total_count
        FROM voice_records v
        LEFT JOIN users u ON v.user_id = u.id
        WHERE u.status = 1
        GROUP BY v.user_id
        ORDER BY max_score DESC
        LIMIT 20
    `).all();
    res.json(rank);
});

// 注销账号接口（带日志记录）
app.post('/api/delete-account', auth, (req, res) => {
    const { password } = req.body;
    const userId = req.user.id;
    const ip = req.ip;
    const userAgent = req.headers['user-agent'];
    
    // 1. 验证密码
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
    if (!user) {
        // 记录失败日志
        db.prepare(`
            INSERT INTO operation_logs (user_id, operation, ip, user_agent, status)
            VALUES (?, 'delete_account', ?, ?, 'fail')
        `).run(userId, ip, userAgent);
        return res.status(400).json({ msg: '用户不存在' });
    }
    if (!bcrypt.compareSync(password, user.password)) {
        // 记录失败日志
        db.prepare(`
            INSERT INTO operation_logs (user_id, operation, ip, user_agent, status)
            VALUES (?, 'delete_account', ?, ?, 'fail')
        `).run(userId, ip, userAgent);
        return res.status(400).json({ msg: '密码错误' });
    }
    
    // 2. 禁止注销管理员账号
    if (user.role === 'admin') {
        db.prepare(`
            INSERT INTO operation_logs (user_id, operation, ip, user_agent, status)
            VALUES (?, 'delete_account', ?, ?, 'fail')
        `).run(userId, ip, userAgent);
        return res.status(403).json({ msg: '管理员账号不允许注销' });
    }
    
    try {
        // 3. 开启事务，级联删除用户数据
        const transaction = db.transaction(() => {
            // 删除音色记录
            db.prepare('DELETE FROM voice_records WHERE user_id = ?').run(userId);
            // 更新PK记录（匿名化）
            db.prepare('UPDATE pk_records SET user1_id = NULL WHERE user1_id = ?').run(userId);
            db.prepare('UPDATE pk_records SET user2_id = NULL WHERE user2_id = ?').run(userId);
            db.prepare('UPDATE pk_records SET winner_id = NULL WHERE winner_id = ?').run(userId);
            // 记录注销日志
            db.prepare(`
                INSERT INTO operation_logs (user_id, operation, ip, user_agent)
                VALUES (?, 'delete_account', ?, ?)
            `).run(userId, ip, userAgent);
            // 删除用户
            db.prepare('DELETE FROM users WHERE id = ?').run(userId);
        });
        
        transaction();
        
        res.json({ msg: '账号注销成功' });
    } catch (e) {
        console.error('注销账号失败:', e);
        db.prepare(`
            INSERT INTO operation_logs (user_id, operation, ip, user_agent, status)
            VALUES (?, 'delete_account', ?, ?, 'fail')
        `).run(userId, ip, userAgent);
        res.status(500).json({ msg: '服务器错误，注销失败' });
    }
});

// ==================== 管理员接口 ====================
// 获取所有用户
app.get('/api/admin/users', adminAuth, (req, res) => {
    const users = db.prepare('SELECT id, username, role, status, create_time FROM users ORDER BY create_time DESC').all();
    res.json(users);
});

// 封禁/解封用户
app.post('/api/admin/user-status', adminAuth, (req, res) => {
    const { user_id, status } = req.body;
    // 禁止修改管理员状态
    const user = db.prepare('SELECT role FROM users WHERE id = ?').get(user_id);
    if (user && user.role === 'admin') {
        return res.status(403).json({ msg: '禁止修改管理员状态' });
    }
    db.prepare('UPDATE users SET status = ? WHERE id = ?').run(status, user_id);
    res.json({ msg: '操作成功' });
});

// 重置用户密码
app.post('/api/admin/reset-pwd', adminAuth, (req, res) => {
    const { user_id, new_pwd } = req.body;
    // 禁止重置管理员密码
    const user = db.prepare('SELECT role FROM users WHERE id = ?').get(user_id);
    if (user && user.role === 'admin') {
        return res.status(403).json({ msg: '禁止重置管理员密码' });
    }
    const hashPwd = bcrypt.hashSync(new_pwd, 10);
    db.prepare('UPDATE users SET password = ? WHERE id = ?').run(hashPwd, user_id);
    res.json({ msg: '密码重置成功' });
});

// 获取所有PK记录
app.get('/api/admin/pk-records', adminAuth, (req, res) => {
    const records = db.prepare(`
        SELECT p.*, u1.username as user1_name, u2.username as user2_name, uw.username as winner_name
        FROM pk_records p
        LEFT JOIN users u1 ON p.user1_id = u1.id
        LEFT JOIN users u2 ON p.user2_id = u2.id
        LEFT JOIN users uw ON p.winner_id = uw.id
        ORDER BY create_time DESC
        LIMIT 100
    `).all();
    res.json(records);
});

// 获取操作日志
app.get('/api/admin/logs', adminAuth, (req, res) => {
    const logs = db.prepare(`
        SELECT l.*, u.username 
        FROM operation_logs l
        LEFT JOIN users u ON l.user_id = u.id
        ORDER BY create_time DESC
        LIMIT 100
    `).all();
    res.json(logs);
});

// ==================== WebSocket 实时PK系统 ====================
const pkRooms = new Map(); // 房间列表
const userSocketMap = new Map(); // 用户ID和socket映射

// 定时清理无效房间（每分钟）
setInterval(() => {
    const now = Date.now();
    for (const [roomId, room] of pkRooms) {
        // 超过5分钟未活动的房间直接清理
        if (room.createTime && now - room.createTime > 5 * 60 * 1000) {
            pkRooms.delete(roomId);
            console.log(`清理无效房间：${roomId}`);
        }
    }
}, 60 * 1000);

wss.on('connection', (ws, req) => {
    let currentUser = null;
    console.log('新的WebSocket连接');

    // 消息处理
    ws.on('message', (data) => {
        try {
            const msg = JSON.parse(data);
            const { type, token, payload } = msg;

            // 鉴权
            if (type === 'auth') {
                try {
                    const decoded = jwt.verify(token, JWT_SECRET);
                    currentUser = decoded;
                    userSocketMap.set(currentUser.id, ws);
                    ws.send(JSON.stringify({ type: 'auth_success', msg: '连接成功' }));
                } catch (e) {
                    ws.send(JSON.stringify({ type: 'auth_fail', msg: '鉴权失败' }));
                }
                return;
            }

            if (!currentUser) {
                ws.send(JSON.stringify({ type: 'error', msg: '请先登录' }));
                return;
            }

            // 匹配PK
            if (type === 'pk_match') {
                // 查找等待中的房间
                let waitingRoom = null;
                for (const [roomId, room] of pkRooms) {
                    if (room.status === 'waiting' && room.user1 !== currentUser.id) {
                        waitingRoom = room;
                        break;
                    }
                }

                if (waitingRoom) {
                    // 加入房间
                    waitingRoom.user2 = currentUser.id;
                    waitingRoom.status = 'fighting';
                    pkRooms.set(waitingRoom.roomId, waitingRoom);

                    // 通知双方
                    const user1Ws = userSocketMap.get(waitingRoom.user1);
                    const user2Ws = userSocketMap.get(waitingRoom.user2);
                    const user1Info = db.prepare('SELECT username FROM users WHERE id = ?').get(waitingRoom.user1);
                    const user2Info = db.prepare('SELECT username FROM users WHERE id = ?').get(waitingRoom.user2);

                    if (user1Ws) user1Ws.send(JSON.stringify({
                        type: 'pk_start',
                        payload: { roomId: waitingRoom.roomId, opponent: user2Info.username }
                    }));
                    if (user2Ws) user2Ws.send(JSON.stringify({
                        type: 'pk_start',
                        payload: { roomId: waitingRoom.roomId, opponent: user1Info.username }
                    }));

                    // 写入数据库
                    db.prepare('INSERT INTO pk_records (room_id, user1_id, user2_id, status) VALUES (?, ?, ?, ?)').run(
                        waitingRoom.roomId, waitingRoom.user1, waitingRoom.user2, 'fighting'
                    );
                } else {
                    // 创建新房间
                    const roomId = 'pk_' + Date.now() + '_' + Math.random().toString(36).slice(2, 8);
                    pkRooms.set(roomId, {
                        roomId,
                        user1: currentUser.id,
                        user2: null,
                        status: 'waiting',
                        user1_score: 0,
                        user2_score: 0,
                        createTime: Date.now() // 记录创建时间，用于清理
                    });
                    ws.send(JSON.stringify({ type: 'pk_waiting', msg: '正在匹配对手...' }));
                }
                return;
            }

            // 取消PK匹配
            if (type === 'pk_cancel') {
                // 查找用户创建的房间
                for (const [roomId, room] of pkRooms) {
                    if (room.user1 === currentUser.id && room.status === 'waiting') {
                        pkRooms.delete(roomId);
                        ws.send(JSON.stringify({ type: 'success', msg: '已取消匹配' }));
                        break;
                    }
                }
                return;
            }

            // 提交PK分数
            if (type === 'pk_submit_score') {
                const { roomId, score } = payload;
                const room = pkRooms.get(roomId);
                
                if (!room) {
                    ws.send(JSON.stringify({ type: 'error', msg: '房间不存在' }));
                    return;
                }

                // 更新分数
                if (room.user1 === currentUser.id) {
                    room.user1_score = score;
                } else if (room.user2 === currentUser.id) {
                    room.user2_score = score;
                } else {
                    ws.send(JSON.stringify({ type: 'error', msg: '你不是该房间成员' }));
                    return;
                }

                pkRooms.set(roomId, room);

                // 检查双方是否都提交了分数
                if (room.user1_score > 0 && room.user2_score > 0) {
                    // 判定胜负
                    let winnerId = room.user1_score > room.user2_score ? room.user1 : room.user2;
                    let loserId = winnerId === room.user1 ? room.user2 : room.user1;
                    
                    // 通知双方结果
                    const winnerWs = userSocketMap.get(winnerId);
                    const loserWs = userSocketMap.get(loserId);
                    
                    if (winnerWs) {
                        winnerWs.send(JSON.stringify({
                            type: 'pk_result',
                            payload: {
                                win: true,
                                myScore: winnerId === room.user1 ? room.user1_score : room.user2_score,
                                opponentScore: winnerId === room.user1 ? room.user2_score : room.user1_score
                            }
                        }));
                    }
                    
                    if (loserWs) {
                        loserWs.send(JSON.stringify({
                            type: 'pk_result',
                            payload: {
                                win: false,
                                myScore: loserId === room.user1 ? room.user1_score : room.user2_score,
                                opponentScore: loserId === room.user1 ? room.user2_score : room.user1_score
                            }
                        }));
                    }

                    // 更新数据库
                    db.prepare(`
                        UPDATE pk_records 
                        SET user1_score = ?, user2_score = ?, winner_id = ?, status = 'finished', end_time = CURRENT_TIMESTAMP
                        WHERE room_id = ?
                    `).run(room.user1_score, room.user2_score, winnerId, roomId);

                    // 删除房间
                    pkRooms.delete(roomId);
                } else {
                    ws.send(JSON.stringify({ type: 'success', msg: '分数已提交，等待对手...' }));
                }
                return;
            }

        } catch (e) {
            console.error('WebSocket消息处理错误:', e);
            ws.send(JSON.stringify({ type: 'error', msg: '处理失败，请重试' }));
        }
    });

    // 断开连接
    ws.on('close', () => {
        console.log('WebSocket连接关闭');
        if (currentUser) {
            userSocketMap.delete(currentUser.id);
            
            // 清理用户的等待房间
            for (const [roomId, room] of pkRooms) {
                if (room.user1 === currentUser.id && room.status === 'waiting') {
                    pkRooms.delete(roomId);
                    break;
                }
            }
        }
    });

    // 错误处理
    ws.on('error', (error) => {
        console.error('WebSocket错误:', error);
    });
});

// 健康检查接口（用于服务器监控）
app.get('/health', (req, res) => {
    res.json({ status: 'ok', time: new Date().toISOString() });
});

// 启动服务器
server.listen(PORT, () => {
    console.log(`✅ 服务器运行在 http://localhost:${PORT}`);
    console.log(`🔒 运行环境：${process.env.NODE_ENV || 'development'}`);
    console.log(`📊 管理员后台地址: http://localhost:${PORT}/admin.html`);
});

// 优雅关闭（保证数据不丢失）
process.on('SIGINT', () => {
    console.log('\n🛑 正在关闭服务器...');
    // 关闭数据库连接
    db.close();
    // 关闭WebSocket服务器
    wss.close();
    // 关闭HTTP服务器
    server.close(() => {
        console.log('✅ 服务器已安全关闭');
        process.exit(0);
    });
});
