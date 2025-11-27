const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET;

// === Middleware Autentikasi (Cek Token) ===
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Format: Bearer <token>

    if (token == null) {
        return res.status(401).json({ error: 'Token tidak ditemukan' });
    }

    jwt.verify(token, JWT_SECRET, (err, decodedPayload) => {
        if (err) {
            return res.status(403).json({ error: 'Token tidak valid' });
        }

        // Sekarang req.user berisi { id, username, role }
        req.user = decodedPayload.user;
        next();
    });
}

// === Middleware Autorisasi Role (Admin/User) ===
function authorizeRole(role) {
    return (req, res, next) => {
        // authorizeRole harus dipanggil SETELAH authenticateToken

        if (req.user && req.user.role === role) {
            return next(); // Role cocok → lanjut
        }

        // Role tidak cocok → akses dilarang
        return res.status(403).json({
            error: 'Akses Dilarang: Peran tidak memadai'
        });
    };
}

module.exports = {
    authenticateToken,
    authorizeRole
};
