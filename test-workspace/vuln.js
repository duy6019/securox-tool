// Vulnerable JavaScript file used as SAST fixture
// DO NOT use in production – these are intentionally bad patterns for testing

// 1. SQL Injection via string concatenation
function getUserById(id) {
  const query = "SELECT * FROM users WHERE id = " + id;  // noqa
  db.query(query);
}

// 2. XSS via innerHTML
function renderComment(comment) {
  document.getElementById('output').innerHTML = comment;  // noqa
}

// 3. Hardcoded credential
const DB_PASSWORD = "super_secret_password_123";  // noqa

module.exports = { getUserById, renderComment };
