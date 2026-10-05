'use strict';

document.addEventListener('DOMContentLoaded', () => {
  // 1. Detect if opened directly from filesystem (file://) instead of web server
  if (window.location.protocol === 'file:') {
    const warningEl = document.getElementById('file-protocol-warning');
    if (warningEl) {
      warningEl.style.display = 'block';
    }
    const btns = document.querySelectorAll('button[type="submit"]');
    btns.forEach((btn) => {
      btn.addEventListener('click', (e) => {
        e.preventDefault();
        alert('Notice: You opened index.html directly from your hard drive.\n\nPlease start the server by running "npm start" in your terminal and visit http://localhost:3000 to connect with the database.');
      });
    });
    return;
  }

  // 2. Fetch database status and show indicator
  fetch('/api/db-status')
    .then((r) => r.json())
    .then((data) => {
      const badges = document.querySelectorAll('.security-badge');
      badges.forEach((badge) => {
        const dbBadge = document.createElement('div');
        dbBadge.className = 'db-indicator-badge';
        dbBadge.style.cssText = 'margin-top: 8px; font-size: 0.8rem; opacity: 0.85; display: flex; align-items: center; justify-content: center; gap: 6px;';

        if (data.isSupabase) {
          dbBadge.innerHTML = '⚡ <span>Database: <strong>Supabase Cloud (PostgreSQL)</strong></span>';
          dbBadge.style.color = '#10b981';
        } else {
          dbBadge.innerHTML = '📁 <span>Database: <strong>Local Store (data.db.json)</strong></span>';
          dbBadge.style.color = '#94a3b8';
        }
        badge.parentNode.insertBefore(dbBadge, badge.nextSibling);
      });
    })
    .catch(() => { /* Silent fail */ });

  // 3. Check if already logged in
  SecureApp.api('/api/auth/me')
    .then(() => { window.location.href = '/dashboard'; })
    .catch(() => { /* Not logged in, stay on login view */ });

  // 4. Toggle views
  const showRegisterLink = document.getElementById('show-register');
  if (showRegisterLink) {
    showRegisterLink.addEventListener('click', (e) => {
      e.preventDefault();
      document.getElementById('login-view').style.display = 'none';
      document.getElementById('register-view').style.display = 'block';
    });
  }

  const showLoginLink = document.getElementById('show-login');
  if (showLoginLink) {
    showLoginLink.addEventListener('click', (e) => {
      e.preventDefault();
      document.getElementById('register-view').style.display = 'none';
      document.getElementById('login-view').style.display = 'block';
    });
  }

  // 5. Password requirements live checker
  const pwInput = document.getElementById('reg-password');
  if (pwInput) {
    pwInput.addEventListener('input', () => {
      const pw = pwInput.value;
      const reqs = {
        length: pw.length >= 8,
        lower: /[a-z]/.test(pw),
        upper: /[A-Z]/.test(pw),
        number: /[0-9]/.test(pw),
        special: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(pw),
      };
      Object.keys(reqs).forEach((key) => {
        const el = document.querySelector(`[data-req="${key}"]`);
        if (el) {
          el.classList.toggle('met', reqs[key]);
          const icon = el.querySelector('.password-req-icon');
          if (icon) icon.textContent = reqs[key] ? '✓' : '○';
        }
      });
    });
  }

  // 6. Login form
  const loginForm = document.getElementById('login-form');
  if (loginForm) {
    loginForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      e.stopPropagation();

      const btn = document.getElementById('login-btn');
      const originalText = btn.textContent;
      btn.disabled = true;
      btn.innerHTML = '<div class="spinner"></div> Signing in...';

      try {
        const data = await SecureApp.api('/api/auth/login', {
          method: 'POST',
          body: {
            username: document.getElementById('login-username').value.trim(),
            password: document.getElementById('login-password').value,
          },
        });
        SecureApp.toast('Welcome back!', `Hello, ${data.user.displayName}`, 'success');
        setTimeout(() => { window.location.href = '/dashboard'; }, 800);
      } catch (err) {
        SecureApp.toast('Login Failed', err.message, 'error');
        btn.disabled = false;
        btn.textContent = originalText;
      }
      return false;
    });
  }

  // 7. Register form
  const registerForm = document.getElementById('register-form');
  if (registerForm) {
    registerForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      e.stopPropagation();

      const btn = document.getElementById('register-btn');
      const originalText = btn.textContent;
      btn.disabled = true;
      btn.innerHTML = '<div class="spinner"></div> Creating account...';

      try {
        const data = await SecureApp.api('/api/auth/register', {
          method: 'POST',
          body: {
            displayName: document.getElementById('reg-display-name').value.trim(),
            username: document.getElementById('reg-username').value.trim(),
            email: document.getElementById('reg-email').value.trim(),
            password: document.getElementById('reg-password').value,
          },
        });
        SecureApp.toast('Account Created!', `Welcome, ${data.user.displayName}`, 'success');
        setTimeout(() => { window.location.href = '/dashboard'; }, 800);
      } catch (err) {
        SecureApp.toast('Registration Failed', err.message, 'error');
        btn.disabled = false;
        btn.textContent = originalText;
      }
      return false;
    });
  }
});
