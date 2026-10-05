/**
 * SecureApp — Frontend JavaScript
 * 
 * Security practices in this file:
 * - NEVER uses innerHTML (XSS prevention) — all DOM mutations use textContent/createElement
 * - Always includes CSRF token in state-changing requests
 * - Client-side validation as defense in depth (server is the authority)
 * - No eval(), no Function(), no dynamic script injection
 */

'use strict';

// ═══════════════════════════════════════════════════════════════════
// SecureApp — Global API & Utility Layer
// ═══════════════════════════════════════════════════════════════════

const SecureApp = (() => {
  let csrfToken = null;

  /**
   * Fetch a CSRF token from the server.
   * Must be called before any POST/PUT/DELETE request.
   */
  async function fetchCsrfToken() {
    const res = await fetch('/api/csrf-token', {
      credentials: 'same-origin',
    });
    const data = await res.json();
    csrfToken = data.token;
    return csrfToken;
  }

  /**
   * Make an API request with CSRF token and proper error handling.
   * No raw fetch() calls elsewhere — all API communication goes through this.
   */
  async function api(url, options = {}) {
    const { method = 'GET', body } = options;

    // Fetch CSRF token for state-changing requests
    if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(method)) {
      if (!csrfToken) {
        await fetchCsrfToken();
      }
    }

    const fetchOptions = {
      method,
      credentials: 'same-origin',
      headers: {
        'Content-Type': 'application/json',
      },
    };

    if (csrfToken) {
      fetchOptions.headers['x-csrf-token'] = csrfToken;
    }

    if (body) {
      fetchOptions.body = JSON.stringify(body);
    }

    const res = await fetch(url, fetchOptions);
    const data = await res.json();

    if (!res.ok) {
      // Refresh CSRF token on 403 (might be expired)
      if (res.status === 403) {
        csrfToken = null;
      }
      // Redirect to login on 401
      if (res.status === 401 && !url.includes('/auth/')) {
        window.location.href = '/';
        throw new Error('Session expired');
      }
      throw new Error(data.error || 'Something went wrong');
    }

    return data;
  }

  /**
   * Display a toast notification.
   * Uses textContent (never innerHTML) to prevent XSS.
   */
  function toast(title, message, type = 'info') {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const icons = {
      success: '✅',
      error: '❌',
      warning: '⚠️',
      info: 'ℹ️',
    };

    const toastEl = document.createElement('div');
    toastEl.className = `toast ${type}`;

    const iconEl = document.createElement('span');
    iconEl.className = 'toast-icon';
    iconEl.textContent = icons[type] || icons.info;

    const contentEl = document.createElement('div');
    contentEl.className = 'toast-content';

    const titleEl = document.createElement('div');
    titleEl.className = 'toast-title';
    titleEl.textContent = title; // textContent = XSS safe

    const msgEl = document.createElement('div');
    msgEl.className = 'toast-message';
    msgEl.textContent = message; // textContent = XSS safe

    contentEl.appendChild(titleEl);
    contentEl.appendChild(msgEl);
    toastEl.appendChild(iconEl);
    toastEl.appendChild(contentEl);
    container.appendChild(toastEl);

    // Auto remove after 5s
    setTimeout(() => {
      toastEl.classList.add('removing');
      setTimeout(() => toastEl.remove(), 300);
    }, 5000);
  }

  /**
   * Safely set text content of an element by ID.
   * Never uses innerHTML.
   */
  function setText(id, text) {
    const el = document.getElementById(id);
    if (el) el.textContent = text;
  }

  /**
   * Safely escape text for display (defense in depth).
   */
  function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/[&<>"']/g, (match) => {
      const escapes = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
      return escapes[match];
    });
  }

  return { api, toast, setText, escapeHtml, fetchCsrfToken };
})();

// ═══════════════════════════════════════════════════════════════════
// Dashboard Controller
// ═══════════════════════════════════════════════════════════════════

class Dashboard {
  constructor() {
    this.user = null;
    this.tasks = [];
    this.stats = {};
    this.currentFilter = 'all';
    this.editingTaskId = null;
    this.deletingTaskId = null;
  }

  async init() {
    try {
      // Check authentication
      const authData = await SecureApp.api('/api/auth/me');
      this.user = authData.user;
      this.renderUserInfo();
      await this.loadTasks();
      this.bindEvents();
      this.setupPasswordChecker();
      this.renderDbStatus();
    } catch (err) {
      // Not authenticated — redirect to login
      window.location.href = '/';
    }
  }

  async renderDbStatus() {
    try {
      const res = await fetch('/api/db-status');
      const data = await res.json();
      const sidebarFooter = document.querySelector('.sidebar-footer');
      if (sidebarFooter && !document.getElementById('sidebar-db-badge')) {
        const badge = document.createElement('div');
        badge.id = 'sidebar-db-badge';
        badge.style.cssText = 'font-size: 0.75rem; padding: 6px 10px; margin-bottom: 8px; border-radius: 6px; background: rgba(255,255,255,0.05); display: flex; align-items: center; gap: 6px;';
        if (data.isSupabase) {
          badge.innerHTML = '⚡ <span style="color: #10b981; font-weight: 600;">Supabase Cloud DB</span>';
        } else {
          badge.innerHTML = '📁 <span style="color: #94a3b8;">Local DB (data.db.json)</span>';
        }
        sidebarFooter.insertBefore(badge, sidebarFooter.firstChild);
      }
    } catch (e) {}
  }

  // ─── Data Loading ──────────────────────────────────────────

  async loadTasks() {
    try {
      const data = await SecureApp.api('/api/tasks');
      this.tasks = data.tasks || [];
      this.stats = data.stats || {};
      this.renderStats();
      this.renderTasks();
    } catch (err) {
      SecureApp.toast('Error', 'Failed to load tasks', 'error');
    }
  }

  // ─── Rendering (all XSS-safe via textContent/createElement) ─

  renderUserInfo() {
    if (!this.user) return;
    const initials = this.user.displayName
      ? this.user.displayName.split(' ').map((n) => n[0]).join('').toUpperCase().slice(0, 2)
      : '?';

    SecureApp.setText('sidebar-username', this.user.displayName || this.user.username);
    SecureApp.setText('sidebar-email', this.user.email);
    SecureApp.setText('sidebar-avatar', initials);
    SecureApp.setText('profile-avatar', initials);
    SecureApp.setText('profile-display-name', this.user.displayName);

    if (this.user.createdAt) {
      const joined = new Date(this.user.createdAt).toLocaleDateString('en-US', {
        year: 'numeric', month: 'long', day: 'numeric',
      });
      SecureApp.setText('profile-joined', `Member since ${joined}`);
    }

    const editName = document.getElementById('edit-display-name');
    const editEmail = document.getElementById('edit-email');
    if (editName) editName.value = this.user.displayName || '';
    if (editEmail) editEmail.value = this.user.email || '';
  }

  renderStats() {
    SecureApp.setText('stat-total', this.stats.total || 0);
    SecureApp.setText('stat-pending', this.stats.pending || 0);
    SecureApp.setText('stat-progress', this.stats.in_progress || 0);
    SecureApp.setText('stat-completed', this.stats.completed || 0);
    SecureApp.setText('task-count-badge', this.stats.total || 0);
  }

  renderTasks() {
    const container = document.getElementById('task-list');
    if (!container) return;

    // Clear container safely
    while (container.firstChild) {
      container.removeChild(container.firstChild);
    }

    // Filter tasks
    let filtered = this.tasks;
    if (this.currentFilter !== 'all') {
      filtered = this.tasks.filter((t) => t.status === this.currentFilter);
    }

    if (filtered.length === 0) {
      const emptyDiv = document.createElement('div');
      emptyDiv.className = 'empty-state';

      const iconDiv = document.createElement('div');
      iconDiv.className = 'empty-state-icon';
      iconDiv.textContent = this.currentFilter === 'all' ? '📝' : '🔍';

      const h3 = document.createElement('h3');
      h3.textContent = this.currentFilter === 'all'
        ? 'No tasks yet'
        : `No ${this.currentFilter.replace('_', ' ')} tasks`;

      const p = document.createElement('p');
      p.textContent = this.currentFilter === 'all'
        ? 'Create your first task to get started!'
        : 'Tasks matching this filter will appear here.';

      emptyDiv.appendChild(iconDiv);
      emptyDiv.appendChild(h3);
      emptyDiv.appendChild(p);

      if (this.currentFilter === 'all') {
        const btn = document.createElement('button');
        btn.className = 'btn btn-primary';
        btn.textContent = '+ Create Task';
        btn.addEventListener('click', () => this.openTaskModal());
        emptyDiv.appendChild(btn);
      }

      container.appendChild(emptyDiv);
      return;
    }

    filtered.forEach((task) => {
      container.appendChild(this.createTaskElement(task));
    });
  }

  createTaskElement(task) {
    const card = document.createElement('div');
    card.className = `glass-card task-card ${task.status === 'completed' ? 'completed' : ''}`;
    card.dataset.taskId = task.id;

    // Checkbox
    const checkbox = document.createElement('button');
    checkbox.className = `task-checkbox ${task.status === 'completed' ? 'checked' : ''}`;
    checkbox.textContent = task.status === 'completed' ? '✓' : '';
    checkbox.setAttribute('aria-label', 'Toggle task completion');
    checkbox.addEventListener('click', (e) => {
      e.stopPropagation();
      this.toggleTaskStatus(task);
    });

    // Content
    const content = document.createElement('div');
    content.className = 'task-content';

    const title = document.createElement('div');
    title.className = 'task-title';
    title.textContent = task.title; // XSS safe

    const meta = document.createElement('div');
    meta.className = 'task-meta';

    // Priority badge
    const priority = document.createElement('span');
    priority.className = `task-priority ${task.priority}`;
    const priorityLabels = { low: '● Low', medium: '● Medium', high: '● High', urgent: '● Urgent' };
    priority.textContent = priorityLabels[task.priority] || task.priority;

    meta.appendChild(priority);

    // Due date
    if (task.dueDate) {
      const dueSpan = document.createElement('span');
      const dueDate = new Date(task.dueDate);
      const isOverdue = dueDate < new Date() && task.status !== 'completed';
      dueSpan.className = `task-due ${isOverdue ? 'overdue' : ''}`;
      dueSpan.textContent = `📅 ${dueDate.toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}`;
      meta.appendChild(dueSpan);
    }

    content.appendChild(title);

    if (task.description) {
      const desc = document.createElement('div');
      desc.className = 'task-due';
      desc.style.marginTop = '4px';
      desc.textContent = task.description.length > 80
        ? task.description.substring(0, 80) + '…'
        : task.description;
      content.appendChild(desc);
    }

    content.appendChild(meta);

    // Status badge
    const statusBadge = document.createElement('span');
    statusBadge.className = `task-status-badge ${task.status}`;
    const statusLabels = { pending: 'Pending', in_progress: 'In Progress', completed: 'Completed' };
    statusBadge.textContent = statusLabels[task.status] || task.status;

    // Actions
    const actions = document.createElement('div');
    actions.className = 'task-actions';

    const editBtn = document.createElement('button');
    editBtn.className = 'task-action-btn';
    editBtn.textContent = '✏️';
    editBtn.setAttribute('aria-label', 'Edit task');
    editBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      this.openTaskModal(task);
    });

    const deleteBtn = document.createElement('button');
    deleteBtn.className = 'task-action-btn delete';
    deleteBtn.textContent = '🗑️';
    deleteBtn.setAttribute('aria-label', 'Delete task');
    deleteBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      this.confirmDelete(task.id);
    });

    actions.appendChild(editBtn);
    actions.appendChild(deleteBtn);

    card.appendChild(checkbox);
    card.appendChild(content);
    card.appendChild(statusBadge);
    card.appendChild(actions);

    return card;
  }

  // ─── Task Operations ──────────────────────────────────────

  async toggleTaskStatus(task) {
    const newStatus = task.status === 'completed' ? 'pending' : 'completed';
    try {
      await SecureApp.api(`/api/tasks/${task.id}`, {
        method: 'PUT',
        body: { status: newStatus },
      });
      await this.loadTasks();
      SecureApp.toast(
        newStatus === 'completed' ? 'Task Completed!' : 'Task Reopened',
        task.title,
        'success'
      );
    } catch (err) {
      SecureApp.toast('Error', err.message, 'error');
    }
  }

  openTaskModal(task = null) {
    const modal = document.getElementById('task-modal');
    const form = document.getElementById('task-form');
    const statusGroup = document.getElementById('task-status-group');

    // Reset form
    form.reset();
    document.getElementById('task-edit-id').value = '';

    if (task) {
      // Edit mode
      this.editingTaskId = task.id;
      SecureApp.setText('modal-title', 'Edit Task');
      const submitBtn = document.getElementById('modal-submit');
      submitBtn.textContent = 'Save Changes';

      document.getElementById('task-edit-id').value = task.id;
      document.getElementById('task-title').value = task.title;
      document.getElementById('task-description').value = task.description || '';
      document.getElementById('task-priority').value = task.priority;
      document.getElementById('task-due-date').value = task.dueDate || '';
      document.getElementById('task-status').value = task.status;
      statusGroup.style.display = 'block';
    } else {
      // Create mode
      this.editingTaskId = null;
      SecureApp.setText('modal-title', 'New Task');
      const submitBtn = document.getElementById('modal-submit');
      submitBtn.textContent = 'Create Task';
      statusGroup.style.display = 'none';
    }

    modal.classList.remove('hidden');
    document.getElementById('task-title').focus();
  }

  closeTaskModal() {
    document.getElementById('task-modal').classList.add('hidden');
    this.editingTaskId = null;
  }

  async submitTask(e) {
    e.preventDefault();

    const title = document.getElementById('task-title').value.trim();
    if (!title) {
      SecureApp.toast('Validation', 'Task title is required', 'warning');
      return;
    }

    const body = {
      title,
      description: document.getElementById('task-description').value.trim(),
      priority: document.getElementById('task-priority').value,
      dueDate: document.getElementById('task-due-date').value || null,
    };

    const submitBtn = document.getElementById('modal-submit');
    const originalText = submitBtn.textContent;
    submitBtn.disabled = true;

    try {
      if (this.editingTaskId) {
        body.status = document.getElementById('task-status').value;
        await SecureApp.api(`/api/tasks/${this.editingTaskId}`, {
          method: 'PUT',
          body,
        });
        SecureApp.toast('Task Updated', title, 'success');
      } else {
        await SecureApp.api('/api/tasks', {
          method: 'POST',
          body,
        });
        SecureApp.toast('Task Created', title, 'success');
      }

      this.closeTaskModal();
      await this.loadTasks();
    } catch (err) {
      SecureApp.toast('Error', err.message, 'error');
    } finally {
      submitBtn.disabled = false;
      submitBtn.textContent = originalText;
    }
  }

  confirmDelete(taskId) {
    this.deletingTaskId = taskId;
    document.getElementById('delete-modal').classList.remove('hidden');
  }

  closeDeleteModal() {
    document.getElementById('delete-modal').classList.add('hidden');
    this.deletingTaskId = null;
  }

  async deleteTask() {
    if (!this.deletingTaskId) return;

    try {
      await SecureApp.api(`/api/tasks/${this.deletingTaskId}`, {
        method: 'DELETE',
      });
      SecureApp.toast('Task Deleted', 'Task has been removed', 'success');
      this.closeDeleteModal();
      await this.loadTasks();
    } catch (err) {
      SecureApp.toast('Error', err.message, 'error');
    }
  }

  // ─── Navigation ───────────────────────────────────────────

  switchView(viewName) {
    // Update nav
    document.querySelectorAll('.nav-item[data-view]').forEach((btn) => {
      btn.classList.toggle('active', btn.dataset.view === viewName);
    });

    // Update views
    document.querySelectorAll('.view').forEach((view) => {
      view.classList.remove('active');
    });
    const targetView = document.getElementById(`${viewName}-view`);
    if (targetView) targetView.classList.add('active');

    // Update topbar
    const titles = {
      tasks: { title: 'Tasks', subtitle: 'Manage your tasks securely' },
      profile: { title: 'Profile', subtitle: 'Manage your account details' },
      security: { title: 'Security', subtitle: 'Keep your account protected' },
    };
    const t = titles[viewName] || titles.tasks;
    SecureApp.setText('page-title', t.title);
    SecureApp.setText('page-subtitle', t.subtitle);

    // Show/hide add task button
    const addBtn = document.getElementById('add-task-btn');
    if (addBtn) addBtn.style.display = viewName === 'tasks' ? '' : 'none';
  }

  // ─── Event Binding ────────────────────────────────────────

  bindEvents() {
    // Navigation
    document.querySelectorAll('.nav-item[data-view]').forEach((btn) => {
      btn.addEventListener('click', () => {
        this.switchView(btn.dataset.view);
        // Close mobile sidebar
        document.getElementById('sidebar').classList.remove('open');
      });
    });

    // Mobile menu
    const mobileBtn = document.getElementById('mobile-menu-btn');
    if (mobileBtn) {
      mobileBtn.addEventListener('click', () => {
        document.getElementById('sidebar').classList.toggle('open');
      });
    }

    // Add task
    document.getElementById('add-task-btn').addEventListener('click', () => {
      this.openTaskModal();
    });

    // Task form
    document.getElementById('task-form').addEventListener('submit', (e) => {
      this.submitTask(e);
    });

    // Modal close buttons
    document.getElementById('modal-close').addEventListener('click', () => this.closeTaskModal());
    document.getElementById('modal-cancel').addEventListener('click', () => this.closeTaskModal());
    document.getElementById('task-modal').addEventListener('click', (e) => {
      if (e.target.id === 'task-modal') this.closeTaskModal();
    });

    // Delete modal
    document.getElementById('delete-modal-close').addEventListener('click', () => this.closeDeleteModal());
    document.getElementById('delete-cancel').addEventListener('click', () => this.closeDeleteModal());
    document.getElementById('delete-confirm').addEventListener('click', () => this.deleteTask());
    document.getElementById('delete-modal').addEventListener('click', (e) => {
      if (e.target.id === 'delete-modal') this.closeDeleteModal();
    });

    // Filters
    document.querySelectorAll('.filter-btn').forEach((btn) => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.filter-btn').forEach((b) => b.classList.remove('active'));
        btn.classList.add('active');
        this.currentFilter = btn.dataset.filter;
        this.renderTasks();
      });
    });

    // Logout
    document.getElementById('logout-btn').addEventListener('click', async () => {
      try {
        await SecureApp.api('/api/auth/logout', { method: 'POST' });
        window.location.href = '/';
      } catch (err) {
        // Force redirect even if logout API fails
        window.location.href = '/';
      }
    });

    // Profile form
    document.getElementById('profile-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const btn = document.getElementById('save-profile-btn');
      btn.disabled = true;

      try {
        const data = await SecureApp.api('/api/user/profile', {
          method: 'PUT',
          body: {
            displayName: document.getElementById('edit-display-name').value.trim(),
            email: document.getElementById('edit-email').value.trim(),
          },
        });
        this.user = data.user;
        this.renderUserInfo();
        SecureApp.toast('Profile Updated', 'Your changes have been saved', 'success');
      } catch (err) {
        SecureApp.toast('Error', err.message, 'error');
      } finally {
        btn.disabled = false;
      }
    });

    // Password form
    document.getElementById('password-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const btn = document.getElementById('change-password-btn');
      btn.disabled = true;

      try {
        await SecureApp.api('/api/user/password', {
          method: 'PUT',
          body: {
            currentPassword: document.getElementById('current-password').value,
            newPassword: document.getElementById('new-password').value,
          },
        });
        document.getElementById('password-form').reset();
        // Reset password requirement indicators
        document.querySelectorAll('#security-password-reqs .password-req').forEach((el) => {
          el.classList.remove('met');
          el.querySelector('.password-req-icon').textContent = '○';
        });
        SecureApp.toast('Password Changed', 'Your password has been updated', 'success');
      } catch (err) {
        SecureApp.toast('Error', err.message, 'error');
      } finally {
        btn.disabled = false;
      }
    });

    // Keyboard shortcuts
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        this.closeTaskModal();
        this.closeDeleteModal();
      }
    });
  }

  setupPasswordChecker() {
    const pwInput = document.getElementById('new-password');
    if (!pwInput) return;

    pwInput.addEventListener('input', () => {
      const pw = pwInput.value;
      const reqs = {
        length: pw.length >= 8,
        lower: /[a-z]/.test(pw),
        upper: /[A-Z]/.test(pw),
        number: /[0-9]/.test(pw),
        special: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(pw),
      };
      const container = document.getElementById('security-password-reqs');
      if (!container) return;
      Object.keys(reqs).forEach((key) => {
        const el = container.querySelector(`[data-req="${key}"]`);
        if (el) {
          el.classList.toggle('met', reqs[key]);
          el.querySelector('.password-req-icon').textContent = reqs[key] ? '✓' : '○';
        }
      });
    });
  }
}
