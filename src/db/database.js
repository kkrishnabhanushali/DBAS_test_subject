'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DB_PATH = path.join(__dirname, '..', '..', 'data.db.json');

/**
 * A secure, file-backed JSON data store.
 * 
 * Security design:
 * - No SQL at all = zero SQL injection surface
 * - All lookups use exact-match functions (no string interpolation)
 * - All writes go through validated helper functions
 * - Atomic file writes prevent corruption
 */
class SecureStore {
  constructor() {
    this.data = null;
  }

  /**
   * Initialize the data store. Load existing data or create fresh.
   */
  init() {
    if (fs.existsSync(DB_PATH)) {
      try {
        const raw = fs.readFileSync(DB_PATH, 'utf8');
        this.data = JSON.parse(raw);
        console.log('[DB] Loaded existing database');
      } catch (err) {
        console.error('[DB] Corrupt database file, creating new one');
        this._createFresh();
      }
    } else {
      this._createFresh();
    }
    // Cleanup expired data on init
    this._cleanupLoginAttempts();
    this._unlockExpiredUsers();
    return this;
  }

  _createFresh() {
    this.data = {
      users: [],
      tasks: [],
      loginAttempts: [],
      nextUserId: 1,
      nextTaskId: 1,
    };
    this._persist();
    console.log('[DB] Created new database');
  }

  /**
   * Atomic write to disk — write to temp file then rename.
   * Prevents data corruption on crash.
   */
  _persist() {
    const tempPath = DB_PATH + '.tmp';
    fs.writeFileSync(tempPath, JSON.stringify(this.data, null, 2), 'utf8');
    fs.renameSync(tempPath, DB_PATH);
  }

  // ─── User Operations ──────────────────────────────────────────

  createUser({ username, email, passwordHash, displayName }) {
    // Check uniqueness (case-insensitive)
    if (this.findUserByUsername(username)) {
      throw new Error('USERNAME_EXISTS');
    }
    if (this.findUserByEmail(email)) {
      throw new Error('EMAIL_EXISTS');
    }

    const user = {
      id: this.data.nextUserId++,
      username: username,
      email: email,
      passwordHash: passwordHash,
      displayName: displayName,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      isLocked: false,
      lockedUntil: null,
    };
    this.data.users.push(user);
    this._persist();
    return user.id;
  }

  findUserByUsername(username) {
    return this.data.users.find(
      (u) => u.username.toLowerCase() === username.toLowerCase()
    ) || null;
  }

  findUserByEmail(email) {
    return this.data.users.find(
      (u) => u.email.toLowerCase() === email.toLowerCase()
    ) || null;
  }

  findUserById(id) {
    const user = this.data.users.find((u) => u.id === id);
    if (!user) return null;
    // Never return password hash
    const { passwordHash, ...safe } = user;
    return safe;
  }

  findUserByIdWithPassword(id) {
    return this.data.users.find((u) => u.id === id) || null;
  }

  updateUser(id, { displayName, email }) {
    const user = this.data.users.find((u) => u.id === id);
    if (!user) return null;

    // Check email uniqueness if changing
    if (email && email.toLowerCase() !== user.email.toLowerCase()) {
      const existing = this.findUserByEmail(email);
      if (existing && existing.id !== id) {
        throw new Error('EMAIL_EXISTS');
      }
    }

    if (displayName) user.displayName = displayName;
    if (email) user.email = email;
    user.updatedAt = new Date().toISOString();
    this._persist();
    return this.findUserById(id);
  }

  updateUserPassword(id, passwordHash) {
    const user = this.data.users.find((u) => u.id === id);
    if (!user) return false;
    user.passwordHash = passwordHash;
    user.updatedAt = new Date().toISOString();
    this._persist();
    return true;
  }

  lockUser(username) {
    const user = this.findUserByUsername(username);
    if (!user) return;
    user.isLocked = true;
    user.lockedUntil = new Date(Date.now() + 15 * 60 * 1000).toISOString();
    this._persist();
  }

  _unlockExpiredUsers() {
    const now = new Date().toISOString();
    let changed = false;
    this.data.users.forEach((u) => {
      if (u.isLocked && u.lockedUntil && u.lockedUntil < now) {
        u.isLocked = false;
        u.lockedUntil = null;
        changed = true;
      }
    });
    if (changed) this._persist();
  }

  // ─── Task Operations (ownership enforced in every query) ───────

  createTask(userId, { title, description, priority, dueDate }) {
    const task = {
      id: this.data.nextTaskId++,
      userId: userId,
      title: title,
      description: description || '',
      status: 'pending',
      priority: priority || 'medium',
      dueDate: dueDate || null,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
    this.data.tasks.push(task);
    this._persist();
    return task;
  }

  getTasksByUserId(userId) {
    const priorityOrder = { urgent: 1, high: 2, medium: 3, low: 4 };
    return this.data.tasks
      .filter((t) => t.userId === userId)
      .sort((a, b) => {
        const pa = priorityOrder[a.priority] || 5;
        const pb = priorityOrder[b.priority] || 5;
        if (pa !== pb) return pa - pb;
        return new Date(b.createdAt) - new Date(a.createdAt);
      });
  }

  getTaskById(taskId, userId) {
    return this.data.tasks.find(
      (t) => t.id === taskId && t.userId === userId
    ) || null;
  }

  updateTask(taskId, userId, updates) {
    const task = this.getTaskById(taskId, userId);
    if (!task) return null;

    // Only update whitelisted fields
    if (updates.title !== undefined) task.title = updates.title;
    if (updates.description !== undefined) task.description = updates.description;
    if (updates.status !== undefined) task.status = updates.status;
    if (updates.priority !== undefined) task.priority = updates.priority;
    if (updates.dueDate !== undefined) task.dueDate = updates.dueDate;
    task.updatedAt = new Date().toISOString();

    this._persist();
    return task;
  }

  deleteTask(taskId, userId) {
    const idx = this.data.tasks.findIndex(
      (t) => t.id === taskId && t.userId === userId
    );
    if (idx === -1) return false;
    this.data.tasks.splice(idx, 1);
    this._persist();
    return true;
  }

  getTaskStats(userId) {
    const userTasks = this.data.tasks.filter((t) => t.userId === userId);
    return {
      total: userTasks.length,
      pending: userTasks.filter((t) => t.status === 'pending').length,
      in_progress: userTasks.filter((t) => t.status === 'in_progress').length,
      completed: userTasks.filter((t) => t.status === 'completed').length,
    };
  }

  // ─── Login Attempt Tracking ────────────────────────────────────

  recordLoginAttempt(ipAddress, username, wasSuccessful) {
    this.data.loginAttempts.push({
      ipAddress,
      username,
      wasSuccessful,
      attemptedAt: new Date().toISOString(),
    });
    // Keep only last 1000 attempts to prevent unbounded growth
    if (this.data.loginAttempts.length > 1000) {
      this.data.loginAttempts = this.data.loginAttempts.slice(-500);
    }
    this._persist();
  }

  getRecentFailedAttempts(ipAddress, minutes = 15) {
    const cutoff = new Date(Date.now() - minutes * 60 * 1000).toISOString();
    return this.data.loginAttempts.filter(
      (a) => a.ipAddress === ipAddress && !a.wasSuccessful && a.attemptedAt > cutoff
    ).length;
  }

  getRecentFailedAttemptsByUsername(username, minutes = 15) {
    const cutoff = new Date(Date.now() - minutes * 60 * 1000).toISOString();
    return this.data.loginAttempts.filter(
      (a) =>
        a.username &&
        a.username.toLowerCase() === username.toLowerCase() &&
        !a.wasSuccessful &&
        a.attemptedAt > cutoff
    ).length;
  }

  _cleanupLoginAttempts() {
    const cutoff = new Date(Date.now() - 60 * 60 * 1000).toISOString();
    const before = this.data.loginAttempts.length;
    this.data.loginAttempts = this.data.loginAttempts.filter(
      (a) => a.attemptedAt > cutoff
    );
    if (this.data.loginAttempts.length !== before) {
      this._persist();
    }
  }
}

// ─── Dual Store Manager ──────────────────────────────────────────
const SupabaseStore = require('./supabase');

const localStore = new SecureStore();
let supabaseStore = null;

const dbManager = {
  activeEngine: 'local',

  init() {
    localStore.init();
    const supabaseUrl = process.env.SUPABASE_URL;
    const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY;

    if (supabaseUrl && supabaseKey && !supabaseUrl.includes('your-project')) {
      supabaseStore = new SupabaseStore(supabaseUrl, supabaseKey);
      this.activeEngine = 'supabase';
      console.log(`[DB] Active Engine: Supabase Cloud Database (${supabaseUrl})`);
    } else {
      this.activeEngine = 'local';
      console.log('[DB] Active Engine: Built-in Local Database (data.db.json)');
    }
    return this;
  },

  getStore() {
    if (this.activeEngine === 'supabase' && supabaseStore) {
      return supabaseStore;
    }
    return localStore;
  },

  async createUser(data) {
    return await this.getStore().createUser(data);
  },

  async findUserByUsername(username) {
    return await this.getStore().findUserByUsername(username);
  },

  async findUserByEmail(email) {
    return await this.getStore().findUserByEmail(email);
  },

  async findUserById(id) {
    return await this.getStore().findUserById(id);
  },

  async findUserByIdWithPassword(id) {
    return await this.getStore().findUserByIdWithPassword(id);
  },

  async updateUser(id, updates) {
    return await this.getStore().updateUser(id, updates);
  },

  async updateUserPassword(id, passwordHash) {
    return await this.getStore().updateUserPassword(id, passwordHash);
  },

  async lockUser(username) {
    return await this.getStore().lockUser(username);
  },

  async createTask(userId, data) {
    return await this.getStore().createTask(userId, data);
  },

  async getTasksByUserId(userId) {
    return await this.getStore().getTasksByUserId(userId);
  },

  async getTaskById(taskId, userId) {
    return await this.getStore().getTaskById(taskId, userId);
  },

  async updateTask(taskId, userId, updates) {
    return await this.getStore().updateTask(taskId, userId, updates);
  },

  async deleteTask(taskId, userId) {
    return await this.getStore().deleteTask(taskId, userId);
  },

  async getTaskStats(userId) {
    return await this.getStore().getTaskStats(userId);
  },

  async recordLoginAttempt(ip, username, success) {
    return await this.getStore().recordLoginAttempt(ip, username, success);
  },

  async getRecentFailedAttempts(ip, minutes) {
    return await this.getStore().getRecentFailedAttempts(ip, minutes);
  },

  async getRecentFailedAttemptsByUsername(username, minutes) {
    return await this.getStore().getRecentFailedAttemptsByUsername(username, minutes);
  },
};

module.exports = dbManager;

