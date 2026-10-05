'use strict';

/**
 * Supabase Database Client
 * 
 * Uses standard PostgREST API with native fetch.
 * Fully compatible with Node 18+ and requires no external binary dependencies.
 */
class SupabaseStore {
  constructor(url, key) {
    this.url = url ? url.replace(/\/$/, '') : '';
    this.key = key || '';
  }

  isConfigured() {
    return Boolean(this.url && this.key && this.url.startsWith('http') && !this.url.includes('your-project'));
  }

  async _request(endpoint, options = {}) {
    const { method = 'GET', body, headers = {} } = options;
    const reqUrl = `${this.url}/rest/v1/${endpoint}`;

    const fetchHeaders = {
      'apikey': this.key,
      'Authorization': `Bearer ${this.key}`,
      'Content-Type': 'application/json',
      ...headers,
    };

    const fetchOptions = {
      method,
      headers: fetchHeaders,
    };

    if (body) {
      fetchOptions.body = JSON.stringify(body);
    }

    const res = await fetch(reqUrl, fetchOptions);
    if (!res.ok) {
      const errorText = await res.text();
      let errorJson = null;
      try { errorJson = JSON.parse(errorText); } catch (e) {}
      const message = (errorJson && (errorJson.message || errorJson.error)) || errorText || `Supabase HTTP ${res.status}`;
      throw new Error(`[Supabase Error] ${message}`);
    }

    if (res.status === 204) return null;
    return await res.json();
  }

  // ─── Users ──────────────────────────────────────────────────────

  async createUser({ username, email, passwordHash, displayName }) {
    // Check duplicates
    const existingUser = await this.findUserByUsername(username);
    if (existingUser) throw new Error('USERNAME_EXISTS');

    const existingEmail = await this.findUserByEmail(email);
    if (existingEmail) throw new Error('EMAIL_EXISTS');

    const [created] = await this._request('users', {
      method: 'POST',
      headers: { 'Prefer': 'return=representation' },
      body: {
        username,
        email,
        password_hash: passwordHash,
        display_name: displayName,
      },
    });

    return created.id;
  }

  async findUserByUsername(username) {
    if (!username) return null;
    const data = await this._request(`users?username=ilike.${encodeURIComponent(username)}&select=*`);
    if (!data || data.length === 0) return null;
    const u = data[0];
    return {
      id: Number(u.id),
      username: u.username,
      email: u.email,
      passwordHash: u.password_hash,
      displayName: u.display_name,
      isLocked: Boolean(u.is_locked),
      lockedUntil: u.locked_until,
      createdAt: u.created_at,
      updatedAt: u.updated_at,
    };
  }

  async findUserByEmail(email) {
    if (!email) return null;
    const data = await this._request(`users?email=ilike.${encodeURIComponent(email)}&select=*`);
    if (!data || data.length === 0) return null;
    const u = data[0];
    return {
      id: Number(u.id),
      username: u.username,
      email: u.email,
      passwordHash: u.password_hash,
      displayName: u.display_name,
      isLocked: Boolean(u.is_locked),
      lockedUntil: u.locked_until,
      createdAt: u.created_at,
      updatedAt: u.updated_at,
    };
  }

  async findUserById(id) {
    if (!id) return null;
    const data = await this._request(`users?id=eq.${id}&select=id,username,email,display_name,is_locked,locked_until,created_at,updated_at`);
    if (!data || data.length === 0) return null;
    const u = data[0];
    return {
      id: Number(u.id),
      username: u.username,
      email: u.email,
      displayName: u.display_name,
      isLocked: Boolean(u.is_locked),
      lockedUntil: u.locked_until,
      createdAt: u.created_at,
      updatedAt: u.updated_at,
    };
  }

  async findUserByIdWithPassword(id) {
    if (!id) return null;
    const data = await this._request(`users?id=eq.${id}&select=*`);
    if (!data || data.length === 0) return null;
    const u = data[0];
    return {
      id: Number(u.id),
      username: u.username,
      email: u.email,
      passwordHash: u.password_hash,
      displayName: u.display_name,
      isLocked: Boolean(u.is_locked),
      lockedUntil: u.locked_until,
      createdAt: u.created_at,
      updatedAt: u.updated_at,
    };
  }

  async updateUser(id, { displayName, email }) {
    if (email) {
      const existing = await this.findUserByEmail(email);
      if (existing && existing.id !== Number(id)) {
        throw new Error('EMAIL_EXISTS');
      }
    }

    const updates = { updated_at: new Date().toISOString() };
    if (displayName) updates.display_name = displayName;
    if (email) updates.email = email;

    const data = await this._request(`users?id=eq.${id}`, {
      method: 'PATCH',
      headers: { 'Prefer': 'return=representation' },
      body: updates,
    });

    if (!data || data.length === 0) return null;
    return await this.findUserById(id);
  }

  async updateUserPassword(id, passwordHash) {
    const data = await this._request(`users?id=eq.${id}`, {
      method: 'PATCH',
      headers: { 'Prefer': 'return=representation' },
      body: {
        password_hash: passwordHash,
        updated_at: new Date().toISOString(),
      },
    });
    return data && data.length > 0;
  }

  async lockUser(username) {
    const lockedUntil = new Date(Date.now() + 15 * 60 * 1000).toISOString();
    await this._request(`users?username=ilike.${encodeURIComponent(username)}`, {
      method: 'PATCH',
      headers: { 'Prefer': 'return=minimal' },
      body: {
        is_locked: true,
        locked_until: lockedUntil,
      },
    });
  }

  // ─── Tasks ──────────────────────────────────────────────────────

  async createTask(userId, { title, description, priority, dueDate }) {
    const [task] = await this._request('tasks', {
      method: 'POST',
      headers: { 'Prefer': 'return=representation' },
      body: {
        user_id: userId,
        title,
        description: description || '',
        status: 'pending',
        priority: priority || 'medium',
        due_date: dueDate || null,
      },
    });

    return {
      id: Number(task.id),
      userId: Number(task.user_id),
      title: task.title,
      description: task.description,
      status: task.status,
      priority: task.priority,
      dueDate: task.due_date,
      createdAt: task.created_at,
      updatedAt: task.updated_at,
    };
  }

  async getTasksByUserId(userId) {
    const data = await this._request(`tasks?user_id=eq.${userId}&order=created_at.desc&select=*`);
    if (!data) return [];
    const priorityOrder = { urgent: 1, high: 2, medium: 3, low: 4 };

    return data.map((task) => ({
      id: Number(task.id),
      userId: Number(task.user_id),
      title: task.title,
      description: task.description,
      status: task.status,
      priority: task.priority,
      dueDate: task.due_date,
      createdAt: task.created_at,
      updatedAt: task.updated_at,
    })).sort((a, b) => {
      const pa = priorityOrder[a.priority] || 5;
      const pb = priorityOrder[b.priority] || 5;
      if (pa !== pb) return pa - pb;
      return new Date(b.createdAt) - new Date(a.createdAt);
    });
  }

  async getTaskById(taskId, userId) {
    const data = await this._request(`tasks?id=eq.${taskId}&user_id=eq.${userId}&select=*`);
    if (!data || data.length === 0) return null;
    const task = data[0];
    return {
      id: Number(task.id),
      userId: Number(task.user_id),
      title: task.title,
      description: task.description,
      status: task.status,
      priority: task.priority,
      dueDate: task.due_date,
      createdAt: task.created_at,
      updatedAt: task.updated_at,
    };
  }

  async updateTask(taskId, userId, updates) {
    const patch = { updated_at: new Date().toISOString() };
    if (updates.title !== undefined) patch.title = updates.title;
    if (updates.description !== undefined) patch.description = updates.description;
    if (updates.status !== undefined) patch.status = updates.status;
    if (updates.priority !== undefined) patch.priority = updates.priority;
    if (updates.dueDate !== undefined) patch.due_date = updates.dueDate;

    const data = await this._request(`tasks?id=eq.${taskId}&user_id=eq.${userId}`, {
      method: 'PATCH',
      headers: { 'Prefer': 'return=representation' },
      body: patch,
    });

    if (!data || data.length === 0) return null;
    const task = data[0];
    return {
      id: Number(task.id),
      userId: Number(task.user_id),
      title: task.title,
      description: task.description,
      status: task.status,
      priority: task.priority,
      dueDate: task.due_date,
      createdAt: task.created_at,
      updatedAt: task.updated_at,
    };
  }

  async deleteTask(taskId, userId) {
    const data = await this._request(`tasks?id=eq.${taskId}&user_id=eq.${userId}`, {
      method: 'DELETE',
      headers: { 'Prefer': 'return=representation' },
    });
    return data && data.length > 0;
  }

  async getTaskStats(userId) {
    const tasks = await this.getTasksByUserId(userId);
    return {
      total: tasks.length,
      pending: tasks.filter((t) => t.status === 'pending').length,
      in_progress: tasks.filter((t) => t.status === 'in_progress').length,
      completed: tasks.filter((t) => t.status === 'completed').length,
    };
  }

  // ─── Login Attempts ─────────────────────────────────────────────

  async recordLoginAttempt(ipAddress, username, wasSuccessful) {
    try {
      await this._request('login_attempts', {
        method: 'POST',
        headers: { 'Prefer': 'return=minimal' },
        body: {
          ip_address: ipAddress,
          username: username || null,
          was_successful: wasSuccessful,
        },
      });
    } catch (err) {
      // Don't fail entire login if attempt logging has transient failure
      console.error('[Supabase] Failed to record login attempt:', err.message);
    }
  }

  async getRecentFailedAttempts(ipAddress, minutes = 15) {
    try {
      const cutoff = new Date(Date.now() - minutes * 60 * 1000).toISOString();
      const data = await this._request(
        `login_attempts?ip_address=eq.${encodeURIComponent(ipAddress)}&was_successful=eq.false&attempted_at=gt.${cutoff}&select=id`
      );
      return data ? data.length : 0;
    } catch (err) {
      return 0;
    }
  }

  async getRecentFailedAttemptsByUsername(username, minutes = 15) {
    try {
      const cutoff = new Date(Date.now() - minutes * 60 * 1000).toISOString();
      const data = await this._request(
        `login_attempts?username=ilike.${encodeURIComponent(username)}&was_successful=eq.false&attempted_at=gt.${cutoff}&select=id`
      );
      return data ? data.length : 0;
    } catch (err) {
      return 0;
    }
  }
}

module.exports = SupabaseStore;
