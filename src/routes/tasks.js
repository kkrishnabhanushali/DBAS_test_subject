'use strict';

const express = require('express');
const router = express.Router();
const db = require('../db/database');
const { requireAuth } = require('../middleware/auth');
const { apiLimiter } = require('../middleware/rateLimiter');
const { validateCreateTask, validateUpdateTask } = require('../middleware/validator');

// All task routes require authentication
router.use(requireAuth);
router.use(apiLimiter);

/**
 * GET /api/tasks
 * Get all tasks for the authenticated user (ownership enforced)
 */
router.get('/', async (req, res, next) => {
  try {
    const tasks = await db.getTasksByUserId(req.session.userId);
    const stats = await db.getTaskStats(req.session.userId);
    res.json({ success: true, tasks, stats });
  } catch (err) {
    next(err);
  }
});

/**
 * POST /api/tasks
 * Create a new task (auto-assigned to authenticated user)
 */
router.post('/', validateCreateTask, async (req, res, next) => {
  try {
    // Explicit field whitelist — prevents mass assignment
    const { title, description, priority, dueDate } = req.body;
    const task = await db.createTask(req.session.userId, {
      title,
      description,
      priority,
      dueDate,
    });
    res.status(201).json({ success: true, task });
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/tasks/:id
 * Get a single task (ownership enforced)
 */
router.get('/:id', async (req, res, next) => {
  try {
    const taskId = parseInt(req.params.id, 10);
    if (isNaN(taskId) || taskId < 1) {
      return res.status(400).json({ success: false, error: 'Invalid task ID' });
    }

    const task = await db.getTaskById(taskId, req.session.userId);
    if (!task) {
      return res.status(404).json({ success: false, error: 'Task not found' });
    }
    res.json({ success: true, task });
  } catch (err) {
    next(err);
  }
});

/**
 * PUT /api/tasks/:id
 * Update a task (ownership enforced + field whitelist)
 */
router.put('/:id', validateUpdateTask, async (req, res, next) => {
  try {
    const taskId = parseInt(req.params.id, 10);
    if (isNaN(taskId) || taskId < 1) {
      return res.status(400).json({ success: false, error: 'Invalid task ID' });
    }

    // Explicit field whitelist
    const { title, description, status, priority, dueDate } = req.body;
    const task = await db.updateTask(taskId, req.session.userId, {
      title,
      description,
      status,
      priority,
      dueDate,
    });

    if (!task) {
      return res.status(404).json({ success: false, error: 'Task not found' });
    }
    res.json({ success: true, task });
  } catch (err) {
    next(err);
  }
});

/**
 * DELETE /api/tasks/:id
 * Delete a task (ownership enforced)
 */
router.delete('/:id', async (req, res, next) => {
  try {
    const taskId = parseInt(req.params.id, 10);
    if (isNaN(taskId) || taskId < 1) {
      return res.status(400).json({ success: false, error: 'Invalid task ID' });
    }

    const deleted = await db.deleteTask(taskId, req.session.userId);
    if (!deleted) {
      return res.status(404).json({ success: false, error: 'Task not found' });
    }
    res.json({ success: true, message: 'Task deleted' });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
