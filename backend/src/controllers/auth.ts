import { Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { User } from '../models/user';
import { redis } from '../config/redis';

export const register = async (req: Request, res: Response) => {
  try {
    const { email, password, tenantId } = req.body;

    const existingUser = await User.findOne({ email, tenantId });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await User.create({
      email,
      password: hashedPassword,
      tenantId,
      roles: ['user']
    });

    const token = jwt.sign(
      { userId: user._id, tenantId, roles: user.roles },
      process.env.JWT_SECRET!,
      { expiresIn: '1h' }
    );

    res.status(201).json({ token });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
};

export const login = async (req: Request, res: Response) => {
  try {
    const { email, password, tenantId } = req.body;

    const user = await User.findOne({ email, tenantId });
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { userId: user._id, tenantId, roles: user.roles },
      process.env.JWT_SECRET!,
      { expiresIn: '1h' }
    );

    res.json({ token });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
};

export const logout = async (req: Request, res: Response) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (token) {
      // Add token to blacklist with 1 hour expiry
      await redis.set(`blacklist:${token}`, '1', 'EX', 3600);
    }
    res.json({ message: 'Logged out successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
};