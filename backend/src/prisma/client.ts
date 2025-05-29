import { PrismaClient } from '@prisma/client';

// Create a new PrismaClient instance with logging to help debug
const prisma = new PrismaClient({
  log: ['query', 'info', 'warn', 'error'],
});

export default prisma;
