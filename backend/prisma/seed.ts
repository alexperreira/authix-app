import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';

const prisma = new PrismaClient();

async function main() {
  await prisma.user.createMany({
    data: [
      {
        id: 1,
        username: 'testuser',
        email: 'testuser@example.com',
        password: await bcrypt.hash('Pa55word!', 12),
        role: 'user',
      },
      {
        id: 2,
        username: 'Facob',
        email: 'fakeuser@notrealsite.com',
        password: await bcrypt.hash('abc123', 12),
        role: 'user',
      },
      {
        id: 3,
        username: 'anotherfakeuser',
        email: 'somanyfakeemails@fakeemail.com',
        password: await bcrypt.hash('newpassword', 12),
        role: 'user',
      },
      {
        id: 4,
        username: 'Admin',
        email: 'admin@authix.com',
        password: await bcrypt.hash('adminsrule', 12),
        role: 'admin',
      },
      {
        id: 5,
        username: 'newadmin',
        email: 'newadmin@authix.com',
        password: await bcrypt.hash('abc123', 12),
        role: 'user',
      },
    ],
    skipDuplicates: true,
  });
}

main()
  .then(() => {
    console.log('🌱 Seed complete');
    return prisma.$disconnect();
  })
  .catch((e) => {
    console.error('❌ Seed failed', e);
    return prisma.$disconnect();
  });
