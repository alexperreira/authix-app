import prisma from '../src/prisma/client';
import bcrypt from 'bcryptjs';

async function createAdmin() {
    const hashedPassword = await bcrypt.hash('abcd1234', 12);
    await prisma.user.create({
        data: {
            username: 'admin',
            email: 'admin@authix.com',
            password: hashedPassword,
            role: 'admin',
        },
    });

    console.log('Admin user created.');
}

createAdmin().catch((error) => {
    console.error(error);
    process.exit(1);
});