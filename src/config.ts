import { config } from 'dotenv';

config()

export const {
	PORT = 3000,
	SALT_ROUNDS = 10,
	SECRET_JWT_KEY
}: any = process.env