import User from '../schemas/user-repository';
import { SALT_ROUNDS, SECRET_JWT_KEY } from '../config';
import { userSchema } from '../validations/auth';
import { Request, Response } from 'express';
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'

export const register = (req: Request, res: Response) => {
	const { username, password } = req.body;

	try {
		const id = crypto.randomUUID()
		const hashedPassword = bcrypt.hashSync(password, SALT_ROUNDS)

		try {
			userSchema.parse({ username, password })
		} catch (error: any) {
			throw new Error(`${error.errors.map((e: any) => e.message).join(", ")}`)
		}

		if (User.findOne({ username })) throw new Error('User already exists')

		User.create({
			_id: id,
			username,
			password: hashedPassword
		}).save()

		res.send({ id })
	} catch (error: any) {
		res.status(400).send({ error: error.message })
	}
}

export const login = (req: Request, res: Response) => {
	const { username, password } = req.body;

	try {
		try { userSchema.parse({ username, password }) }
		catch (error: any) {
			throw new Error(`${error.errors.map((e: any) => e.message).join(", ")}`)
		}

		const foundUser = User.findOne({ username });

		const isValid = bcrypt.compareSync(password, foundUser.password)

		if (!isValid) throw new Error('Invalid credentials')

		const { password: _, ...publicUser } = foundUser;

		const token = jwt.sign(publicUser, SECRET_JWT_KEY, { expiresIn: '1h' })

		res
			.cookie('access_token', token, { httpOnly: true })
			.send({ token, user: publicUser })
	} catch (error) {
		console.log("error:", error)
		res.status(401).send({ error: 'Invalid credentials' })
	}
}

export const home = (req: Request, res: Response) => {
	const token = req.cookies.access_token;

	if (!token) return res.status(403).send('access not authorized')

	try {
		const data = jwt.verify(token, SECRET_JWT_KEY)

		res.send({
			message: 'Access granted',
			user: data
		})
	}
	catch (error: any) {
		res.status(401).send('access not authorized')
	}
}

export const logout = (req: Request, res: Response) => {
	res
		.clearCookie('access_token')
		.json({ message: 'logging out' })
}
