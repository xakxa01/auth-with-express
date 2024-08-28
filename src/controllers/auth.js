import User from '../schemas/user-repository.js';
import { userSchema } from '../validations/auth.js';
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'

export const register = (req, res) => {
	const { username, password } = req.body;

	try {
		const id = crypto.randomUUID()
		const hashedPassword = bcrypt.hashSync(password, process.env.SALT_ROUNDS)

		try {
			userSchema.parse({ username, password })
		} catch (error) {
			throw new Error(`${error.errors.map((e) => e.message).join(", ")}`)
		}

		if (User.findOne({ username })) throw new Error('User already exists')

		User.create({
			_id: id,
			username,
			password: hashedPassword
		}).save()

		res.send({ id })
	} catch (error) {
		res.status(400).send({ error: error.message })
	}
}

export const login = (req, res) => {
	const { username, password } = req.body;

	try {
		try { userSchema.parse({ username, password }) }
		catch (error) {
			throw new Error(`${error.errors.map((e) => e.message).join(", ")}`)
		}

		const foundUser = User.findOne({ username });

		const isValid = bcrypt.compareSync(password, foundUser.password)

		if (!isValid) throw new Error('Invalid credentials')

		const { password: _, ...publicUser } = foundUser;

		const token = jwt.sign(publicUser, jwtKey, { expiresIn: '1h' })

		res
			.cookie('access_token', token, { httpOnly: true })
			.send({ token, user: publicUser })
	} catch (error) {
		console.log("error:", error)
		res.status(401).send({ error: 'Invalid credentials' })
	}
}

export const home = (req, res) => {
	const token = req.cookies.access_token;

	if (!token) return res.status(403).send('access not authorized')

	try {
		const data = jwt.verify(token, process.env.SECRET_JWT_KEY)

		res.send({
			message: 'Access granted',
			user: data
		})
	}
	catch (error) {
		res.status(401).send('access not authorized')
	}
}

export const logout = (req, res) => {
	res
		.clearCookie('access_token')
		.json({ message: 'logging out' })
}
