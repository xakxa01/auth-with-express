import { Router } from "express";
import { home, login, logout, register } from "../controllers/auth";

const route = Router()

route
	.post('/register', register)
	.post('/login', login)
	.post('logout', logout)
	.get('/protected', home)

export default route