import express from 'express';
import { PORT, SECRET_JWT_KEY } from './config'
import authRoutes from './routes/autentication'
import morgan from 'morgan'
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';

const app = express();

app.use(express.json());
app.use(morgan('dev'))
app.use(cookieParser())

app.use('/auth', authRoutes);

app.get('/', (req, res) => res.send('Hello, World!'))

app.listen(PORT);

console.log(`Server is running on port ${PORT}`);
