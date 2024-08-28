import express from 'express';
import authRoutes from './routes/autentication.js'
import morgan from 'morgan'
import cookieParser from 'cookie-parser';
import { config } from 'dotenv';

config()

const app = express();

app.use(express.json());
app.use(morgan('dev'))
app.use(cookieParser())

app.use('/auth', authRoutes);

app.get('/', (_, res) => res.send('Hello, World!'))

const port = process.env.PORT || 3000;

app.listen(port);

console.log(`Server is running on port ${port}`);
