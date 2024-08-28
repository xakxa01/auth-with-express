import express from 'express';
import { PORT } from './config'
import authRoutes from './routes/autentication'
import morgan from 'morgan'
import cookieParser from 'cookie-parser';

const app = express();

app.use(express.json());
app.use(morgan('dev'))
app.use(cookieParser())

app.use('/auth', authRoutes);

app.get('/', (_, res) => res.send('Hello, World!'))

app.listen(PORT);

console.log(`Server is running on port ${PORT}`);
