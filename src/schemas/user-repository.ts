import DBLocal from 'db-local';

const { Schema } = new DBLocal({ path: './db' })

const User = Schema('User', {
	_id: {
		type: String,
		required: true,
	},
	username: {
		type: String,
		required: true,
	},
	password: {
		type: String,
		required: true,
	},
})

export default User;