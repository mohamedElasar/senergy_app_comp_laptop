const bcrypt =require('bcryptjs') ;

const data = {
  users: [
    {
      name: 'mohamed',
      email: 'mohamed@gmail.com',
      password: bcrypt.hashSync('1234', 8),
      isAdmin: false,
    },
    {
      name: 'haytham',
      email: 'haytham@gmail.com',
      password: bcrypt.hashSync('1234', 8),
      isAdmin: true,
    },
  ],
  
};

module.exports = data;

