User = require('./user.model');
module.exports = (sequelize, Sequelize) => {
  const User_hierarcy = sequelize.define("User_hierarcy", {
    id: {
      type: Sequelize.INTEGER,
      primaryKey: true,
      autoIncrement: true,
      allowNull: false
    },

  },
    { timestamps: false }
  );


  return User_hierarcy;
};
