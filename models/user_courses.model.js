User = require('./user.model');
module.exports = (sequelize, Sequelize) => {
  const User_courses = sequelize.define("User_courses", {
    id: {
      type: Sequelize.INTEGER,
      primaryKey: true,
      autoIncrement: true,
      allowNull: false
    },

  },
    { timestamps: false }
  );


  return User_courses;
};
