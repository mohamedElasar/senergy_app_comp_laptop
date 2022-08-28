User = require('./user.model');
module.exports = (sequelize, Sequelize) => {
  const Report_images = sequelize.define("Report_images", {
    id: {
      type: Sequelize.INTEGER,
      primaryKey: true,
      autoIncrement: true,
      allowNull: false
    },
        image: {
      type: Sequelize.STRING(255),
      allowNull: true
    },

  },
    { timestamps: false }
  );


  return Report_images;
};
