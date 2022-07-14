module.exports = (sequelize, Sequelize) => {
  const cars = sequelize.define("car", {


    name: {
      type: Sequelize.STRING(20),
      allowNull: false
    },
    

  },
    { timestamps: false }
  )

    ;

  return cars;
};
