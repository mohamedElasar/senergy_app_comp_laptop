module.exports = (sequelize, Sequelize) => {
  const advs = sequelize.define("adv", {


    image: {
      type: Sequelize.STRING(255),
      allowNull: false
    },
    

  },
    { timestamps: false }
  )

    ;

  return advs;
};
