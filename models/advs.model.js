module.exports = (sequelize, Sequelize) => {
  const advs = sequelize.define("adv", {


    image: {
      type: Sequelize.STRING(255),
      allowNull: true
    },
    

  },
    { timestamps: false }
  )

    ;

  return advs;
};
