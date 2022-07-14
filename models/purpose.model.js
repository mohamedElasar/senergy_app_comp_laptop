module.exports = (sequelize, Sequelize) => {
  const purposes = sequelize.define("purpose", {


    name: {
      type: Sequelize.STRING(20),
      allowNull: false
    },
    

  },
    { timestamps: false }
  )

    ;

  return purposes;
};
