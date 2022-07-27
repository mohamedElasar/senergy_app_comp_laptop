module.exports = (sequelize, Sequelize) => {
  const asset = sequelize.define("asset", {

    Asset: {
      type: Sequelize.STRING(50),
      allowNull: false
    },


  },
  { timestamps: false }
  )
    
  ;

  return asset;
};
