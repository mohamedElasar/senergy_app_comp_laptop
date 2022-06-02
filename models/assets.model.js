module.exports = (sequelize, Sequelize) => {
  const asset = sequelize.define("asset", {

    Asset: {
      type: Sequelize.STRING(50)
    },


  },
  { timestamps: false }
  )
    
  ;

  return asset;
};
