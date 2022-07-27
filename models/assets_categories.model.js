module.exports = (sequelize, Sequelize) => {
  const Asset_Category = sequelize.define("Asset_Category", {

    category: {
      type: Sequelize.STRING(50),
      allowNull: false
    },


  },
  { timestamps: false }
  )
    
  ;

  return Asset_Category;
};
