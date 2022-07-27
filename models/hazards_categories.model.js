module.exports = (sequelize, Sequelize) => {
  const har_hazards_categories = sequelize.define("har_hazards_categories", {

    hazard_category: {
      type: Sequelize.STRING(50),
      allowNull: false
    },


  },
  { timestamps: false }
  )
    
  ;

  return har_hazards_categories;
};
