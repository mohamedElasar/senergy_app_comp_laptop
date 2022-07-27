module.exports = (sequelize, Sequelize) => {
  const har_classification_details = sequelize.define("har_classification_details", {

    classification_name: {
      type: Sequelize.STRING(50),
      allowNull: false,
    },
    classification_group: {
      type: Sequelize.STRING(50),
      allowNull: false
    },


  },
  { timestamps: false }
  )
    
  ;

  return har_classification_details;
};
