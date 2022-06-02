module.exports = (sequelize, Sequelize) => {
  const har_classification_details = sequelize.define("har_classification_details", {

    classification_name: {
      type: Sequelize.STRING(50)
    },
    classification_group: {
      type: Sequelize.STRING(50)
    },


  },
  { timestamps: false }
  )
    
  ;

  return har_classification_details;
};
