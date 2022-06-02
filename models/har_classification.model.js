module.exports = (sequelize, Sequelize) => {
    const Classification = sequelize.define("har_classification", {
  
    },
    { timestamps: false }
    )
      
    ;
  
    return Classification;
  };
  