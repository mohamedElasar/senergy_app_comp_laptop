module.exports = (sequelize, Sequelize) => {
  const har_reportTypes = sequelize.define("har_report_types", {

    type: {
      type: Sequelize.STRING(50)
    },


  },
  { timestamps: false }
  )
    
  ;

  return har_reportTypes;
};
