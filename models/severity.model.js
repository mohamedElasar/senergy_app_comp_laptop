module.exports = (sequelize, Sequelize) => {
  const severity = sequelize.define("har_severity", {

    severity: {
      type: Sequelize.STRING(50)
    },


  },
  { timestamps: false }
  )
    
  ;

  return severity;
};
