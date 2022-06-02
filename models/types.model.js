module.exports = (sequelize, Sequelize) => {
  const types = sequelize.define("har_types", {

    type_name: {
      type: Sequelize.STRING(50)
    },


  },
  { timestamps: false }
  )
    
  ;

  return types;
};
