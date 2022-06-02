module.exports = (sequelize, Sequelize) => {
  const Location = sequelize.define("Location", {

    location_name: {
      type: Sequelize.STRING(45)
    },


  },
  { timestamps: false }
  )
    
  ;

  return Location;
};
