module.exports = (sequelize, Sequelize) => {
  const Device = sequelize.define("device", {

    token: {
      type: Sequelize.STRING
    },

    isAdmin: {
      type: Sequelize.BOOLEAN
    },

  },
  { timestamps: false }
  )
    
  ;

  return Device;
};

