module.exports = (sequelize, Sequelize) => {
  const har_likelihood = sequelize.define("har_likelihood", {

    likelihood: {
      type: Sequelize.STRING(50)
    },


  },
  { timestamps: false }
  )
    
  ;

  return har_likelihood;
};
