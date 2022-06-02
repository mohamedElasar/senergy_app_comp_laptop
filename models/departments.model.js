module.exports = (sequelize, Sequelize) => {
  const Department = sequelize.define("Department", {

    department_name: {
      type: Sequelize.STRING(50)
    },


  },
  { timestamps: false }
  )
    
  ;

  return Department;
};
