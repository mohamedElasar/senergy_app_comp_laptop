module.exports = (sequelize, Sequelize) => {
  const Department = sequelize.define("Department", {

    department_name: {
      type: Sequelize.STRING(50),
      allowNull: false
    },


  },
  { timestamps: false }
  )
    
  ;

  return Department;
};
