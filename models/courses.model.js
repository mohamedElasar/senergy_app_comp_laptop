module.exports = (sequelize, Sequelize) => {
  const courses = sequelize.define("courses", {

    course_name: {
      type: Sequelize.STRING(50),
      allowNull: false
    },


  },
  { timestamps: false }
  )
    
  ;

  return courses;
};
