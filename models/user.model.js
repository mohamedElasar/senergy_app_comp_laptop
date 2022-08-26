module.exports = (sequelize, Sequelize) => {
  const User = sequelize.define("user", {

    login_id: {
      type: Sequelize.STRING(20)
    },
    password: {
      type: Sequelize.STRING(32),
      allowNull: false

    },
    name: {
      type: Sequelize.STRING(100),
      allowNull: false

      
    },
    email: {
      type: Sequelize.STRING(60),
      allowNull: false

    },
    status: {
      type: Sequelize.TINYINT(4),
      defaultValue:0
    },
    position: {
      type: Sequelize.STRING(20),

    },
    default_pass: {
      type: Sequelize.BOOLEAN,
      defaultValue:false,
      allowNull: false

    },
    login_har: {
      type: Sequelize.BOOLEAN,
      defaultValue:false,
      allowNull: false
    },
    login_jm: {
      type: Sequelize.BOOLEAN,
      defaultValue:false,
      allowNull: false
    },
    login_tr: {
      type: Sequelize.BOOLEAN,
      defaultValue:false,
      allowNull: false
    },
    login_audit: {
      type: Sequelize.BOOLEAN,
      defaultValue:false,
      allowNull: false
    },
    admin: {
      type: Sequelize.BOOLEAN,
      defaultValue:false,
      allowNull: false
    },
    lastlogin: {
      type: Sequelize.INTEGER(12)
    },
    isAdmin: {
      type: Sequelize.BOOLEAN,
      defaultValue:false,
      allowNull: false
    },

  },
  { timestamps: false }
  )
    
  ;

  return User;
};
