module.exports = (sequelize, Sequelize) => {
  const har_actions = sequelize.define("har_action", {

    action_details: {
      type: Sequelize.TEXT,
      allowNull: false
    },
    closingNote: {
      type: Sequelize.TEXT,
      allowNull: true
    },


    target_date: {
      type: Sequelize.BIGINT,
      allowNull: false
    },
    closing_date: {
      type: Sequelize.BIGINT,
      allowNull: true
    },
    action_entry_date: {
      type: Sequelize.BIGINT,
      allowNull: true
    },
    closed: {
      type: Sequelize.BOOLEAN,
      defaultValue: false
    },
    // report_id: {
    //   type: Sequelize.STRING(12)
    // },
    // assigned_to: {
    //   type: Sequelize.STRING(12)
    // },
    // assigned_by: {
    //   type: Sequelize.STRING(12)
    // },
    // closed_by: {
    //   type: Sequelize.STRING(12)
    // },



  },
    { timestamps: false }
  )

    ;

  return har_actions;
};
