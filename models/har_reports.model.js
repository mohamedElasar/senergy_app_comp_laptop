module.exports = (sequelize, Sequelize) => {
  const har_reports = sequelize.define("har_report", {

    title: {
      type: Sequelize.STRING(200),
      allowNull: false
    },
    image: {
      type: Sequelize.STRING(255),
      allowNull: true
    },
    content: {
      type: Sequelize.TEXT,
      allowNull: false

    },
    report_date: {
      type: Sequelize.BIGINT,
      allowNull: false
    },
    entry_date: {
      type: Sequelize.BIGINT,
      allowNull: false
    },
    last_modify: {
      type: Sequelize.BIGINT
    },
    // last_modify_by: {
    //   type: Sequelize.INTEGER
    // },
    report_id: {
      type: Sequelize.STRING(12)
    },
    event_severity: {
      type: Sequelize.INTEGER,
      allowNull: true
    },
    // report_type
    // likelihood
    // severity 
    // reporter 
    status: {
      type: Sequelize.INTEGER,
      defaultValue:0
    },
    closing_date: {
      type: Sequelize.INTEGER,
      allowNull: true

    },
    acknowledged_date: {
      type: Sequelize.INTEGER,
      allowNull: true
    },
    // closed_by 
    // acknowledged_by 
    // department 
    area: {
      type: Sequelize.STRING(50)
    },
    risk_rating: {
      type: Sequelize.INTEGER
    },
    ///////////type&&&&!!!
    //category 

    // class //!!! 
    class: {
      type: Sequelize.BOOLEAN
    },
    client_involved: {
      type: Sequelize.BOOLEAN,
      defaultValue: false

    },
    industry_recognized: {
      type: Sequelize.BOOLEAN,
      defaultValue: false
    },
    // location 
    hide: {
      type: Sequelize.BOOLEAN,
      defaultValue: false
    },
    draft: {
      type: Sequelize.BOOLEAN,
      defaultValue: false
    },

  },
    { timestamps: false }
  )

    ;

  return har_reports;
};
