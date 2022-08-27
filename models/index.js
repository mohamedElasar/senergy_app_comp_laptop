const dbConfig = require("../config/db.config.js");
UUser = require("./user.model.js")
userHH = require("./user_hierarcy.model.js")


const { Sequelize, DataTypes } = require('sequelize');
const sequelize = new Sequelize(dbConfig.DB, dbConfig.USER, dbConfig.PASSWORD, {
  host: dbConfig.HOST,
  dialect: dbConfig.dialect,
  operatorAliases: false,

  pool: {
    max: dbConfig.pool.max,
    min: dbConfig.pool.min,
    acquire: dbConfig.pool.acquire,
    idle: dbConfig.pool.idle
  }
});

const db = {};

db.Sequelize = Sequelize;
db.sequelize = sequelize;

// db.tutorials = require("./tutorial.model.js")(sequelize, Sequelize);
db.users = require("./user.model.js")(sequelize, Sequelize);
db.trips = require("./trip.model.js")(sequelize, Sequelize, DataTypes);
db.devices = require("./device_token.model.js")(sequelize, Sequelize);
db.user_hierarcys = require("./user_hierarcy.model.js")(sequelize, Sequelize);
db.classifications = require("./har_classification.model.js")(sequelize, Sequelize);
db.locations = require("./locations.model.js")(sequelize, Sequelize);
db.assets_categories = require("./assets_categories.model.js")(sequelize, Sequelize);
db.assets = require("./assets.model.js")(sequelize, Sequelize);
db.departments = require("./departments.model.js")(sequelize, Sequelize);
db.classification_details = require("./classification_details.model.js")(sequelize, Sequelize);
db.hazards_categories = require("./hazards_categories.model.js")(sequelize, Sequelize);
db.likelihood = require("./likelihood.model.js")(sequelize, Sequelize);
db.report_types = require("./report_types.model.js")(sequelize, Sequelize);
db.severity = require("./severity.model.js")(sequelize, Sequelize);
db.types = require("./types.model.js")(sequelize, Sequelize);
db.reports = require("./har_reports.model.js")(sequelize, Sequelize);
db.actions = require("./har_report_action.model.js")(sequelize, Sequelize);
db.advs = require("./advs.model.js")(sequelize, Sequelize);
db.cars = require("./cars.model.js")(sequelize, Sequelize);
db.purposes = require("./purpose.model.js")(sequelize, Sequelize);
db.courses = require("./courses.model.js")(sequelize, Sequelize);
db.User_courses = require("./user_courses.model.js")(sequelize, Sequelize);



// trips users 
db.trips.belongsTo(db.users, {
  foreignKey: 'user_id',
  as: 'userr'
})
db.trips.belongsTo(db.cars, {
  foreignKey: 'car_id',
  as: 'carr'
})
db.trips.belongsTo(db.purposes, {
  foreignKey: 'purpose_id',
  as: 'purposee'
})

// devices users 
db.devices.belongsTo(db.users, {
  foreignKey: 'user_id',
  as: 'user'
})

// new way users supervisors 
// db.users.belongsToMany(db.users, {through:db.user_hierarcys,  foreignKey: "user_id", as: 'users' });
// db.users.belongsToMany(db.users, { through:db.user_hierarcys, foreignKey: "supervisor_id", as: 'supervisor' });

// classifications
// db.reports.belongsToMany(db.classification_details, { through: db.classifications, foreignKey: "report_id", as: 'class_details' });
// db.classification_details.belongsToMany(db.reports, { through: db.classifications, foreignKey: "classification_item", as: 'classification_item' });



// user herirarchy 
db.user_hierarcys.belongsTo(db.users, {
  foreignKey: 'users_id',
  as: 'users'
})
db.user_hierarcys.belongsTo(db.users, {
  foreignKey: 'supervisor_id',
  as: 'supers'
})
// courses relations 
db.User_courses.belongsTo(db.users, {
  foreignKey: 'user_id',
  as: 'users'
})
db.User_courses.belongsTo(db.courses, {
  foreignKey: 'course_id',
  as: 'courses'
})
// user classification 
db.classifications.belongsTo(db.reports, {
  foreignKey: 'report_id',
  as: 'reports_ids'
})
db.classifications.belongsTo(db.classification_details, {
  foreignKey: 'classification_item',
  as: 'classification_items'
})

// 


// assets to assets categorey
db.assets.belongsTo(db.assets_categories, {
  foreignKey: 'category_id',
  as: 'category'
})


///// report foriegn keys 
// report_type
db.reports.belongsTo(db.types, {
  foreignKey: 'report_type',
  as: 'report_har_type'
})

//likelihood
db.reports.belongsTo(db.likelihood, {
  foreignKey: 'likelihood',
  as: 'report_likelihood'
})
// severity 
db.reports.belongsTo(db.severity, {
  foreignKey: 'severity',
  as: 'report_severity'
})
// reporter
db.reports.belongsTo(db.users, {
  foreignKey: 'reporter',
  as: 'report_reporter'
})
// last_modify_by
db.reports.belongsTo(db.users, {
  foreignKey: 'last_modify_by',
  as: 'report_last_modify_by'
})
// closed_by 
db.reports.belongsTo(db.users, {
  foreignKey: 'closed_by',
  as: 'report_closed_by'
})
// acknowledged_by 
db.reports.belongsTo(db.users, {
  foreignKey: 'acknowledged_by',
  as: 'report_acknowledged_by'
})
// department 
db.reports.belongsTo(db.departments, {
  foreignKey: 'department',
  as: 'report_department',
})
//category 
db.reports.belongsTo(db.hazards_categories, {
  foreignKey: 'category',
  as: 'report_category'
})
// 
//type 
db.reports.belongsTo(db.report_types, {
  foreignKey: 'type',
  as: 'report_type_'
})
//type 
db.reports.belongsTo(db.locations, {
  foreignKey: 'location',
  as: 'report_location'
})
// 



//actions
db.actions.belongsTo(db.users, {
  foreignKey: 'assigned_to',
  as: 'assigned_too'
})
db.actions.belongsTo(db.users, {
  foreignKey: 'assigned_by',
  as: 'assigned_byy'
})
db.actions.belongsTo(db.users, {
  foreignKey: 'closed_by',
  as: 'closed_byy'
})
db.actions.belongsTo(db.reports, {
  foreignKey: 'report_id',
  as: 'report_idd'
})


db.sequelize.sync({ force: false })
  .then(() => {
    console.log('yes re-sync done!')
  })

module.exports = db;
