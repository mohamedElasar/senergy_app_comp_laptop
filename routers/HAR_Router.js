const express = require('express');
const expressAsyncHandler = require('express-async-handler');
// const bcrypt = require('bcryptjs');
const { isAdmin, isAuth } = require('../utils.js');
const db = require("../models");
const path = require('path')
var sharp = require('sharp');


const User_hierarcy = db.user_hierarcys;
const User = db.users;
const Location = db.locations;;
const Asets_category = db.assets_categories;
const Asset = db.assets;
const Classification_detail = db.classification_details;
const Classification = db.classifications;
const Hazards_category = db.hazards_categories;
const Likelihood = db.likelihood;
const Report_types = db.report_types;
const Severity = db.severity;
const Type = db.types;
const Report = db.reports;
const Action = db.actions;
const Department = db.departments;
const Op = db.Sequelize.Op;
const Trip = db.trips;
const Adv = db.advs;

const Course = db.courses;
const UserCourses = db.User_courses;


const HarRouter = express.Router();

// get all locations 
HarRouter.get(
  '/locations',
  isAuth,
  expressAsyncHandler(async (req, res) => {
    try {
      const locations = await Location.findAll();
      res.send(locations);

    } catch (error) {
      console.log(error);
      res.status(500).send(error);
    }
  })
);

// get all HAR types
HarRouter.get(
  '/har_types',
  isAuth,
  expressAsyncHandler(async (req, res) => {
    try {
      const har_types = await Type.findAll();
      res.send(har_types);

    } catch (error) {
      console.log(error);
      res.status(500).send(error);
    }
  })
);

// get all HAR severities 
HarRouter.get(
  '/severity',
  isAuth,
  expressAsyncHandler(async (req, res) => {
    try {
      const severities = await Severity.findAll();
      res.send(severities);

    } catch (error) {
      console.log(error);
      res.status(500).send(error);
    }
  })
);

// get all report types
HarRouter.get(
  '/report_type',
  isAuth,
  expressAsyncHandler(async (req, res) => {
    try {
      const reportTypes = await Report_types.findAll();
      res.send(reportTypes);

    } catch (error) {
      console.log(error);
      res.status(500).send(error);
    }
  })
);

// get all liklihood
HarRouter.get(
  '/likelihood',
  isAuth,
  expressAsyncHandler(async (req, res) => {
    try {
      const liklihoods = await Likelihood.findAll();
      res.send(liklihoods);

    } catch (error) {
      console.log(error);
      res.status(500).send(error);
    }
  })
);

//get all departments 
HarRouter.get(
  '/all/required/report',
  isAuth,
  expressAsyncHandler(async (req, res) => {
    try {
      const hazards_categorys = await Hazards_category.findAll();
      const departments = await Department.findAll();
      const liklihoods = await Likelihood.findAll();
      const locations = await Location.findAll();
      const reportTypes = await Report_types.findAll();
      const severities = await Severity.findAll();
      const har_types = await Type.findAll();
      const class_details = await Classification_detail.findAll();

      res.send({
        hazards_categorys: hazards_categorys,
        departments: departments,
        liklihoods: liklihoods,
        locations: locations,
        reportTypes: reportTypes,
        severities: severities,
        har_types: har_types,
        class_details: class_details,
      });

    } catch (error) {
      console.log(error);
      res.status(500).send(error);
    }
  })
);
HarRouter.get(
  '/department',
  isAuth,
  expressAsyncHandler(async (req, res) => {
    try {
      const departments = await Department.findAll();
      res.send(departments);

    } catch (error) {
      console.log(error);
      res.status(500).send(error);
    }
  })
);

// get all asset categories
HarRouter.get(
  '/asset_categories',
  isAuth,
  expressAsyncHandler(async (req, res) => {
    try {
      const asset_categories = await Asets_category.findAll();
      res.send(asset_categories);

    } catch (error) {
      console.log(error);
      res.status(500).send(error);
    }
  })
);

// get all assets 
HarRouter.get(
  '/assets',
  isAuth,
  expressAsyncHandler(async (req, res) => {
    try {
      const assets = await Asset.findAll({ include: 'category' });
      res.send(assets);

    } catch (error) {
      console.log(error);
      res.status(500).send(error);
    }
  })
);
// get all classification details
HarRouter.get(
  '/class_details',
  isAuth,
  expressAsyncHandler(async (req, res) => {
    try {
      const class_details = await Classification_detail.findAll();
      res.send(class_details);

    } catch (error) {
      console.log(error);
      res.status(500).send(error);
    }
  })
);

// get all hazardous categories
HarRouter.get(
  '/hazards_categories',
  isAuth,
  expressAsyncHandler(async (req, res) => {
    try {
      const hazards_categorys = await Hazards_category.findAll();
      res.send(hazards_categorys);

    } catch (error) {
      console.log(error);
      res.status(500).send(error);
    }
  })
);

// get all clssifications 
HarRouter.get(
  '/classifications',
  isAuth,
  expressAsyncHandler(async (req, res) => {
    try {
      const classifications = await Classification.findAll({ include: ['classification_items'] });
      res.send(classifications);

    } catch (error) {
      console.log(error);
      res.status(500).send(error);
    }
  })
);

HarRouter.get(
  '/classifications/:id',
  isAuth,
  expressAsyncHandler(async (req, res) => {
    try {
      const classifications = await Classification.findAll({ where: { report_id: req.params.id }, include: ['classification_items'] });
      res.send(classifications);

    } catch (error) {
      console.log(error);
      res.status(500).send(error);
    }
  })
);
// get all users supervisors 
HarRouter.get(
  '/supers',
  isAuth,
  expressAsyncHandler(async (req, res) => {
    try {
      const user_hierarcies = await User_hierarcy.findAll({ include: [{ model: User, as: 'users' }, { model: User, as: 'supers' }] });
      res.send(user_hierarcies);

    } catch (error) {
      console.log(error);
      res.status(500).send(error);
    }
  })
);

HarRouter.get(
  '/reports/:id',
  isAuth,
  expressAsyncHandler(async (req, res) => {
    // const har = await Report.findByPk(req.params.id);
    const har = await Report.findAll({
      where: { id: req.params.id }, include: [
        'report_har_type',
        'report_likelihood',
        'report_severity',
        'report_reporter',
        'report_last_modify_by',
        'report_closed_by',
        'report_acknowledged_by',
        'report_department',
        'report_category',
        'report_type_',
        'report_location',
      ],
    });
    if (har) {
      res.send(har);
    } else {
      res.status(404).send({ message: 'har Not Found' });
    }
  })
);


///// pagination stuff
const getPagingData = (data, page, limit) => {
  const { count: totalItems, rows: trips } = data;
  const currentPage = page ? +page : 0;
  const totalPages = Math.ceil(totalItems / limit);
  return { totalItems, trips, totalPages, currentPage };
};
const getPagination = (page, size) => {
  const limit = size ? +size : 3;
  const offset = page ? page * limit : 0;
  return { limit, offset };
};

// get all reports 
HarRouter.get(
  '/reports',
  isAuth,
  expressAsyncHandler(async (req, res) => {
    const { page, size } = req.query;
    const { limit, offset } = getPagination(page, size);

    try {

      const hars = await Report.findAndCountAll({
        where: null, limit, offset, order: [['id', 'DESC']], include: [
          'report_har_type',
          'report_likelihood',
          'report_severity',
          'report_reporter',
          'report_last_modify_by',
          'report_closed_by',
          'report_acknowledged_by',
          'report_department',
          'report_category',
          'report_type_',
          'report_location',
        ],
      });
      res.send(getPagingData(hars, page, limit));

    } catch (error) {
      console.log(error);
      res.status(500).send(error);
    }
  })
);
HarRouter.get(
  '/reports/mine/all/mine',
  isAuth,
  expressAsyncHandler(async (req, res) => {
    const { page, size } = req.query;
    const { limit, offset } = getPagination(page, size);

    try {

      const hars = await Report.findAndCountAll({
        where: { reporter: req.user._id }, limit, offset, order: [['id', 'DESC']], include: [
          'report_har_type',
          'report_likelihood',
          'report_severity',
          'report_reporter',
          'report_last_modify_by',
          'report_closed_by',
          'report_acknowledged_by',
          'report_department',
          'report_category',
          'report_type_',
          'report_location',
        ],
      });
      res.send(getPagingData(hars, page, limit));

    } catch (error) {
      console.log(error);
      res.status(500).send(error);
    }
  })
);

const multer = require('multer');
// const path = require('path')


const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'images')
  }, filename: (req, file, cb) => {
    cb(null, new Date().toISOString().replace(/:/g, '-') + file.originalname)

  }

})

const upload = multer({ storage: storage });


// create report 
HarRouter.post(
  '/report',
  upload.single('file'),
  expressAsyncHandler(async (req, res) => {
    if ((req.body.title === '') || (req.body.content === '') || (req.body.area === '') || (req.body.report_type === '') || (req.body.likelihood === '') || (req.body.severity === '')
      || (req.body.department == '') || (req.body.category == '') || (req.body.type == '')

    ) {
      res.status(400).send({ message: 'Your should input all data' });
    } else {
      report_checklist = req.body.checklist_list;
      const classification_details = await Classification_detail.findAll({ where: { classification_name: report_checklist } });

      const unixTimestamp = Number(req.body.entry_date);
      function padTo2Digits(num) {
        return num.toString().padStart(2, '0');
      }
      const date = new Date(unixTimestamp);

      const hours = date.getHours();
      const minutes = date.getMinutes();
      const seconds = date.getSeconds();

      // 👇️ Format as hh:mm:ss
      const time = `${padTo2Digits(hours)}:${padTo2Digits(minutes)}:${padTo2Digits(
        seconds,
      )}`;

      const year = date.getFullYear();
      const month = padTo2Digits(date.getMonth() + 1);
      const day = padTo2Digits(date.getDate());

      const dateTime = `${year}${month}${day}000`;
      const NumberReportday = Number(dateTime);



      var start = new Date();
      start.setHours(0, 0, 0, 0);



      const toTimestamp = (strDate) => {
        const dt = Date.parse(strDate);
        return dt / 1000;
      }
      todayTimeStamp = toTimestamp(start.toUTCString());

      todays_reports = await Report.count({
        where: {
          'entry_date': {
            [Op.gte]: todayTimeStamp * 1000

          }
        }
      })


      Report.create({
        title: req.body.title,
        content: req.body.content,
        report_date: req.body.report_date,
        entry_date: req.body.entry_date,
        last_modify: req.body.last_modify,
        report_id: NumberReportday + todays_reports + 1,
        status: req.body.status,

        area: req.body.area,
        risk_rating: req.body.risk_rating,
        class: req.body.class,
        client_involved: req.body.client_involved,
        industry_recognized: req.body.industry_recognized,
        hide: req.body.hide,
        draft: req.body.draft,
        report_type: req.body.report_type,
        likelihood: req.body.likelihood,
        severity: req.body.severity,
        reporter: req.body.reporter,
        last_modify_by: req.body.last_modify_by,
        closed_by: req.body.closed_by,
        acknowledged_by: req.body.acknowledged_by,
        department: req.body.department,
        category: req.body.category,
        type: req.body.type,
        image: req.file ? req.file.path : null,
        location: req.body.location,
        event_severity: req.body.event_severity
      })
        .then(data => {
          classification_details.forEach(e =>
            Classification.create({
              'report_id': data.id,
              'classification_item': e.id,
            })
          );
          res.send(data);
          ;
        })
        .catch(err => {
          res.status(500).send({
            message:
              err.message || "Some error occurred while creating the user."
          });
        });

    }
  })
);

HarRouter.post(
  '/action',
  isAuth,
  expressAsyncHandler(async (req, res) => {

    if ((req.body.action_details === '') || (req.body.target_date === '') || (req.body.assigned_to === '') || (req.body.assigned_by === '')
    ) {
      res.status(400).send({ message: 'Your should input all data' });
    } else {


      // console.log(Number(todayTimeStamp));
      // console.log(req.body.actionDetails);
      // console.log(NumberReportday+todays_reports+1);

      await Action.create({
        action_details: req.body.action_details,
        target_date: req.body.target_date,
        assigned_to: req.body.assigned_to,
        assigned_by: req.body.assigned_by,
        // action_entry_date:req.body.action_entry_date,
        report_id: req.body.report_id
      }
      )
        .then(data => {

          res.send(data);

        })
        .catch(err => {
          res.status(500).send({
            message:
              err.message || "Some error occurred while creating the action."
          });
        });

    }
  })
);

HarRouter.put(
  '/action/:id/action',
  isAuth,

  expressAsyncHandler(async (req, res) => {

    try {


      const action = await Action.findByPk(req.params.id);
      if (action) {
        action.closed = true;
        action.action_entry_date = Date.now();
        action.closed_by = req.user._id;
        action.closingNote = req.body.closingNote;
        action.closing_date = req.body.closing_date;
        const closedAction = await action.save();

        const report = await Report.findByPk(action.report_id);
        report.status = 1;
        const newReport = await report.save()
        res.send({ message: 'action sent', action: closedAction, report: newReport });

      } else {
        res.status(404).send({ message: 'action Not Found' });
      }
    } catch (error) {
      res.status(404).send(error);
      // res.status(500).send({
      //   message:
      //     err.message || "Some error occurred while creating the action."
      // });
    }
  })
);


HarRouter.get(
  '/actions/all',
  isAuth,
  expressAsyncHandler(async (req, res) => {
    // const har = await Report.findByPk(req.params.id);
    const actions = await Action.findAll(
      {
        include: [
          'report_idd',
          'closed_byy',
          'assigned_too',
          'assigned_byy'
        ],
      }
    );
    if (actions) {
      res.send(actions);
    } else {
      res.status(404).send({ message: 'actions Not Found' });
    }
  })
);

HarRouter.get(
  '/actions/all/:id',
  isAuth,
  expressAsyncHandler(async (req, res) => {
    const { page, size } = req.query;
    const { limit, offset } = getPagination(page, size);

    const actions = await Action.findAndCountAll(
      {
        where: { assigned_to: req.params.id, closed: false },
        limit, offset, order: [['id', 'DESC']],
        include: [
          'report_idd',
          'closed_byy',
          'assigned_too',
          'assigned_byy'
        ],
      }
    );
    if (actions) {
      res.send(getPagingData(actions, page, limit));

    } else {
      res.status(404).send({ message: 'actions Not Found' });
    }
  })
);
HarRouter.get(
  '/myactions/one/:id',
  isAuth,
  expressAsyncHandler(async (req, res) => {

    // const action = await Action.findByPk(req.params.id);

    const action = await Action.findByPk(
      req.params.id,

      {
        // where: { id: req.params.id,closed:false },
        // limit, offset,order: [['id', 'DESC']],
        include: [
          'report_idd',
          'closed_byy',
          'assigned_too',
          'assigned_byy'
        ],
      }
    );
    if (action) {
      res.send(action);

    } else {
      res.status(404).send({ message: 'actions Not Found' });
    }
  })
);
HarRouter.get(
  '/actions/reports/count/:id',
  isAuth,
  expressAsyncHandler(async (req, res) => {
    // const har = await Report.findByPk(req.params.id);
    const actions = await Action.findAll(
      {
        where: { assigned_to: req.params.id, closed: false },
        include: [

        ],
      }

    );
    const tripsNeedApproval = await Trip.findAll(
      {
        where: { isApproved: false },
        include: [

        ],
      }
    );

    const yourHars = await Report.findAll(
      {
        where: { reporter: req.user._id },

      }
    );


   const countcourses = await Course.count({
  });
   const userCoursesTaken = await UserCourses.count({
    where: { user_id: req.params.id },
  });

  percentageTaken = ((userCoursesTaken/countcourses) * 100).toFixed(2)
 if(Number.isNaN( Number(percentageTaken) )){
  percentageTaken = 0;
 }



 const user = await User.findAll({ where: { id: req.params.id }, include: [] });
 
 const userCreatedAt = user[0].dataValues.createdAt;
 const dateUser = new Date(userCreatedAt);


 function getMonthDifference(startDate, endDate) {
  return (
    endDate.getMonth() -
    startDate.getMonth() +
    12 * (endDate.getFullYear() - startDate.getFullYear())
  );
}


  requiredHar = getMonthDifference(dateUser,new Date(Date.now())) *2 +2; 
  const advs = await Adv.findAll(
    {

    });




    if (actions) {
      res.send({
         count: actions.length,
         countTripsNeedApprove: tripsNeedApproval.length,
         percentagecourses:percentageTaken+' %', 
         usertrainingrequired:user[0].dataValues.training_required.toString() +' %',
         HarTrack:(yourHars.length-requiredHar).toString(),
         advs:advs
        });
    } else {
      res.status(404).send({ message: 'actions Not Found' });
    }
  })
);


HarRouter.get(
  '/advs/all/all',
  isAuth,
  expressAsyncHandler(async (req, res) => {
    const advs = await Adv.findAll(
      {

      }
    );
    if (advs) {
      res.send(advs);
    } else {
      res.status(404).send({ message: 'images Not Found' });
    }
  })
);








module.exports = HarRouter;