const express = require('express');
const expressAsyncHandler = require('express-async-handler');
// const bcrypt = require('bcryptjs');
const { isAdmin, isAuth } = require('../utils.js');
const db = require("../models");

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
const Department = db.departments;
const Op = db.Sequelize.Op;

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
  '/hazards categories',
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
      const classifications = await Classification.findAll({include:'reports_ids'});
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
      const user_hierarcies = await User_hierarcy.findAll({ include: [ { model: User, as: 'users' },{ model: User, as: 'supers' } ]});
      res.send(user_hierarcies);

    } catch (error) {
      console.log(error);
      res.status(500).send(error);
    }
  })
);

// get all reports 
HarRouter.get(
  '/reports',
  isAuth,
  expressAsyncHandler(async (req, res) => {
    try {
      const reports = await Report.findAll({include: 'reportType'});
      res.send(reports);

    } catch (error) {
      console.log(error);
      res.status(500).send(error);
    }
  })
);


// create report 
HarRouter.post(
  '/report',
  expressAsyncHandler(async (req, res) => {


    Report.create({
      title: req.body.title,
        content: req.body.content,
        report_date: req.body.report_date,
        entry_date: req.body.entry_date,
        last_modify: req.body.last_modify,
        report_id: req.body.report_id,
        status: req.body.status,
        // "closing_date": 1654006650,
        // "acknowledged_date": 1654006650,
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
    })
    .then(data => {
      res.send(data);
    })
    .catch(err => {
      res.status(500).send({
        message:
          err.message || "Some error occurred while creating the user."
      });
    });
  })
);




module.exports = HarRouter;