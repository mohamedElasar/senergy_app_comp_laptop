const express = require('express');
const expressAsyncHandler = require('express-async-handler');
const { isAdmin, isAuth } = require('../utils.js');
const db = require("../models");
const Trip = db.trips;
const Car = db.cars;
const Purpose = db.purposes;
const Op = db.Sequelize.Op;
const sequelize = require('sequelize');

const tripRouter = express.Router();

tripRouter.get(
  '/mine',
  isAuth,
  expressAsyncHandler(async (req, res) => {

    const trips = await Trip.findAll({ where: { user_id: req.user._id } });
    res.send(trips);
  })
);


tripRouter.get(
  '/',
  isAuth,
  isAdmin,
  expressAsyncHandler(async (req, res) => {
    try {
      const trips = await Trip.findAll();
      res.send(trips);

    } catch (error) {
      console.log(error);
      res.status(500).send(error);
    }
  })
);
tripRouter.get(
  '/cars/cars',
  isAuth,
  expressAsyncHandler(async (req, res) => {
    try {
      const cars = await Car.findAll();
      res.send(cars);

    } catch (error) {
      console.log(error);
      res.status(500).send(error);
    }
  })
);

tripRouter.post(
  '/',
  isAuth,
  expressAsyncHandler(async (req, res) => {





    const unixTimestamp = Number(req.body.startTimeStamp);

    const date = new Date(unixTimestamp);

    const hours = date.getHours();



    const newTrip = new Trip(req.body);
    newTrip.user_id = req.user._id;
    if(hours < 18 && hours >=4){
      newTrip.isApproved = true;
      newTrip.isApprovedAt = Date.now();
    }
    try {

      if ( (req.body.phone === '') || (req.body.carNumber === '') || (req.body.passengers === '') || (req.body.from === '') || (req.body.to === '') || (req.body.to == '')


      ) {
        console.log(req.body)
        res.status(400).send({ message: 'Your should input all data' });
      }
      else if (req.body.vehicle === false) {
        res.status(400).send({ message: 'Car should have license' });
      }

      else {

        const createdtrip = await newTrip.save();
        res
          .status(201)
          .send({ message: 'New trip Created', trip: createdtrip });
      }
    } catch (error) {
      console.log(error)
    }
  })
);

tripRouter.get(
  '/:id',
  isAuth,
  expressAsyncHandler(async (req, res) => {
    // const trip = await Trip.findByPk(req.params.id);
    const trip = await Trip.findAll({where: {id: req.params.id},include: [
      'carr',
      'userr',
      'purposee'

    ],});
    if (trip) {
      res.send(trip);
    } else {
      res.status(404).send({ message: 'trip Not Found' });
    }
  })
);

tripRouter.put(
  '/:id/approve',
  isAuth,
  isAdmin,
  expressAsyncHandler(async (req, res) => {

    try {

      const trip = await Trip.findByPk(req.params.id);
      if (trip) {
        trip.isApproved = true;
        trip.isApprovedAt = Date.now();

        const approvedTrip = await trip.save();
        res.send({ message: 'trip approved', trip: approvedTrip });
      } else {
        res.status(404).send({ message: 'trip Not Found' });
      }
    } catch (error) {
    }
  })
);
tripRouter.put(
  '/:id/danger',
  isAuth,

  expressAsyncHandler(async (req, res) => {

    try {

      const trip = await Trip.findByPk(req.params.id);
      if (trip) {
        trip.danger = true;
        // trip.isApprovedAt = Date.now();

        const dangerTrip = await trip.save();
        res.send({ message: 'trip in danger', trip: dangerTrip });
      } else {
        res.status(404).send({ message: 'trip Not Found' });
      }
    } catch (error) {
    }
  })
);

//delete trip 
tripRouter.delete(
  '/:id/delete',
  isAuth,
  isAdmin,
  expressAsyncHandler(async (req, res) => {

    try {

      const trip = await Trip.findByPk(req.params.id);
      if (trip) {
        await Trip.destroy({
          where: { id: req.params.id }
        });
        // trip.isApprovedAt = Date.now();


        res.send({ message: 'your trip is deleted', trip: trip });
      } else {
        res.status(404).send({ message: 'trip Not Found' });
      }
    } catch (error) {
      console.log(error);
    }
  })
);
tripRouter.put(
  '/:id/close',
  isAuth,
  expressAsyncHandler(async (req, res) => {

    try {

      const trip = await Trip.findByPk(req.params.id);
      if (trip) {
        trip.isClosed = true;
        trip.isClosedAt = Date.now();

        const closedTrip = await trip.save();
        res.send({ message: 'trip closed', trip: closedTrip });
      } else {
        res.status(404).send({ message: 'trip Not Found' });
      }
    } catch (error) {
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

tripRouter.get(
  '/p/all',
  isAuth,
  isAdmin,
  expressAsyncHandler(async (req, res) => {
    const { page, size, driverName } = req.query;
    const { limit, offset } = getPagination(page, size);
    var condition =  null;


    try {
      // const trips = await Trip.findAndCountAll({ where: condition, limit, offset });
      const trips = await Trip.findAndCountAll({ where: condition, limit, offset, order: [['id', 'DESC']],       
       include: [
        'carr',
        'userr',
        'purposee'

      ],});
      res.send(getPagingData(trips, page, limit));

    } catch (error) {
      console.log(error);
      res.status(500).send(error);
    }
  })
);
//get mine paginated
tripRouter.get(
  '/p/mine',
  isAuth,
  expressAsyncHandler(async (req, res) => {
    const { page, size, driverName } = req.query;
    const { limit, offset } = getPagination(page, size);
    // var condition = driverName ? { driverName: { [Op.like]: `%${driverName}%` } } : null;


    try {
      // const trips = await Trip.findAndCountAll({ where: condition, limit, offset });
      const trips = await Trip.findAndCountAll({ where: { user_id: req.user._id }, limit, offset, order: [['id', 'DESC']],
      include: [
        'carr',
        'userr',
        'purposee'

      ], });
      res.send(getPagingData(trips, page, limit));

    } catch (error) {
      console.log(error);
      res.status(500).send(error);
    }
  })
);

tripRouter.get(
  '/purpose/all/all',
  isAuth,
  expressAsyncHandler(async (req, res) => {
    // const har = await Report.findByPk(req.params.id);
    const purposes = await Purpose.findAll(
      {

      }
    );
    if (purposes) {
      res.send(purposes);
    } else {
      res.status(404).send({ message: 'images Not Found' });
    }
  })
);



module.exports = tripRouter;