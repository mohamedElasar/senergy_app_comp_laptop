const express = require('express');
const expressAsyncHandler = require('express-async-handler');
const bcrypt = require("bcrypt")
const CryptoJS = require('crypto-js')


const data = require('../data.js');
const db = require("../models");
const User = db.users;
const Op = db.Sequelize.Op;


const { generateToken, isAuth } = require('../utils.js');

const userRouter = express.Router();

userRouter.get(
  '/seed',
  expressAsyncHandler(async (req, res) => {
    // await User.remove({});
    const createdUsers = await User.insertMany(data.users);
    res.send({ createdUsers });
  })
);

userRouter.post(
  '/signin',
  expressAsyncHandler(async (req, res) => {
    const user = await User.findOne({ where: { email: req.body.email } });

    if (user) {

      const result = await bcrypt.compare(req.body.password, user.password.toString());

      if(result==true){

        res.send({
          _id: user.id,
          name: user.name,
          email: user.email,
          isAdmin: user.isAdmin,
          token: generateToken(user),
        });
        return;
      }
      
    }
    res.status(401).send({ message: 'Invalid email or password' });
  })
);

userRouter.post(
  '/register',
  expressAsyncHandler(async (req, res) => {
    const usercheck = await User.findOne({ where: { email: req.body.email } });
    if(usercheck){
      res.status(401).send({
        message:
          "email already exist"
      });
      return;
    }
    const user = {
      name: req.body.name,
      email: req.body.email,
      password:await bcrypt.hash(req.body.password, 10),
      position:req.body.position,
      isAdmin: req.body.isAdmin
    };

    User.create(user)
      .then(data => {
        const {password,...others} = data.dataValues;
        res.send(others);
      })
      .catch(err => {
        res.status(500).send({
          message:
            err.message || "Some error occurred while creating the user."
        });
      });


  })
);

userRouter.get(
  '/:id',
  expressAsyncHandler(async (req, res) => {
    const user = await User.findByPk(req.params.id);
    if (user) {
      res.send(user);
    } else {
      res.status(404).send({ message: 'User Not Found' });
    }
  })
);
userRouter.get(
  '/',
  expressAsyncHandler(async (req, res) => {
    const user = await User.findAll();
    if (user) {
      res.send(user);
    } else {
      res.status(404).send({ message: 'User Not Found' });
    }
  })
);


module.exports = userRouter;