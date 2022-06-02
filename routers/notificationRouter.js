const express = require('express');
const expressAsyncHandler = require('express-async-handler');
const bcrypt = require('bcryptjs');
const data = require('../data.js');

const { generateToken, isAuth } = require('../utils.js');
var FCM = require('fcm-node');
const dotenv = require('dotenv');
dotenv.config();
const db = require("../models");
const Device = db.devices;
const Op = db.Sequelize.Op;

const notificationRouter = express.Router();
const server_key = process.env.FIREBASE_SERVER_KEY;
var fcm = new FCM(server_key);

// find admin tokens 
notificationRouter.get(
    '/token/admin',
    expressAsyncHandler(async (req, res) => {
        const device = await Device.findALL({ Where: { isAdmin: true } });
        if (device) {
            res.send(device);
        } else {
            res.status(404).send({ message: 'devices Not Found' });
        }
    })
);
// register device token 
notificationRouter.post(
    '/token/admin',
    expressAsyncHandler(async (req, res) => {
        const mydevice = await Device.findOne({ where: { token: req.body.token } });
        if (mydevice) {
            // console.log(mydevice);

            const newdevice = await Device.update({ token: req.body.token, isAdmin: req.body.isAdmin,user_id:req.body._id }, {
                where: {
                    token: mydevice.token
                }
            })
            const creatednewdevice = await newdevice.save();
            res.send(creatednewdevice);

        } else {

            const device = new Device({
                isAdmin: req.body.isAdmin,
                token: req.body.token,
                user_id:req.body._id,
            });
            const createdDevice = await device.save();

            if (createdDevice) {

                res.send(createdDevice);
                // console.log(createdDevice);
            } else {
                res.status(404).send({ message: 'device not added' });

            }
        }
    }
    )
);
// send notification 
notificationRouter.post(
    '/token/admin/send',
    expressAsyncHandler(async (req, res) => {

        const admin_devices = await Device.findAll({ where: { isAdmin: true } });
        console.log('admin_devices')

        if (admin_devices) {
            const registrationTokens = admin_devices.map((device) => device.token);
            console.log(registrationTokens)
            var message = {
                registration_ids: registrationTokens,
                notification: {
                    title: req.body.title,
                    body: req.body.message,
                },
                // data: { //you can send only notification or only data(or include both)
                //     title: 'ok cdfsdsdfsd',
                //     body: '{"name" : "okg ooggle ogrlrl","product_id" : "123","final_price" : "0.00035"}'
                // }

            };
            try {


                fcm.send(message, function (err, response) {
                    if (err) {
                        console.log("Something has gone wrong!" + err);
                        console.log("Respponse:! " + response);
                    } else {
                        // showToast("Successfully sent with response");
                        console.log("Successfully sent with response: ", response);
                    }

                });
            } catch (error) {
                console.log(error)
            }
            // try {

            //     await fcm.getMessaging().sendMulticast(message)
            //          .then((response) => {
            //              console.log(response.successCount + ' messages were sent successfully');
            //          });
            // } catch (error) {
            //     console.log(error);
            // }


        } else {
            res.status(404).send({ message: 'device not added' });

        }
    })
);










module.exports = notificationRouter;