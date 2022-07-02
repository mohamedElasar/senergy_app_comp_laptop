
const express = require('express');

const dotenv = require('dotenv');
const userRouter =require('./routers/userRouter.js') ;
const tripRouter =require('./routers/tripRouter.js') ;
const notificationRouter =require('./routers/notificationRouter.js') ;
const HarRouter =require('./routers/HAR_Router.js') ;

const multer = require('multer');
const path = require('path')
var bodyParser = require('body-parser');


dotenv.config();

const app = express();
app.use(express.json());
app.use(bodyParser.urlencoded({extended: true}));
app.use(bodyParser.json());


app.use(express.urlencoded({ extended: true }));
app.use('/images',express.static(path.join(__dirname,'images')))


const db = require("./models");
db.sequelize.sync({ force: false });

app.use('/api/users', userRouter);
app.use('/api/trips', tripRouter);
app.use('/api/notifications', notificationRouter);
app.use('/api/har', HarRouter);
// app.use('/api/products', productRouter);
// app.use('/api/orders', orderRouter);
// app.get('/api/config/paypal', (req, res) => {
//   res.send(process.env.PAYPAL_CLIENT_ID || 'sb');
// });
const storage = multer.diskStorage({
  destination:(req,file,cb)=>{
      cb(null, 'images')
  }, filename:(req,file,cb)=>{
      cb(null,new Date().toISOString().replace(/:/g, '-')+file.originalname)
      
  }

})

const upload = multer({storage:storage});
app.post('/api/upload',upload.single('file'),(req,res)=>{
  console.log(req.file);
  res.status(200).json('file has been uploaded')
})



app.get('/', (req, res) => {
  res.send('Server is ready');
});

app.use((err, req, res, next) => {
  res.status(500).send({ message: err.message });
});

const port = process.env.PORT || 5000;
app.listen(port, () => {
  console.log(`Serve at http://localhost:${port}`);
});
