const nodemailer = require("nodemailer");

const transporter = nodemailer.createTransport({  //Creates mail transporter object.
      service: "gmail", //Tells nodemailer to use Gmail service.
      auth: {
        user: process.env.MAIL_USER,
        pass: process.env.MAIL_PASS
      }  //Uses email and app password from .env
})
module.exports = transporter; //Exports transporter so we can use it in controller.