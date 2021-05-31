import User from "../models/user";
import { hashPassword, comparePassword } from "../utils/auth";
import jwt from "jsonwebtoken";
import AWS from "aws-sdk";
import { nanoid } from "nanoid";

const awsConfig = {
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  region: process.env.AWS_REGION,
  apiVersion: process.env.AWS_API_VERSION,
};
const SES = new AWS.SES(awsConfig);

export const register = async (req, res) => {
  try {
    //console.log(req.body);
    const { name, email, password } = req.body;
    // validation
    if (!name) return res.status(400).send("Name is required");
    if (!email) return res.status(400).send("Email is required");
    if (!password || password.length < 6)
      return res
        .status(400)
        .send("Password is required and should be min 6 characters long");
    let userExist = await User.findOne({ email: email }).exec();
    if (userExist) return res.status(400).send("Email is taken");

    // hash password
    const hashedPassword = await hashPassword(password);

    // register
    const user = new User({
      name,
      email,
      password: hashedPassword,
    });
    await user.save();
    // console.log("Saved user-->", user);
    return res.json({ ok: true });
  } catch (err) {
    console.error(err);
    return res.status(400).send("Error, Try again");
  }
};

export const login = async (req, res) => {
  try {
    // console.log(req.body);
    const { email, password } = req.body;
    // check if db has user with that email
    const user = await User.findOne({ email }).exec();
    if (!user) return res.status(400).send("No user found");
    // check password
    const match = await comparePassword(password, user.password); // user.password is hashed password from db we accessed for checking email
    if (!match) return res.status(400).send("Wrong Password");

    // create signed JWT
    const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "7d",
    });
    // return user and token to client, exclude hashed password
    user.password = undefined; // we make password as undefined, so hashed password will not be send
    // send token and cookie
    res.cookie("token", token, {
      httpOnly: true,
      // secure:true, // only works on https
    });
    // send user as json response
    res.json(user);
  } catch (err) {
    console.error(err);
    return res.status(400).send("Error, Try again");
  }
};

export const logout = async (req, res) => {
  try {
    res.clearCookie("token");
    return res.json({ message: "logout success" });
  } catch (err) {
    console.error(err);
  }
};

export const currentUser = async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select("-password").exec();
    console.log("CURRENT_USER--->", user);
    return res.json({ ok: true });
  } catch (err) {
    console.error(err);
  }
};

export const forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;
    const shortCode = nanoid(6).toUpperCase();
    const user = await User.findOneAndUpdate(
      { email }, // first params is what to find
      { passwordResetCode: shortCode } // second is what to update
    );
    if (!user) return res.status(400).send("User not found");

    // prepare for email
    const params = {
      Source: process.env.EMAIL_FROM,
      Destination: {
        ToAddresses: [email],
      },
      Message: {
        Body: {
          Html: {
            Charset: "UTF-8",
            Data: `
          <html>
          <h1>Reset Password link</h1>
          <p>Please use following link to reset your password</p>
          <h2 style="color:red;">${shortCode}</h2>
          <i>edemy.com</i>
          </html>
          `,
          },
        },
        Subject: {
          Charset: "UTF-8",
          Data: "Password reset code",
        },
      },
    };

    const emailSent = SES.sendEmail(params).promise();

    emailSent
      .then((data) => {
        console.log(data);
        res.json({ ok: true });
      })
      .catch((err) => console.error(err));
  } catch (err) {
    console.error(err);
  }
};

export const resetPassword = async (req, res) => {
  try {
    const { email, code, newPassword } = req.body;
    const hashedPassword = await hashPassword(newPassword);

    const user = User.findOneAndUpdate(
      { email, passwordResetCode: code },
      { password: hashedPassword, passwordResetCode: "" }
    ).exec();
    return res.json({ ok: true });
  } catch (err) {
    console.error(err);
    return res.status(400).send("Error, Try again");
  }
};
