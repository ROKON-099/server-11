const express = require("express");
const cors = require("cors");
const { MongoClient, ObjectId } = require("mongodb");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const stripe = process.env.STRIPE_SECRET_KEY
  ? require("stripe")(process.env.STRIPE_SECRET_KEY)
  : null;

const app = express();
const port = process.env.PORT || 5000;

/* ======================
   Middleware
====================== */
app.use(
  cors({
    origin: [
      "http://localhost:5173",
      "https://client-11-f4tc.vercel.app",
    ],
    credentials: true,
  })
);

/* ======================
   MongoDB
====================== */

const client = new MongoClient(process.env.MONGODB_URI);

let userCollection;
let donationCollection;
let fundingCollection;

/* ======================
   Auth Middleware
====================== */

const verifyToken = (req, res, next) => {

  const token = req.headers.authorization?.split(" ")[1];

  if (!token)
    return res.status(401).send({ message: "Unauthorized" });

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {

    if (err)
      return res.status(401).send({ message: "Unauthorized" });

    req.user = decoded;

    next();

  });

};

const verifyAdmin = async (req, res, next) => {

  const user = await userCollection.findOne({
    email: req.user.email,
  });

  if (user?.role !== "admin")
    return res.status(403).send({ message: "Forbidden" });

  next();

};

const verifyVolunteer = async (req, res, next) => {

  const user = await userCollection.findOne({
    email: req.user.email,
  });

  if (!["admin", "volunteer"].includes(user?.role))
    return res.status(403).send({ message: "Forbidden" });

  next();

};

/* ======================
   Main
====================== */

async function run() {

  try {

    await client.connect();

    const db = client.db("blood-bd");

    userCollection = db.collection("users");

    donationCollection = db.collection("donationRequests");

    fundingCollection = db.collection("fundings");

    /* ======================
       JWT (FIXED SECURE)
    ====================== */

    app.post("/jwt", async (req, res) => {

      const { email } = req.body;

      const user = await userCollection.findOne({ email });

      if (!user)
        return res.status(401).send({
          message: "User not found",
        });

      const token = jwt.sign(
        {
          email: user.email,
          role: user.role,
        },
        process.env.JWT_SECRET,
        {
          expiresIn: "7d",
        }
      );

      res.send({ token });

    });

    /* ======================
       USERS (FIXED)
    ====================== */

    app.post("/users", async (req, res) => {

      const user = req.body;

      user.role = "donor";

      user.status = "active";

      const result = await userCollection.insertOne(user);

      res.send(result);

    });

    app.get("/users/:email", verifyToken, async (req, res) => {

      res.send(
        (await userCollection.findOne({
          email: req.params.email,
        })) || {}
      );

    });

    app.patch("/users/:email", verifyToken, async (req, res) => {

      const email = req.params.email.toLowerCase();

      if (email !== req.user.email)
        return res.status(403).send({
          message: "Forbidden",
        });

      const result = await userCollection.updateOne(
        { email },
        { $set: req.body }
      );

      res.send(result);

    });

    app.get("/users", verifyToken, verifyAdmin, async (req, res) => {

      const query =
        req.query.status && req.query.status !== "all"
          ? { status: req.query.status }
          : {};

      res.send(await userCollection.find(query).toArray());

    });

    app.get("/users/admin/:email", verifyToken, async (req, res) => {

      if (req.params.email !== req.user.email)
        return res.status(403).send({
          message: "Forbidden",
        });

      const user = await userCollection.findOne({
        email: req.params.email,
      });

      res.send({
        admin: user?.role === "admin",
      });

    });

    app.get("/users/volunteer/:email", verifyToken, async (req, res) => {

      if (req.params.email !== req.user.email)
        return res.status(403).send({
          message: "Forbidden",
        });

      const user = await userCollection.findOne({
        email: req.params.email,
      });

      res.send({
        volunteer:
          user?.role === "volunteer" ||
          user?.role === "admin",
      });

    });

    app.patch(
      "/users/status/:id",
      verifyToken,
      verifyAdmin,
      async (req, res) => {

        await userCollection.updateOne(
          { _id: new ObjectId(req.params.id) },
          {
            $set: {
              status: req.body.status,
            },
          }
        );

        res.send({ modifiedCount: 1 });

      }
    );

    app.patch(
      "/users/volunteer/:id",
      verifyToken,
      verifyAdmin,
      async (req, res) => {

        await userCollection.updateOne(
          { _id: new ObjectId(req.params.id) },
          {
            $set: { role: "volunteer" },
          }
        );

        res.send({ modifiedCount: 1 });

      }
    );

    app.patch(
      "/users/admin/:id",
      verifyToken,
      verifyAdmin,
      async (req, res) => {

        await userCollection.updateOne(
          { _id: new ObjectId(req.params.id) },
          {
            $set: { role: "admin" },
          }
        );

        res.send({ modifiedCount: 1 });

      }
    );

    /* ======================
       SEARCH DONORS (ADDED)
    ====================== */

    app.get("/search-donors", async (req, res) => {

      const query = {
        role: "donor",
        status: "active",
      };

      if (req.query.bloodGroup)
        query.bloodGroup =
          req.query.bloodGroup;

      if (req.query.district)
        query.district =
          req.query.district;

      if (req.query.upazila)
        query.upazila =
          req.query.upazila;

      res.send(
        await userCollection.find(query).toArray()
      );

    });

    /* ======================
       DONATION REQUESTS
    ====================== */

    app.post(
      "/donation-requests",
      verifyToken,
      async (req, res) => {

        const user =
          await userCollection.findOne({
            email: req.user.email,
          });

        if (user.status === "blocked")
          return res.status(403).send({
            message: "Blocked user",
          });

        const result =
          await donationCollection.insertOne({
            ...req.body,
            donationStatus: "pending",
          });

        res.send(result);

      }
    );

    app.get(
      "/donation-requests/public",
      async (req, res) => {

        res.send(
          await donationCollection
            .find({
              donationStatus: "pending",
            })
            .toArray()
        );

      }
    );

    /* PAGINATION ADDED */

    app.get(
      "/donation-requests",
      verifyToken,
      async (req, res) => {

        if (req.query.email !== req.user.email)
          return res.status(403).send({
            message: "Forbidden",
          });

        const page =
          parseInt(req.query.page) || 0;

        const size =
          parseInt(req.query.size) || 10;

        res.send(
          await donationCollection
            .find({
              requesterEmail:
                req.user.email,
            })
            .skip(page * size)
            .limit(size)
            .toArray()
        );

      }
    );

    app.patch(
      "/donation-requests/:id",
      verifyToken,
      async (req, res) => {

        const donation =
          await donationCollection.findOne({
            _id: new ObjectId(
              req.params.id
            ),
          });

        if (
          req.body.donationStatus ===
          "inprogress"
        ) {

          req.body.donorEmail =
            req.user.email;

        }

        res.send(
          await donationCollection.updateOne(
            { _id: donation._id },
            { $set: req.body }
          )
        );

      }
    );

    app.delete(
      "/donation-requests/:id",
      verifyToken,
      async (req, res) => {

        res.send(
          await donationCollection.deleteOne({
            _id: new ObjectId(
              req.params.id
            ),
          })
        );

      }
    );

    /* ======================
       FUNDING
    ====================== */

    app.post(
      "/create-payment-intent",
      verifyToken,
      async (req, res) => {

        const amount = Math.round(
          req.body.amount * 100
        );

        const intent =
          await stripe.paymentIntents.create(
            {
              amount,
              currency: "usd",
            }
          );

        res.send({
          clientSecret:
            intent.client_secret,
        });

      }
    );

    app.get(
      "/fundings",
      verifyToken,
      async (req, res) => {

        res.send(
          await fundingCollection
            .find()
            .toArray()
        );

      }
    );

    app.post(
      "/fundings",
      verifyToken,
      async (req, res) => {

        res.send(
          await fundingCollection.insertOne(
            {
              ...req.body,
              createdAt:
                new Date(),
            }
          )
        );

      }
    );

    /* ======================
       ADMIN STATS
    ====================== */

    app.get(
      "/admin-stats",
      verifyToken,
      verifyVolunteer,
      async (req, res) => {

        const users =
          await userCollection.countDocuments(
            {
              role: "donor",
            }
          );

        const requests =
          await donationCollection.countDocuments();

        const funds =
          await fundingCollection
            .aggregate([
              {
                $group: {
                  _id: null,
                  total: {
                    $sum: "$amount",
                  },
                },
              },
            ])
            .toArray();

        res.send({
          users,
          requests,
          totalFunds:
            funds[0]?.total || 0,
        });

      }
    );

    console.log(
      "MongoDB Connected"
    );

  } catch (err) {

    console.error(err);

  }

}

run();

app.get("/", (req, res) =>
  res.send(
    "Blood Donation Server Running"
  )
);

app.listen(port, () =>
  console.log(
    `Server running on port ${port}`
  )
);