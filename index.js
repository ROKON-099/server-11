

const express = require("express");
const cors = require("cors");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const jwt = require("jsonwebtoken");
require("dotenv").config();
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);

const app = express();
const port = process.env.PORT || 5000;

/* ======================
   Middleware
====================== */
app.use(cors());
app.use(express.json());

/* ======================
   MongoDB URI
====================== */
const uri = process.env.MONGODB_URI;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

/* ======================
   JWT Middleware
====================== */
const verifyToken = (req, res, next) => {
  if (!req.headers.authorization) {
    return res.status(401).send({ message: "unauthorized access" });
  }
  const token = req.headers.authorization.split(" ")[1];
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).send({ message: "unauthorized access" });
    }
    req.decoded = decoded;
    next();
  });
};

/* ======================
   Role Middleware
====================== */
const verifyAdmin = async (req, res, next) => {
  const email = req.decoded.email;
  const user = await userCollection.findOne({ email });
  if (user?.role !== "admin") {
    return res.status(403).send({ message: "forbidden access" });
  }
  next();
};

const verifyVolunteer = async (req, res, next) => {
  const email = req.decoded.email;
  const user = await userCollection.findOne({ email });
  if (user?.role !== "volunteer" && user?.role !== "admin") {
    return res.status(403).send({ message: "forbidden access" });
  }
  next();
};

/* ======================
   Main Function
====================== */
let userCollection;
let donationCollection;
let fundingCollection;

async function run() {
  try {
    await client.connect();

    const db = client.db("blood-db");
    userCollection = db.collection("users");
    donationCollection = db.collection("donationRequests");
    fundingCollection = db.collection("fundings");

    /* ======================
       AUTH / JWT
    ====================== */
    app.post("/jwt", (req, res) => {
      const user = req.body;
      const token = jwt.sign(user, process.env.JWT_SECRET, {
        expiresIn: "1h",
      });
      res.send({ token });
    });

    /* ======================
       USERS API
    ====================== */

    // Register User
    app.post("/users", async (req, res) => {
      const user = req.body;
      const exists = await userCollection.findOne({ email: user.email });
      if (exists) {
        return res.send({ message: "user already exists" });
      }
      user.role = "donor";
      user.status = "active";
      const result = await userCollection.insertOne(user);
      res.send(result);
    });

    // Get all users (Admin)
    app.get("/users", verifyToken, verifyAdmin, async (req, res) => {
      const status = req.query.status;
      const query = status ? { status } : {};
      const result = await userCollection.find(query).toArray();
      res.send(result);
    });

    // Get single user
    app.get("/users/:email", verifyToken, async (req, res) => {
      if (req.params.email !== req.decoded.email) {
        return res.status(403).send({ message: "forbidden" });
      }
      const user = await userCollection.findOne({
        email: req.params.email,
      });
      res.send(user);
    });

    // Update profile
    app.patch("/users/:email", verifyToken, async (req, res) => {
      const update = {
        $set: {
          name: req.body.name,
          bloodGroup: req.body.bloodGroup,
          district: req.body.district,
          upazila: req.body.upazila,
          avatar: req.body.avatar,
        },
      };
      const result = await userCollection.updateOne(
        { email: req.params.email },
        update
      );
      res.send(result);
    });

    // Make Admin
    app.patch("/users/admin/:id", verifyToken, verifyAdmin, async (req, res) => {
      const result = await userCollection.updateOne(
        { _id: new ObjectId(req.params.id) },
        { $set: { role: "admin" } }
      );
      res.send(result);
    });

    // Make Volunteer
    app.patch(
      "/users/volunteer/:id",
      verifyToken,
      verifyAdmin,
      async (req, res) => {
        const result = await userCollection.updateOne(
          { _id: new ObjectId(req.params.id) },
          { $set: { role: "volunteer" } }
        );
        res.send(result);
      }
    );

    // Block / Unblock
    app.patch(
      "/users/status/:id",
      verifyToken,
      verifyAdmin,
      async (req, res) => {
        const result = await userCollection.updateOne(
          { _id: new ObjectId(req.params.id) },
          { $set: { status: req.body.status } }
        );
        res.send(result);
      }
    );

    /* ======================
       DONATION REQUEST API
    ====================== */

    // Create request
    app.post("/donation-requests", verifyToken, async (req, res) => {
      const user = await userCollection.findOne({
        email: req.body.requesterEmail,
      });
      if (user?.status === "blocked") {
        return res.send({ message: "blocked user" });
      }
      req.body.donationStatus = "pending";
      const result = await donationCollection.insertOne(req.body);
      res.send(result);
    });

    // Public pending requests
    app.get("/donation-requests/public", async (req, res) => {
      const result = await donationCollection
        .find({ donationStatus: "pending" })
        .toArray();
      res.send(result);
    });

    // My requests
    app.get("/donation-requests", verifyToken, async (req, res) => {
      if (req.query.email !== req.decoded.email) {
        return res.status(403).send({ message: "forbidden" });
      }
      const result = await donationCollection
        .find({ requesterEmail: req.query.email })
        .toArray();
      res.send(result);
    });

    // All requests (Admin / Volunteer)
    app.get(
      "/donation-requests/all",
      verifyToken,
      verifyVolunteer,
      async (req, res) => {
        const status = req.query.status;
        const query = status ? { donationStatus: status } : {};
        const result = await donationCollection.find(query).toArray();
        res.send(result);
      }
    );

    // Update status
    app.patch("/donation-requests/:id", verifyToken, async (req, res) => {
      const update = { $set: req.body };
      const result = await donationCollection.updateOne(
        { _id: new ObjectId(req.params.id) },
        update
      );
      res.send(result);
    });

    // Delete
    app.delete("/donation-requests/:id", verifyToken, async (req, res) => {
      const result = await donationCollection.deleteOne({
        _id: new ObjectId(req.params.id),
      });
      res.send(result);
    });

    /* ======================
       FUNDING / STRIPE
    ====================== */

    app.post("/create-payment-intent", verifyToken, async (req, res) => {
      const amount = parseInt(req.body.amount * 100);
      const paymentIntent = await stripe.paymentIntents.create({
        amount,
        currency: "usd",
        payment_method_types: ["card"],
      });
      res.send({ clientSecret: paymentIntent.client_secret });
    });

    app.post("/fundings", verifyToken, async (req, res) => {
      const result = await fundingCollection.insertOne(req.body);
      res.send(result);
    });
    const axios = require("axios");

app.post("/upload-image", verifyToken, async (req, res) => {
  try {
    const { image } = req.body;

    if (!image) {
      return res.status(400).send({ message: "image is required" });
    }

    const response = await axios.post(
      `https://api.imgbb.com/1/upload?key=${process.env.IMGBB_API_KEY}`,
      { image }
    );

    res.send({
      success: true,
      imageUrl: response.data.data.url,
    });
  } catch (error) {
    res.status(500).send({
      success: false,
      message: "Image upload failed",
    });
  }
});


    /* ======================
       ADMIN STATS
    ====================== */
    app.get("/admin-stats", verifyToken, verifyAdmin, async (req, res) => {
      const users = await userCollection.countDocuments();
      const requests = await donationCollection.countDocuments();
      const funds = await fundingCollection.find().toArray();
      const totalFunds = funds.reduce(
        (sum, item) => sum + item.amount,
        0
      );
      res.send({ users, requests, totalFunds });
    });

    console.log(" MongoDB connected");
  } finally {
  }
}
run();

/* ======================
   Root
====================== */
app.get("/", (req, res) => {
  res.send(" Blood Donation Server is running");
});

app.listen(port, () => {
  console.log(` Server running on port ${port}`);
});
