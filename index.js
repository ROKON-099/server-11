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
app.use(express.json()); // ✅ FIX 1: REQUIRED

app.use(
  cors({
    origin: [
      "http://localhost:5173",
      "http://localhost:5174",
      "https://client-11-s787.vercel.app",
      "https://client-11-hlov.vercel.app",
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
  if (!token) return res.status(401).send({ message: "Unauthorized" });

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).send({ message: "Unauthorized" });
    req.user = decoded;
    next();
  });
};

const verifyAdmin = async (req, res, next) => {
  const user = await userCollection.findOne({ email: req.user.email });
  if (user?.role !== "admin")
    return res.status(403).send({ message: "Forbidden" });
  next();
};

const verifyVolunteer = async (req, res, next) => {
  const user = await userCollection.findOne({ email: req.user.email });
  if (!["volunteer", "admin"].includes(user?.role))
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
       JWT (SAFE)
    ====================== */
    app.post("/jwt", async (req, res) => {
      try {
        const { email } = req.body;

        if (!email) {
          return res.status(400).send({ message: "Email is required" });
        }

        const user = await userCollection.findOne({ email });
        if (!user) {
          return res.status(404).send({ message: "User not found" });
        }

        const token = jwt.sign(
          { email: user.email, role: user.role },
          process.env.JWT_SECRET,
          { expiresIn: "7d" }
        );

        res.send({ token });
      } catch (error) {
        console.error("JWT ERROR:", error);
        res.status(500).send({ message: "JWT generation failed" });
      }
    });

    /* ======================
       USERS
    ====================== */
    app.post("/users", async (req, res) => {
  const user = req.body;

  const email = user.email.toLowerCase(); // 🔥 FIX

  const exists = await userCollection.findOne({ email });
  if (exists) return res.send({ message: "User exists" });

  const result = await userCollection.insertOne({
    ...user,
    email, // 🔥 lowercase email
    role: "donor",
    status: "active",
  });

  res.send(result);
});


    app.get("/users", verifyToken, verifyAdmin, async (req, res) => {
      const query =
        req.query.status && req.query.status !== "all"
          ? { status: req.query.status }
          : {};
      res.send(await userCollection.find(query).toArray());
    });

    app.get("/users/:email", verifyToken, async (req, res) => {
      res.send(
        (await userCollection.findOne({ email: req.params.email })) || {}
      );
    });

    app.get("/users/admin/:email", verifyToken, async (req, res) => {
      if (req.params.email !== req.user.email)
        return res.status(403).send({ message: "Forbidden" });

      const user = await userCollection.findOne({ email: req.params.email });
      res.send({ admin: user?.role === "admin" });
    });

    app.get("/users/volunteer/:email", verifyToken, async (req, res) => {
      if (req.params.email !== req.user.email)
        return res.status(403).send({ message: "Forbidden" });

      const user = await userCollection.findOne({ email: req.params.email });
      res.send({
        volunteer: user?.role === "volunteer" || user?.role === "admin",
      });
    });

    app.patch("/users/status/:id", verifyToken, verifyAdmin, async (req, res) => {
      await userCollection.updateOne(
        { _id: new ObjectId(req.params.id) },
        { $set: { status: req.body.status } }
      );
      res.send({ modifiedCount: 1 });
    });

    app.patch("/users/volunteer/:id", verifyToken, verifyAdmin, async (req, res) => {
      await userCollection.updateOne(
        { _id: new ObjectId(req.params.id) },
        { $set: { role: "volunteer" } }
      );
      res.send({ modifiedCount: 1 });
    });

    app.patch("/users/admin/:id", verifyToken, verifyAdmin, async (req, res) => {
      await userCollection.updateOne(
        { _id: new ObjectId(req.params.id) },
        { $set: { role: "admin" } }
      );
      res.send({ modifiedCount: 1 });
    });

    /* ======================
       DONATION REQUESTS
    ====================== */
    app.post("/donation-requests", verifyToken, async (req, res) => {
      const user = await userCollection.findOne({ email: req.user.email });
      if (user.status === "blocked")
        return res.status(403).send({ message: "Blocked user" });

      const result = await donationCollection.insertOne({
        ...req.body,
        donationStatus: "pending",
      });
      res.send(result);
    });

    app.get("/donation-requests/public", async (req, res) => {
      res.send(
        await donationCollection
          .find({ donationStatus: "pending" })
          .toArray()
      );
    });

    app.get("/donation-requests", verifyToken, async (req, res) => {
      if (req.query.email !== req.user.email)
        return res.status(403).send({ message: "Forbidden" });

      res.send(
        await donationCollection
          .find({ requesterEmail: req.user.email })
          .toArray()
      );
    });

    app.get(
      "/donation-requests/all",
      verifyToken,
      verifyVolunteer,
      async (req, res) => {
        const query = req.query.status
          ? { donationStatus: req.query.status }
          : {};
        res.send(await donationCollection.find(query).toArray());
      }
    );

    app.get("/donation-requests/:id", verifyToken, async (req, res) => {
      try {
        const donation = await donationCollection.findOne({
          _id: new ObjectId(req.params.id),
        });

        if (!donation) {
          return res.status(404).send({ message: "Donation not found" });
        }

        res.send(donation);
      } catch {
        res.status(400).send({ message: "Invalid donation ID" });
      }
    });

    app.patch("/donation-requests/:id", verifyToken, async (req, res) => {
      const user = await userCollection.findOne({ email: req.user.email });
      const donation = await donationCollection.findOne({
        _id: new ObjectId(req.params.id),
      });

      if (!donation) return res.status(404).send({ message: "Not found" });

      if (user.role === "donor" && donation.requesterEmail !== user.email)
        return res.status(403).send({ message: "Forbidden" });

      const validFlow = {
        pending: ["inprogress"],
        inprogress: ["done", "canceled"],
      };

      if (
        req.body.donationStatus &&
        !validFlow[donation.donationStatus]?.includes(
          req.body.donationStatus
        )
      )
        return res.status(400).send({ message: "Invalid status flow" });

      res.send(
        await donationCollection.updateOne(
          { _id: donation._id },
          { $set: req.body }
        )
      );
    });

    app.delete("/donation-requests/:id", verifyToken, async (req, res) => {
      const user = await userCollection.findOne({ email: req.user.email });
      const donation = await donationCollection.findOne({
        _id: new ObjectId(req.params.id),
      });

      if (user.role !== "admin" && donation.requesterEmail !== user.email)
        return res.status(403).send({ message: "Forbidden" });

      res.send(await donationCollection.deleteOne({ _id: donation._id }));
    });

    /* ======================
       FUNDING
    ====================== */
    app.post("/create-payment-intent", verifyToken, async (req, res) => {
      if (!stripe)
        return res.status(500).send({ message: "Stripe not configured" });

      const amount = Math.round(req.body.amount * 100);

      const intent = await stripe.paymentIntents.create({
        amount,
        currency: "usd",
        payment_method_types: ["card"],
      });

      res.send({ clientSecret: intent.client_secret });
    });

    app.get("/fundings", verifyToken, async (req, res) => {
      res.send(await fundingCollection.find().sort({ createdAt: -1 }).toArray());
    });

    app.post("/fundings", verifyToken, async (req, res) => {
      res.send(
        await fundingCollection.insertOne({
          ...req.body,
          createdAt: new Date(),
        })
      );
    });

    /* ======================
       ADMIN STATS
    ====================== */
    app.get("/admin-stats", verifyToken, verifyVolunteer, async (req, res) => {
      const users = await userCollection.countDocuments({ role: "donor" });
      const requests = await donationCollection.countDocuments();
      const fundAgg = await fundingCollection
        .aggregate([{ $group: { _id: null, total: { $sum: "$amount" } } }])
        .toArray();

      res.send({
        users,
        requests,
        totalFunds: fundAgg[0]?.total || 0,
      });
    });

    console.log("MongoDB Connected");
  } catch (err) {
    console.error(err);
  }
}

run();

app.get("/", (req, res) => res.send("Blood Donation Server Running"));
app.listen(port, () => console.log(`Server running on port ${port}`));
