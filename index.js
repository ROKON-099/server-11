const express = require("express");
const cors = require("cors");
const { MongoClient, ObjectId, ServerApiVersion } = require("mongodb");
const jwt = require("jsonwebtoken");
const axios = require("axios");
const FormData = require("form-data");
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
      "http://localhost:3000",
      
    ],
    credentials: true,
  })
);
app.use(express.json());

/* ======================
   MongoDB
====================== */
const client = new MongoClient(process.env.MONGODB_URI, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

let userCollection;
let donationCollection;
let fundingCollection;

/* ======================
   JWT Middleware
====================== */
const verifyToken = (req, res, next) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).send({ message: "unauthorized" });

  const token = auth.split(" ")[1];
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).send({ message: "unauthorized" });
    req.decoded = decoded;
    next();
  });
};

const verifyAdmin = async (req, res, next) => {
  const user = await userCollection.findOne({ email: req.decoded.email });
  if (user?.role !== "admin") {
    return res.status(403).send({ message: "forbidden" });
  }
  next();
};

const verifyVolunteer = async (req, res, next) => {
  const user = await userCollection.findOne({ email: req.decoded.email });
  if (!["admin", "volunteer"].includes(user?.role)) {
    return res.status(403).send({ message: "forbidden" });
  }
  next();
};

/* ======================
   Main
====================== */
async function run() {
  try {
    await client.connect();
    const db = client.db("blood-db");

    userCollection = db.collection("users");
    donationCollection = db.collection("donationRequests");
    fundingCollection = db.collection("fundings");

    /* Indexes */
    await userCollection.createIndex({ email: 1 }, { unique: true });
    await donationCollection.createIndex({ requesterEmail: 1 });
    await donationCollection.createIndex({ donationStatus: 1 });

    /* ======================
       JWT
    ====================== */
    app.post("/jwt", async (req, res) => {
      const { email } = req.body;
      const user = await userCollection.findOne({ email });
      if (!user) return res.status(401).send({ message: "unauthorized" });

      const token = jwt.sign(
        { email: user.email, role: user.role },
        process.env.JWT_SECRET,
        { expiresIn: "1h" }
      );

      res.send({ token });
    });

    /* ======================
       USERS
    ====================== */
    app.post("/users", async (req, res) => {
      const user = req.body;
      const exists = await userCollection.findOne({ email: user.email });
      if (exists) return res.send({ message: "user already exists" });

      user.role = "donor";
      user.status = "active";
      res.send(await userCollection.insertOne(user));
    });

    app.get("/users", verifyToken, verifyAdmin, async (req, res) => {
      const query = req.query.status ? { status: req.query.status } : {};
      res.send(await userCollection.find(query).toArray());
    });

    app.get("/users/:email", verifyToken, async (req, res) => {
      if (req.params.email !== req.decoded.email) {
        return res.status(403).send({ message: "forbidden" });
      }
      res.send(await userCollection.findOne({ email: req.params.email }));
    });

    app.patch("/users/:email", verifyToken, async (req, res) => {
      if (req.params.email !== req.decoded.email) {
        return res.status(403).send({ message: "forbidden" });
      }

      const update = {
        $set: {
          name: req.body.name,
          bloodGroup: req.body.bloodGroup,
          district: req.body.district,
          upazila: req.body.upazila,
          avatar: req.body.avatar,
        },
      };

      res.send(await userCollection.updateOne({ email: req.params.email }, update));
    });

    app.patch("/users/admin/:id", verifyToken, verifyAdmin, async (req, res) => {
      res.send(
        await userCollection.updateOne(
          { _id: new ObjectId(req.params.id) },
          { $set: { role: "admin" } }
        )
      );
    });

    app.patch("/users/volunteer/:id", verifyToken, verifyAdmin, async (req, res) => {
      res.send(
        await userCollection.updateOne(
          { _id: new ObjectId(req.params.id) },
          { $set: { role: "volunteer" } }
        )
      );
    });

    app.patch("/users/status/:id", verifyToken, verifyAdmin, async (req, res) => {
      res.send(
        await userCollection.updateOne(
          { _id: new ObjectId(req.params.id) },
          { $set: { status: req.body.status } }
        )
      );
    });

    /* ======================
       DONOR SEARCH (PUBLIC)
    ====================== */
    app.get("/donors", async (req, res) => {
      const query = {
        role: "donor",
        status: "active",
        ...(req.query.bloodGroup && { bloodGroup: req.query.bloodGroup }),
        ...(req.query.district && { district: req.query.district }),
        ...(req.query.upazila && { upazila: req.query.upazila }),
      };

      res.send(await userCollection.find(query).toArray());
    });

    /* ======================
       DONATION REQUESTS
    ====================== */
    app.post("/donation-requests", verifyToken, async (req, res) => {
      const user = await userCollection.findOne({ email: req.decoded.email });
      if (user.status === "blocked") {
        return res.status(403).send({ message: "blocked user" });
      }

      req.body.donationStatus = "pending";
      res.send(await donationCollection.insertOne(req.body));
    });

    app.get("/donation-requests/public", async (req, res) => {
      res.send(
        await donationCollection.find({ donationStatus: "pending" }).toArray()
      );
    });

    app.get("/donation-requests", verifyToken, async (req, res) => {
      if (req.query.email !== req.decoded.email) {
        return res.status(403).send({ message: "forbidden" });
      }
      res.send(
        await donationCollection
          .find({ requesterEmail: req.query.email })
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

    app.patch("/donation-requests/:id", verifyToken, async (req, res) => {
      const user = await userCollection.findOne({ email: req.decoded.email });
      const donation = await donationCollection.findOne({
        _id: new ObjectId(req.params.id),
      });

      if (user.role === "donor" && donation.requesterEmail !== user.email) {
        return res.status(403).send({ message: "forbidden" });
      }

      if (
        user.role === "volunteer" &&
        Object.keys(req.body).length !== 1
      ) {
        return res.status(403).send({ message: "restricted" });
      }

      const validFlow = {
        pending: ["inprogress"],
        inprogress: ["done", "canceled"],
      };

      if (
        req.body.donationStatus &&
        !validFlow[donation.donationStatus]?.includes(req.body.donationStatus)
      ) {
        return res.status(400).send({ message: "invalid status flow" });
      }

      res.send(
        await donationCollection.updateOne(
          { _id: donation._id },
          { $set: req.body }
        )
      );
    });

    app.delete("/donation-requests/:id", verifyToken, async (req, res) => {
      const user = await userCollection.findOne({ email: req.decoded.email });
      const donation = await donationCollection.findOne({
        _id: new ObjectId(req.params.id),
      });

      if (user.role !== "admin" && donation.requesterEmail !== user.email) {
        return res.status(403).send({ message: "forbidden" });
      }

      res.send(await donationCollection.deleteOne({ _id: donation._id }));
    });

    /* ======================
       STRIPE & FUNDING
    ====================== */
    app.post("/create-payment-intent", verifyToken, async (req, res) => {
      if (!stripe) {
        return res.status(500).send({ message: "Stripe not configured" });
      }

      const amount = Math.round(req.body.amount * 100);
      const intent = await stripe.paymentIntents.create({
        amount,
        currency: "usd",
        payment_method_types: ["card"],
      });

      res.send({ clientSecret: intent.client_secret });
    });

    app.post("/fundings", verifyToken, async (req, res) => {
      res.send(await fundingCollection.insertOne(req.body));
    });

    /* ======================
       IMAGE UPLOAD
    ====================== */
    app.post("/upload-image", verifyToken, async (req, res) => {
      const formData = new FormData();
      formData.append("image", req.body.image);

      const response = await axios.post(
        `https://api.imgbb.com/1/upload?key=${process.env.IMGBB_API_KEY}`,
        formData,
        { headers: formData.getHeaders() }
      );

      res.send({ imageUrl: response.data.data.url });
    });

    /* ======================
       ADMIN STATS
    ====================== */
    app.get("/admin-stats", verifyToken, verifyAdmin, async (req, res) => {
      const users = await userCollection.countDocuments();
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

    console.log("✅ MongoDB connected");
  } catch (err) {
    console.error(err);
  }
}

run();

app.get("/", (req, res) => {
  res.send("Blood Donation Server is running");
});

app.listen(port, () => {
  console.log(`🚀 Server running on port ${port}`);
});
