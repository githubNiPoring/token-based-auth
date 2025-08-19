import dotenv from "dotenv";
dotenv.config();
import express from "express";
import supabase from "./db-config.js";
import cookieParser from "cookie-parser";

import userRoutes from "../routes/user.routes.js";

const app = express();
const port = process.env.PORT;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.use("/api/v1", userRoutes);

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
