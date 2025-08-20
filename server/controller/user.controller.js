import supabase from "../src/db-config.js";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

const token = async (req, res) => {
  const user = {
    id: 1,
    email: "test@test.com",
  };

  const accessToken = jwt.sign(
    { ...user, iss: "login", aud: "vhel.app" },
    process.env.JWT_ACCESS_SECRET,
    {
      expiresIn: "20s",
    }
  );

  const refreshToken = jwt.sign(
    { ...user, iss: "login", aud: "vhel.app" },
    process.env.JWT_REFRESH_SECRET,
    {
      expiresIn: "1d",
    }
  );

  res.json({ accessToken, refreshToken });
};

const verifyToken = async (req, res) => {
  try {
    const token = req.header("Authorization")?.split(" ")[1];

    const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET);

    res.json({ decoded });
  } catch (error) {
    return res.status(401).json({
      name: error.name,
      message: error.message,
    });
  }
};

const refreshToken = async (req, res) => {
  try {
    const refreshToken = req.header("Authorization")?.split(" ")[1];

    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);

    const user = {
      id: decoded.id,
      email: decoded.email,
    };

    const accessToken = jwt.sign(
      { ...user, iss: "refresh", aud: "vhel.app" },
      process.env.JWT_ACCESS_SECRET,
      {
        expiresIn: "20s",
      }
    );

    const newRefreshToken = jwt.sign(
      {
        id: decoded.id,
        email: decoded.email,
      },
      process.env.JWT_REFRESH_SECRET,
      {
        expiresIn: "1d",
      }
    );

    res.json({ accessToken, refreshToken: newRefreshToken });
  } catch (error) {
    return res.status(401).json({
      name: error.name,
      message: error.message,
    });
  }
};

const register = async (req, res) => {
  try {
    const { email, password, firstname, lastname } = req.body;

    let existingUser = await supabase
      .from("accounts")
      .select("id")
      .eq("email", email);

    if (existingUser.data.length > 0) {
      return res.status(400).json({
        message: "User already exists",
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const { data: userData, error: userError } = await supabase
      .from("accounts")
      .insert([{ email, password: hashedPassword, firstname, lastname }])
      .select();

    if (userError) {
      return res.status(500).json({
        message: "Failed to create user",
        error: userError.message,
      });
    }

    res.status(201).json({ userData });
  } catch (error) {
    res.status(400).json({ name: error.name, message: error.message });
  }
};

const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    const { data: userData, error: userError } = await supabase
      .from("accounts")
      .select("id, email, password")
      .eq("email", email);

    if (userError || !userData || userData.length === 0) {
      return res.status(400).json({
        message: "Account not found",
        error: userError?.message || "User not found",
      });
    }

    const comparePassword = await bcrypt.compare(
      password,
      userData[0].password
    );

    if (!comparePassword) {
      return res.status(400).json({
        message: "Invalid username or password",
      });
    }

    const accessToken = jwt.sign(
      {
        id: userData[0].id,
        email: userData[0].email,
      },
      process.env.JWT_ACCESS_SECRET,
      { expiresIn: "20s" }
    );

    const refreshToken = jwt.sign(
      {
        id: userData[0].id,
        email: userData[0].email,
      },
      process.env.JWT_REFRESH_SECRET,
      { expiresIn: "1d" }
    );

    if (userData[0].id >= 1) {
      await supabase.from("session").delete().eq("id", userData[0].id);
    }

    await supabase
      .from("session")
      .insert([{ id: userData[0].id, refresh_token: refreshToken }])
      .select();

    res.cookie("auth__accessToken", accessToken, {
      path: "/",
      sameSite: "strict",
      secure: process.env.NODE_ENV === "production", // Only secure in production
      httpOnly: true,
      maxAge: 20 * 1000, // 20 seconds (matches JWT expiration)
    });

    res.cookie("auth__refreshToken", refreshToken, {
      path: "/",
      sameSite: "strict",
      secure: process.env.NODE_ENV === "production",
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000, // 1 day (matches JWT expiration)
    });

    res.status(200).json({ accessToken, refreshToken });
  } catch (error) {
    res.status(400).json({ name: error.name, message: error.message });
  }
};

const test = async (req, res) => {
  try {
    const session = req.session;

    const { data: accountData } = supabase
      .from("accounts")
      .select("*")
      .eq("id", session.account_id)
      .select();

    res.status(200).json(session);
  } catch (error) {
    res.status(400).json({ name: error.name, message: error.message });
  }
};

export default { token, verifyToken, refreshToken, register, login, test };
