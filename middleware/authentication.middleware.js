import supabase from "../src/db-config.js";
import jwt from "jsonwebtoken";

const authenticationMiddleware = async (req, res, next) => {
  try {
    const accessToken = req.cookies?.auth__accessToken;
    const refreshToken = req.cookies?.auth__refreshToken;

    if (!accessToken && !refreshToken) {
      return res.status(401).json({
        name: "UnauthorizedError",
        message: "Unauthorized",
      });
    }

    try {
      const decodedAccessToken = jwt.verify(
        accessToken,
        process.env.JWT_ACCESS_SECRET
      );

      req.session = {
        account_id: decodedAccessToken.id,
        email: decodedAccessToken.email,
      };
    } catch {
      try {
        const decodedRefreshToken = jwt.verify(
          refreshToken,
          process.env.JWT_REFRESH_SECRET
        );

        const { data: sessionData } = await supabase
          .from("session")
          .select("refresh_token")
          .eq("refresh_token", refreshToken)
          .single();

        if (!sessionData || !decodedRefreshToken) {
          return res.status(401).json({
            name: "UnauthorizedError",
            message: "Session not found",
          });
        }

        console.log(decodedRefreshToken.id, decodedRefreshToken.email);

        const newAccessToken = jwt.sign(
          {
            id: decodedRefreshToken.id,
            email: decodedRefreshToken.email,
          },
          process.env.JWT_ACCESS_SECRET,
          { expiresIn: "20s" }
        );
        const newRefreshToken = jwt.sign(
          {
            id: decodedRefreshToken.id,
            email: decodedRefreshToken.email,
          },
          process.env.JWT_REFRESH_SECRET,
          { expiresIn: "1d" }
        );

        await supabase.from("session").delete.eq("id", decodedRefreshToken.id);
        await supabase
          .from("session")
          .insert([
            { id: decodedRefreshToken.id, refresh_token: newRefreshToken },
          ])
          .select();

        res.cookie("auth__accessToken", newAccessToken, {
          path: "/",
          sameSite: "strict",
          secure: process.env.NODE_ENV === "production", // Only secure in production
          httpOnly: true,
          maxAge: 20 * 1000, // 20 seconds (matches JWT expiration)
        });

        res.cookie("auth__refreshToken", newRefreshToken, {
          path: "/",
          sameSite: "strict",
          secure: process.env.NODE_ENV === "production",
          httpOnly: true,
          maxAge: 24 * 60 * 60 * 1000, // 1 day (matches JWT expiration)
        });

        req.session = {
          account_id: decodedRefreshToken.id,
          email: decodedRefreshToken.email,
        };
      } catch {
        res.status(401).json({ message: "Invalid Refresh Token" });
      }
    }
  } catch (error) {
    res.status(401).json({ name: error.name, message: error.message });
  }

  await next();
};

export default authenticationMiddleware;
