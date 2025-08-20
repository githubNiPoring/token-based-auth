import supabase from "../src/db-config.js";
import jwt from "jsonwebtoken";

const authenticationMiddleware = async (req, res, next) => {
  try {
    const accessToken = req.cookies?.auth__accessToken;
    const refreshToken = req.cookies?.auth__refreshToken;

    // If no tokens at all, return unauthorized
    if (!accessToken && !refreshToken) {
      return res.status(401).json({
        name: "UnauthorizedError",
        message: "Unauthorized",
      });
    }

    // Try to verify access token first
    if (accessToken) {
      try {
        const decodedAccessToken = jwt.verify(
          accessToken,
          process.env.JWT_ACCESS_SECRET
        );

        req.session = {
          account_id: decodedAccessToken.id,
          email: decodedAccessToken.email,
        };

        // Access token is valid, proceed
        return next();
      } catch (accessTokenError) {
        // Access token invalid/expired, try refresh token
        console.log("Access token invalid, trying refresh token");
      }
    }

    // If we reach here, access token is invalid/missing, try refresh token
    if (!refreshToken) {
      return res.status(401).json({
        name: "UnauthorizedError",
        message: "No refresh token available",
      });
    }

    try {
      const decodedRefreshToken = jwt.verify(
        refreshToken,
        process.env.JWT_REFRESH_SECRET
      );

      // Verify refresh token exists in database
      const { data: sessionData, error: sessionError } = await supabase
        .from("session")
        .select("refresh_token")
        .eq("refresh_token", refreshToken)
        .single();

      if (sessionError || !sessionData) {
        return res.status(401).json({
          name: "UnauthorizedError",
          message: "Session not found or invalid",
        });
      }

      console.log(
        "Refreshing tokens for user:",
        decodedRefreshToken.id,
        decodedRefreshToken.email
      );

      // Generate new tokens
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

      // Delete old refresh token and insert new one
      // Note: Fixed the syntax error here
      const { error: deleteError } = await supabase
        .from("session")
        .delete()
        .eq("refresh_token", refreshToken); // Delete by refresh_token, not id

      if (deleteError) {
        console.error("Error deleting old session:", deleteError);
        return res.status(500).json({
          name: "DatabaseError",
          message: "Failed to update session",
        });
      }

      const { error: insertError } = await supabase.from("session").insert([
        {
          id: decodedRefreshToken.id,
          refresh_token: newRefreshToken,
        },
      ]);

      if (insertError) {
        console.error("Error inserting new session:", insertError);
        return res.status(500).json({
          name: "DatabaseError",
          message: "Failed to create new session",
        });
      }

      // Set new cookies
      res.cookie("auth__accessToken", newAccessToken, {
        path: "/",
        sameSite: "strict",
        secure: process.env.NODE_ENV === "production",
        httpOnly: true,
        maxAge: 20 * 1000, // 20 seconds
      });

      res.cookie("auth__refreshToken", newRefreshToken, {
        path: "/",
        sameSite: "strict",
        secure: process.env.NODE_ENV === "production",
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000, // 1 day
      });

      // Set session data
      req.session = {
        account_id: decodedRefreshToken.id,
        email: decodedRefreshToken.email,
      };

      // Proceed to next middleware
      return next();
    } catch (refreshTokenError) {
      console.error("Refresh token error:", refreshTokenError);
      return res.status(401).json({
        name: "UnauthorizedError",
        message: "Invalid refresh token",
      });
    }
  } catch (error) {
    console.error("Authentication middleware error:", error);
    return res.status(500).json({
      name: "InternalServerError",
      message: "Authentication error",
    });
  }
};

export default authenticationMiddleware;
