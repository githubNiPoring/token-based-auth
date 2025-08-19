import { Router } from "express";
import userController from "../controller/user.controller.js";
import authenticationMiddleware from "../middleware/authentication.middleware.js";

const router = Router();

router.get("/token", userController.token);
router.get("/verify-token", userController.verifyToken);
router.get("/refresh-token", userController.refreshToken);
router.post("/register", userController.register);
router.post("/login", userController.login);
router.get("/test", authenticationMiddleware, userController.test);

export default router;
