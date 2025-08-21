import express from "express";
import bcrypt from "bcrypt";
import { body, validationResult } from "express-validator";
import User from "../models/User.js";

const router = express.Router();

const populateOptions = [
    { path: "bandMembers", select: "userName firstName lastName profileImage" },
    { path: "bands", select: "userName profileImage" },
];

const cleanUser = (user) => {
    if (!user) return null;
    const obj = user.toObject();
    obj.bandMembers = (obj.bandMembers || []).filter(Boolean);
    obj.bands = (obj.bands || []).filter(Boolean);
    return obj;
};

// --- Middleware helpers ---
const handleValidation = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    next();
};

const asyncHandler = (fn) => (req, res, next) =>
    Promise.resolve(fn(req, res, next)).catch(next);

// --- Validation rules ---
const userValidation = [
    body("userName").notEmpty().withMessage("Username required"),
    body("email").isEmail().withMessage("Valid email required").normalizeEmail(),
    body("password")
        .isLength({ min: 8 })
        .withMessage("Password must be at least 8 characters long"),
];

// --- Routes ---

// Get all users (with optional search)
router.get(
    "/",
    asyncHandler(async (req, res) => {
        const search = req.query.search || "";
        const query = search ? { userName: { $regex: search, $options: "i" } } : {};

        const users = await User.find(query)
            .populate(populateOptions)
            .select("-password");

        res.json(users.map(cleanUser));
    })
);

// Check if email is available
router.post(
    "/check-details",
    [
        body("email").isEmail().withMessage("Invalid email").normalizeEmail(),
        body("firstName").trim().notEmpty().withMessage("First name required"),
        body("lastName").trim().notEmpty().withMessage("Last name required"),
        body("password")
            .isLength({ min: 8 })
            .withMessage("Password must be at least 8 characters long"),
    ],
    handleValidation,
    asyncHandler(async (req, res) => {
        const { email } = req.body;
        const user = await User.findOne({ email });
        if (user) {
            return res.status(409).json({
                errors: [{ msg: "Email already in use", param: "email" }],
            });
        }
        res.json({ available: true });
    })
);

// Get user by username
router.get(
    "/username/:userName",
    asyncHandler(async (req, res) => {
        const user = await User.findOne({ userName: req.params.userName })
            .populate(populateOptions)
            .select("-password");
        if (!user) return res.status(404).json({ error: "User not found" });
        res.json(cleanUser(user));
    })
);

// Get single user by ID
router.get(
    "/:id",
    asyncHandler(async (req, res) => {
        const user = await User.findById(req.params.id)
            .populate(populateOptions)
            .select("-password");
        if (!user) return res.status(404).json({ error: "User not found" });
        res.json(cleanUser(user));
    })
);

// Create user
router.post(
    "/",
    userValidation,
    handleValidation,
    asyncHandler(async (req, res) => {
        const { userName, email, password, ...rest } = req.body;

        const existing = await User.findOne({ $or: [{ email }, { userName }] });
        if (existing)
            return res.status(400).json({ error: "Email or username already taken" });

        const hashedPassword = await bcrypt.hash(password, 10);

        const user = new User({
            userName,
            email,
            password: hashedPassword,
            ...rest,
        });

        const savedUser = await user.save();
        await savedUser.populate(populateOptions);

        res.status(201).json(cleanUser(savedUser));
    })
);

// Update user (restricted fields)
router.patch(
    "/:id",
    asyncHandler(async (req, res) => {
        const allowed = ["firstName", "lastName", "profileImage", "bandMembers", "bands"];
        const updateData = {};
        for (const key of allowed) {
            if (req.body[key] !== undefined) updateData[key] = req.body[key];
        }

        const updated = await User.findByIdAndUpdate(req.params.id, updateData, {
            new: true,
        })
            .populate(populateOptions)
            .select("-password");

        if (!updated) return res.status(404).json({ error: "User not found" });
        res.json(cleanUser(updated));
    })
);

// Delete user
router.delete(
    "/:id",
    asyncHandler(async (req, res) => {
        const deleted = await User.findByIdAndDelete(req.params.id);
        if (!deleted) return res.status(404).json({ error: "User not found" });
        res.json({ message: "User deleted" });
    })
);

// Band member management
router.post(
    "/:id/bandMembers",
    asyncHandler(async (req, res) => {
        const { memberId } = req.body;

        // Ensure member exists
        const member = await User.findById(memberId);
        if (!member) return res.status(404).json({ error: "Member not found" });

        const updated = await User.findByIdAndUpdate(
            req.params.id,
            { $addToSet: { bandMembers: memberId } },
            { new: true }
        )
            .populate(populateOptions)
            .select("-password");

        if (!updated) return res.status(404).json({ error: "User not found" });
        res.json(cleanUser(updated));
    })
);

router.delete(
    "/:id/bandMembers/:memberId",
    asyncHandler(async (req, res) => {
        const updated = await User.findByIdAndUpdate(
            req.params.id,
            { $pull: { bandMembers: req.params.memberId } },
            { new: true }
        )
            .populate(populateOptions)
            .select("-password");

        if (!updated) return res.status(404).json({ error: "User not found" });
        res.json(cleanUser(updated));
    })
);

// --- Central error handler ---
router.use((err, req, res, next) => {
    console.error(err.stack || err);
    res.status(500).json({ error: "Server error" });
});

export default router;
