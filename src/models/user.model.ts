import {Schema, model} from 'mongoose';
import { lowercase } from 'zod';

const userSchema = new Schema({
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true,
    },

    password: {
        type: String,
        required: true
    },

    role: {
        type: String,
        enum: ['user', 'admin'],
        default: 'user'
    },

    isEmailVerified: {
        type: Boolean,
        default: false
    },

    name: {
        type: String
    },

    twoFactorEnabled: {
        type: Boolean,
        default: false
    },

    twoFactorSecret: {
        type: String,
        default: undefined
    },

    tokenVersion: {
        type: Number,
        default: 0
    },

    resetPasswordToken: {
        type: String,
        default: undefined
    },

    resetPasswordExpires: {
        type: Date,
        default: undefined
    }
}, {
    timestamps: true
})

export const User = model('User', userSchema);