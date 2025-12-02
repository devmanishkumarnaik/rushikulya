const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const dotenv = require('dotenv');
const multer = require('multer');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cloudinary = require('cloudinary').v2;
const nodemailer = require('nodemailer');
const { Server } = require('socket.io');
const http = require('http');

dotenv.config();

const app = express();
const server = http.createServer(app);

// Configure Cloudinary
const requiredCloudinaryVars = ['CLOUDINARY_CLOUD_NAME', 'CLOUDINARY_API_KEY', 'CLOUDINARY_API_SECRET'];
const missingCloudinaryVars = requiredCloudinaryVars.filter(varName => !process.env[varName]);

if (missingCloudinaryVars.length > 0) {
  // Cloudinary configuration incomplete
}

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// Configure Nodemailer (using Gmail)
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER || 'udiyamanmatrukhetra1973@gmail.com',
    pass: process.env.EMAIL_PASS // App password from Gmail
  }
});

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB Connection
const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/school-website');
    console.log('MongoDB Connected...');
  } catch (err) {
    process.exit(1);
  }
};

connectDB();

// Contact Schema
const contactSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true },
  phone: String,
  message: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const Contact = mongoose.model('Contact', contactSchema);

// User Schema
const userSchema = new mongoose.Schema({
  userType: { type: String, required: true, enum: ['teacher', 'student', 'member'] },
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  email: { type: String },
  phone: { type: String },
  password: { type: String },
  rollNumber: { type: String },
  class: { type: String },
  fatherName: { type: String },
  motherName: { type: String },
  parentsMobile: { type: String },
  photo: { type: String },
  isActivated: { type: Boolean, default: false },
  isExamEligible: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// Admin Schema
const adminSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  email: { type: String },
  role: { type: String, default: 'admin' },
  createdAt: { type: Date, default: Date.now }
});

const Admin = mongoose.model('Admin', adminSchema);

// Notification Schema
const notificationSchema = new mongoose.Schema({
  message: { type: String, required: true },
  createdBy: { type: String, default: 'Admin' },
  createdAt: { type: Date, default: Date.now },
  isActive: { type: Boolean, default: true }
});

const Notification = mongoose.model('Notification', notificationSchema);

// Quiz Schema
const quizQuestionSchema = new mongoose.Schema({
  question: { type: String, required: true },
  option1: { type: String, required: true },
  option2: { type: String, required: true },
  option3: { type: String, required: true },
  option4: { type: String, required: true },
  correctOption: { type: Number, required: true, min: 1, max: 4 },
  createdAt: { type: Date, default: Date.now }
});

const QuizQuestion = mongoose.model('QuizQuestion', quizQuestionSchema);

// Quiz Result Schema
const quizResultSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  userName: { type: String, required: true },
  score: { type: Number, required: true },
  totalQuestions: { type: Number, required: true },
  percentage: { type: Number, required: true },
  passed: { type: Boolean, required: true },
  isSuspended: { type: Boolean, default: false },
  suspendedReason: { type: String },
  answers: [{
    questionId: mongoose.Schema.Types.ObjectId,
    selectedOption: Number,
    isCorrect: Boolean
  }],
  completedAt: { type: Date, default: Date.now }
});

const QuizResult = mongoose.model('QuizResult', quizResultSchema);

// Exam Session Schema (for live timed exams)
const examSessionSchema = new mongoose.Schema({
  startedBy: { type: String, default: 'Admin' },
  startTime: { type: Date, required: true },
  endTime: { type: Date, required: true },
  duration: { type: Number, required: true }, // in seconds (3600 for 1 hour)
  isActive: { type: Boolean, default: true },
  participantsCount: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
});

const ExamSession = mongoose.model('ExamSession', examSessionSchema);

// Exam Result Schema (for admin-managed results)
const examResultSchema = new mongoose.Schema({
  studentId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  studentName: { type: String, required: true },
  rollNumber: { type: String, required: true },
  class: { type: String, required: true },
  testType: { type: String, default: '' },
  subjects: [{
    name: { type: String, required: true },
    marks: { type: Number, required: true },
    maxMarks: { type: Number, required: true }
  }],
  totalMarks: { type: Number, required: true },
  obtainedMarks: { type: Number, required: true },
  percentage: { type: Number, required: true },
  isPublished: { type: Boolean, default: false },
  examDate: { type: Date, default: Date.now },
  createdAt: { type: Date, default: Date.now }
});

const ExamResult = mongoose.model('ExamResult', examResultSchema);

// Video Schema (for study materials)
const videoSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String },
  videoUrl: { type: String, required: true },
  videoId: { type: String },
  videoType: { type: String, enum: ['youtube', 'drive'], default: 'youtube' },
  category: { type: String, default: 'General' },
  createdAt: { type: Date, default: Date.now }
});

const Video = mongoose.model('Video', videoSchema);

// Note Schema (for study materials PDF)
const noteSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String },
  pdfUrl: { type: String, required: true },
  publicId: { type: String, default: '' },
  category: { type: String, default: 'General' },
  fileSize: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
});

const Note = mongoose.model('Note', noteSchema);

// Gallery Media Schema (for public gallery)
const galleryMediaSchema = new mongoose.Schema({
  type: { type: String, required: true, enum: ['image', 'video', 'audio'] },
  title: { type: String, required: true },
  description: { type: String },
  url: { type: String, required: true },
  thumbnail: { type: String }, // For videos
  publicId: { type: String }, // For Cloudinary
  createdAt: { type: Date, default: Date.now }
});

const GalleryMedia = mongoose.model('GalleryMedia', galleryMediaSchema);

// Message Schema (for student/teacher messages to admin)
const messageSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  userName: { type: String, required: true },
  userType: { type: String, required: true, enum: ['teacher', 'student', 'member'] },
  subject: { type: String, required: true },
  message: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const Message = mongoose.model('Message', messageSchema);

// Notice Schema (for admin to publish notices with attachments)
const noticeSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String },
  fileType: { type: String, required: true, enum: ['pdf', 'image', 'text'] },
  fileUrl: { type: String, required: true },
  fileName: { type: String },
  publicId: { type: String },
  createdBy: { type: String, default: 'Admin' },
  createdAt: { type: Date, default: Date.now },
  isActive: { type: Boolean, default: true }
});

const Notice = mongoose.model('Notice', noticeSchema);

// Subject Schema (for attendance)
const subjectSchema = new mongoose.Schema({
  name: { type: String, required: true },
  class: { type: String, required: true },
  createdBy: { type: String, default: 'Admin' },
  createdAt: { type: Date, default: Date.now }
});

const Subject = mongoose.model('Subject', subjectSchema);

// Attendance Schema
const attendanceSchema = new mongoose.Schema({
  studentId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  studentName: { type: String, required: true },
  rollNumber: { type: String, required: true },
  class: { type: String, required: true },
  date: { type: Date, required: true },
  status: { type: String, enum: ['present', 'absent'], required: true },
  markedBy: { type: String, required: true }, // Teacher or Admin name
  markedByUserId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  createdAt: { type: Date, default: Date.now }
});

// Create compound index to prevent duplicate attendance for same student and date (only one attendance per day)
attendanceSchema.index({ studentId: 1, date: 1 }, { unique: true });

const Attendance = mongoose.model('Attendance', attendanceSchema);

// Teacher Attendance Schema
const teacherAttendanceSchema = new mongoose.Schema({
  teacherId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  teacherName: { type: String, required: true },
  date: { type: Date, required: true },
  status: { type: String, enum: ['present', 'absent'], required: true },
  markedBy: { type: String, required: true }, // Admin name
  markedByUserId: { type: mongoose.Schema.Types.ObjectId },
  createdAt: { type: Date, default: Date.now }
});

// Create compound index to prevent duplicate attendance for same teacher and date
teacherAttendanceSchema.index({ teacherId: 1, date: 1 }, { unique: true });

const TeacherAttendance = mongoose.model('TeacherAttendance', teacherAttendanceSchema);

// Fees Schema
const feesSchema = new mongoose.Schema({
  studentId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  studentName: { type: String, required: true },
  rollNumber: { type: String, required: true },
  class: { type: String, required: true },
  totalFees: { type: Number, required: true, default: 0 },
  deposit: { type: Number, required: true, default: 0 },
  dues: { type: Number, required: true, default: 0 },
  transactions: [{
    amount: { type: Number, required: true },
    type: { type: String, enum: ['deposit', 'fee_set'], required: true },
    description: { type: String, default: '' },
    date: { type: Date, default: Date.now }
  }],
  lastUpdatedBy: { type: String, default: 'Admin' },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const Fees = mongoose.model('Fees', feesSchema);

// Progress Card Schema
const progressCardSchema = new mongoose.Schema({
  year: { type: String, required: true },
  studentId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  studentName: { type: String, required: true },
  rollNumber: { type: String, required: true },
  class: { type: String, required: true },
  aadhaarNumber: { type: String, required: true },
  fatherName: { type: String },
  motherName: { type: String },
  subjects: [{
    name: { type: String, required: true },
    test1FM: { type: Number, required: true },
    test1Marks: { type: Number, required: true },
    test2FM: { type: Number, required: true },
    test2Marks: { type: Number, required: true },
    halfYearlyFM: { type: Number, required: true },
    halfYearlyMarks: { type: Number, required: true },
    test3FM: { type: Number, required: true },
    test3Marks: { type: Number, required: true },
    annualFM: { type: Number, required: true },
    annualMarks: { type: Number, required: true },
    totalMarks: { type: Number, required: true },
    obtainedMarks: { type: Number, required: true },
    remarks: { type: String, default: '' }
  }],
  totalMarks: { type: Number, required: true },
  obtainedMarks: { type: Number, required: true },
  percentage: { type: Number, required: true },
  grade: { type: String, required: true },
  remarks: { type: String },
  promotionStatus: { type: String, enum: ['Promoted', 'Not Promoted'], required: true },
  halfYearlyWorkingDays: { type: Number, default: 0 },
  halfYearlyDaysPresent: { type: Number, default: 0 },
  annualWorkingDays: { type: Number, default: 0 },
  annualDaysPresent: { type: Number, default: 0 },
  isPublished: { type: Boolean, default: false },
  createdBy: { type: String, default: 'Admin' },
  createdAt: { type: Date, default: Date.now }
});

const ProgressCard = mongoose.model('ProgressCard', progressCardSchema);

// Auth Middleware
const authMiddleware = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
    req.userId = decoded.userId;
    req.userType = decoded.userType;
    next();
  } catch (error) {
    res.status(401).json({ message: 'Invalid token' });
  }
};

// Multer configuration for memory storage
const storage = multer.memoryStorage();

const upload = multer({
  storage: storage,
  limits: { fileSize: 2 * 1024 * 1024 }, // 2MB limit for gallery images
  fileFilter: function (req, file, cb) {
    const filetypes = /jpeg|jpg|png|webp/;
    const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = filetypes.test(file.mimetype);
    if (mimetype && extname) {
      return cb(null, true);
    }
    cb(new Error('Only image files (JPEG, JPG, PNG, WEBP) are allowed'));
  }
});

// Multer configuration for PDF uploads
const uploadPdf = multer({
  storage: storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
  fileFilter: function (req, file, cb) {
    if (file.mimetype === 'application/pdf') {
      return cb(null, true);
    }
    cb(new Error('Only PDF files are allowed'));
  }
});

// Routes
// Contact form - Send email directly
app.post('/api/contact', async (req, res) => {
  try {
    const { name, email, phone, message } = req.body;
    
    // Send email to admin
    const mailOptions = {
      from: process.env.EMAIL_USER || 'udiyamanmatrukhetra1973@gmail.com',
      to: 'udiyamanmatrukhetra1973@gmail.com',
      subject: `Contact Form Message from ${name}`,
      html: `
        <h2>New Contact Form Submission</h2>
        <p><strong>Name:</strong> ${name}</p>
        <p><strong>Email:</strong> ${email}</p>
        <p><strong>Phone:</strong> ${phone || 'Not provided'}</p>
        <p><strong>Message:</strong></p>
        <p>${message}</p>
      `
    };

    await transporter.sendMail(mailOptions);
    res.status(200).json({ message: 'Message sent successfully! We will contact you soon.' });
  } catch (error) {
    res.status(500).json({ message: 'Error sending message. Please try again later.', error: error.message });
  }
});

// Get messages from students/teachers (for admin)
app.get('/api/messages', async (req, res) => {
  try {
    const messages = await Message.find().sort({ createdAt: -1 });
    res.json(messages);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching messages', error: error.message });
  }
});

// Send message from student/teacher to admin
app.post('/api/messages', authMiddleware, async (req, res) => {
  try {
    const { subject, message } = req.body;
    const user = await User.findById(req.userId);
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const newMessage = new Message({
      userId: user._id,
      userName: `${user.firstName} ${user.lastName}`,
      userType: user.userType,
      subject,
      message
    });
    
    await newMessage.save();
    
    // Emit real-time update to admins
    if (typeof global.emitAdminUpdate === 'function') {
      global.emitAdminUpdate('new-message', newMessage);
    }
    
    res.status(201).json({ message: 'Message sent successfully!', data: newMessage });
  } catch (error) {
    res.status(500).json({ message: 'Error sending message', error: error.message });
  }
});

// Delete message (for admin)
app.delete('/api/messages/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const deletedMessage = await Message.findByIdAndDelete(id);
    
    if (!deletedMessage) {
      return res.status(404).json({ message: 'Message not found' });
    }

    // Emit real-time update to admins
    if (typeof global.emitAdminUpdate === 'function') {
      global.emitAdminUpdate('message-deleted', { messageId: id });
    }

    res.json({ message: 'Message deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error deleting message', error: error.message });
  }
});

// Register Route
app.post('/api/register', upload.single('photo'), async (req, res) => {
  try {
    const { userType, firstName, lastName, email, phone, password, rollNumber, class: studentClass } = req.body;
    
    if (!req.file) {
      return res.status(400).json({ message: 'Photo is required' });
    }

    // Check if Cloudinary is properly configured
    const isCloudinaryConfigured = process.env.CLOUDINARY_CLOUD_NAME && 
                                 process.env.CLOUDINARY_API_KEY && 
                                 process.env.CLOUDINARY_API_SECRET;
    
    if (!isCloudinaryConfigured) {
      // For development, we can use a placeholder URL
      const userData = {
        userType,
        firstName,
        lastName,
        photo: '/images/default-profile.png' // Placeholder image
      };

      if (userType === 'teacher' || userType === 'member') {
        // Check if email already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
          return res.status(400).json({ message: 'Email already registered' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        userData.email = email;
        if (phone) userData.phone = phone; // Phone is optional for members
        userData.password = hashedPassword;
      } else {
        // Student registration with email and password
        // Check if email already exists
        if (email) {
          const existingEmail = await User.findOne({ email });
          if (existingEmail) {
            return res.status(400).json({ message: 'Email already registered' });
          }
        }
        
        const hashedPassword = await bcrypt.hash(password, 10);
        userData.rollNumber = rollNumber;
        userData.class = studentClass;
        userData.fatherName = req.body.fatherName;
        userData.motherName = req.body.motherName;
        userData.parentsMobile = req.body.parentsMobile;
        userData.email = email;
        userData.password = hashedPassword;
      }

      const newUser = new User(userData);
      await newUser.save();

      return res.status(201).json({ message: 'Registration successful!', data: newUser });
    }
    const uploadStream = cloudinary.uploader.upload_stream(
      {
        folder: 'school-registrations',
        resource_type: 'image'
      },
      async (error, result) => {
        if (error) {
          return res.status(500).json({ message: 'Photo upload failed', error: error.message });
        }

        try {
          let userData = {
            userType,
            firstName,
            lastName,
            photo: result.secure_url
          };

          if (userType === 'teacher' || userType === 'member') {
            // Check if email already exists
            const existingUser = await User.findOne({ email });
            if (existingUser) {
              return res.status(400).json({ message: 'Email already registered' });
            }

            const hashedPassword = await bcrypt.hash(password, 10);
            userData = {
              ...userData,
              email,
              password: hashedPassword
            };
            if (phone) userData.phone = phone; // Phone is optional for members
          } else {
            // Student registration with email and password
            // Check if email already exists
            if (email) {
              const existingEmail = await User.findOne({ email });
              if (existingEmail) {
                return res.status(400).json({ message: 'Email already registered' });
              }
            }
            
            const hashedPassword = await bcrypt.hash(password, 10);
            userData = {
              ...userData,
              rollNumber,
              class: studentClass,
              fatherName: req.body.fatherName,
              motherName: req.body.motherName,
              parentsMobile: req.body.parentsMobile,
              email: email,
              password: hashedPassword
            };
          }

          const newUser = new User(userData);
          await newUser.save();

          // Emit real-time update to admin
          if (typeof global.broadcastUpdate === 'function') {
            global.broadcastUpdate('new-user-registered', { user: newUser });
          }

          res.status(201).json({ message: 'Registration successful!', data: newUser });
        } catch (dbError) {
          res.status(500).json({ message: 'Registration failed', error: dbError.message });
        }
      }
    );

    // Convert buffer to stream and pipe to Cloudinary
    const bufferStream = require('stream').Readable.from(req.file.buffer);
    bufferStream.pipe(uploadStream);
  } catch (error) {
    res.status(500).json({ message: 'Registration failed', error: error.message });
  }
});

// Login Route
app.post('/api/login', async (req, res) => {
  try {
    const { identifier, password } = req.body;

    // Find user by email (teacher, student, and member)
    const user = await User.findOne({
      email: identifier
    });

    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Set token expiration to 2 years for teachers and students
    const token = jwt.sign(
      { userId: user._id, userType: user.userType },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '730d' } // 2 years for better user experience
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        userType: user.userType,
        isActivated: user.isActivated
      }
    });
  } catch (error) {
    res.status(500).json({ message: 'Login failed', error: error.message });
  }
});

// Admin Login Route
app.post('/api/admin/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Find admin by username
    let admin = await Admin.findOne({ username });

    // If admin doesn't exist in database, check against .env credentials and create admin
    if (!admin) {
      const envUsername = process.env.ADMIN_USERNAME || 'sarita';
      const envPassword = process.env.ADMIN_PASSWORD || 'sarita10';

      if (username === envUsername && password === envPassword) {
        // Hash the password and create admin in database
        const hashedPassword = await bcrypt.hash(envPassword, 10);
        admin = new Admin({
          username: envUsername,
          password: hashedPassword,
          role: 'admin'
        });
        await admin.save();
      } else {
        return res.status(400).json({ message: 'Invalid credentials' });
      }
    } else {
      // Admin exists, verify password
      const isMatch = await bcrypt.compare(password, admin.password);
      if (!isMatch) {
        return res.status(400).json({ message: 'Invalid credentials' });
      }
    }

    // Set token expiration to 1 month for admin
    const token = jwt.sign(
      { userId: admin._id, userType: 'admin', username: admin.username },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '30d' } // 1 month for admin
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: admin._id,
        username: admin.username,
        userType: 'admin'
      }
    });
  } catch (error) {
    res.status(500).json({ message: 'Login failed', error: error.message });
  }
});

// Update Admin Password (protected route)
app.put('/api/admin/update-password', authMiddleware, async (req, res) => {
  try {
    // Verify user is admin
    if (req.userType !== 'admin') {
      return res.status(403).json({ message: 'Access denied' });
    }

    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ message: 'Current password and new password are required' });
    }

    const admin = await Admin.findById(req.userId);
    if (!admin) {
      return res.status(404).json({ message: 'Admin not found' });
    }

    // Verify current password
    const isMatch = await bcrypt.compare(currentPassword, admin.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Current password is incorrect' });
    }

    // Hash and update new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    admin.password = hashedPassword;
    await admin.save();

    res.json({ message: 'Password updated successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Failed to update password', error: error.message });
  }
});

// Get all users (for admin)
app.get('/api/users', async (req, res) => {
  try {
    const users = await User.find().select('-password').sort({ createdAt: -1 });
    res.json(users);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching users', error: error.message });
  }
});

// Update user (for admin)
app.put('/api/users/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { firstName, lastName, email, phone, rollNumber, class: studentClass, fatherName, motherName, parentsMobile } = req.body;

    const updateData = {
      firstName,
      lastName
    };

    // Add role-specific fields
    if (email) updateData.email = email;
    if (phone) updateData.phone = phone;
    if (rollNumber) updateData.rollNumber = rollNumber;
    if (studentClass) updateData.class = studentClass;
    if (fatherName) updateData.fatherName = fatherName;
    if (motherName) updateData.motherName = motherName;
    if (parentsMobile) updateData.parentsMobile = parentsMobile;

    const updatedUser = await User.findByIdAndUpdate(
      id,
      updateData,
      { new: true, runValidators: true }
    ).select('-password');

    if (!updatedUser) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json(updatedUser);
  } catch (error) {
    res.status(500).json({ message: 'Error updating user', error: error.message });
  }
});

// Update user photo (for admin)
app.put('/api/users/:id/photo', upload.single('photo'), async (req, res) => {
  try {
    const { id } = req.params;
    
    if (!req.file) {
      return res.status(400).json({ message: 'Photo is required' });
    }

    // Check if Cloudinary is properly configured
    const isCloudinaryConfigured = process.env.CLOUDINARY_CLOUD_NAME && 
                                 process.env.CLOUDINARY_API_KEY && 
                                 process.env.CLOUDINARY_API_SECRET;
    
    if (!isCloudinaryConfigured) {
      return res.status(500).json({ message: 'Cloudinary not configured' });
    }

    const uploadStream = cloudinary.uploader.upload_stream(
      {
        folder: 'school-registrations',
        resource_type: 'image'
      },
      async (error, result) => {
        if (error) {
          return res.status(500).json({ message: 'Photo upload failed', error: error.message });
        }

        try {
          const updatedUser = await User.findByIdAndUpdate(
            id,
            { photo: result.secure_url },
            { new: true, runValidators: true }
          ).select('-password');

          if (!updatedUser) {
            return res.status(404).json({ message: 'User not found' });
          }

          res.json({ message: 'Photo updated successfully', user: updatedUser });
        } catch (dbError) {
          res.status(500).json({ message: 'Failed to update user photo', error: dbError.message });
        }
      }
    );

    // Convert buffer to stream and pipe to Cloudinary
    const bufferStream = require('stream').Readable.from(req.file.buffer);
    bufferStream.pipe(uploadStream);
  } catch (error) {
    res.status(500).json({ message: 'Photo update failed', error: error.message });
  }
});

// Delete user (for admin)
app.delete('/api/users/:id', async (req, res) => {
  try {
    const { id } = req.params;
    
    const deletedUser = await User.findByIdAndDelete(id);
    
    if (!deletedUser) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Delete all associated data
    const deletionPromises = [];

    // 1. Delete quiz results for this user
    deletionPromises.push(QuizResult.deleteMany({ userId: id }));

    // 2. Delete messages sent by this user
    deletionPromises.push(Message.deleteMany({ userId: id }));

    // 3. Delete exam results for this student (if student)
    if (deletedUser.userType === 'student') {
      deletionPromises.push(ExamResult.deleteMany({ studentId: id }));
    }

    // 4. Delete attendance records for this student (if student)
    if (deletedUser.userType === 'student') {
      deletionPromises.push(Attendance.deleteMany({ studentId: id }));
    }

    // 5. Delete fees records for this student (if student)
    if (deletedUser.userType === 'student') {
      deletionPromises.push(Fees.deleteMany({ studentId: id }));
    }

    // Execute all deletions in parallel
    await Promise.all(deletionPromises);

    // Emit real-time update
    if (typeof global.broadcastUpdate === 'function') {
      global.broadcastUpdate('user-deleted', { userId: id });
    }

    res.json({ 
      message: 'User and all associated data deleted successfully', 
      user: deletedUser 
    });
  } catch (error) {
    res.status(500).json({ message: 'Error deleting user', error: error.message });
  }
});

// Toggle user activation (for admin)
app.put('/api/users/:id/activate', async (req, res) => {
  try {
    const { id } = req.params;
    const user = await User.findById(id).select('-password');
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    user.isActivated = !user.isActivated;
    await user.save();

    // Emit real-time update to all clients
    if (typeof global.emitRealTimeUpdate === 'function') {
      global.emitRealTimeUpdate('user-activation-updated', { 
        userId: user._id.toString(), 
        isActivated: user.isActivated,
        userName: `${user.firstName} ${user.lastName}`,
        userType: user.userType
      });
    }

    // Emit to specific user
    if (typeof global.emitUserUpdate === 'function') {
      global.emitUserUpdate(user._id.toString(), 'account-status-changed', {
        isActivated: user.isActivated,
        message: user.isActivated ? 'Your account has been activated!' : 'Your account has been deactivated.'
      });
    }

    res.json({ message: 'Activation status updated', user });
  } catch (error) {
    res.status(500).json({ message: 'Error updating activation', error: error.message });
  }
});

// Toggle exam eligibility (for admin - students and teachers)
app.put('/api/users/:id/exam-eligibility', async (req, res) => {
  try {
    const { id } = req.params;
    const user = await User.findById(id).select('-password');
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    user.isExamEligible = !user.isExamEligible;
    await user.save();

    // Emit real-time update to all clients
    if (typeof global.emitRealTimeUpdate === 'function') {
      global.emitRealTimeUpdate('user-exam-eligibility-updated', { 
        userId: user._id.toString(), 
        isExamEligible: user.isExamEligible,
        userName: `${user.firstName} ${user.lastName}`,
        userType: user.userType
      });
    }

    // Emit to specific user
    if (typeof global.emitUserUpdate === 'function') {
      global.emitUserUpdate(user._id.toString(), 'exam-eligibility-changed', {
        isExamEligible: user.isExamEligible,
        message: user.isExamEligible ? 'You are now eligible for exams!' : 'Your exam eligibility has been revoked.'
      });
    }

    res.json({ message: 'Exam eligibility status updated', user });
  } catch (error) {
    res.status(500).json({ message: 'Error updating exam eligibility', error: error.message });
  }
});

// Get user profile (protected)
app.get('/api/profile', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('-password');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json(user);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching profile', error: error.message });
  }
});

// Notification Routes
// Get all active notifications (for users)
app.get('/api/notifications', authMiddleware, async (req, res) => {
  try {
    const notifications = await Notification.find({ isActive: true }).sort({ createdAt: -1 });
    res.json(notifications);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching notifications', error: error.message });
  }
});

// Get all notifications including history (for admin)
app.get('/api/admin/notifications', async (req, res) => {
  try {
    const notifications = await Notification.find().sort({ createdAt: -1 });
    res.json(notifications);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching notifications', error: error.message });
  }
});

// Create notification (admin only)
app.post('/api/notifications', async (req, res) => {
  try {
    const { message } = req.body;
    const newNotification = new Notification({ message });
    await newNotification.save();
    
    // Emit real-time update to all connected clients
    if (typeof global.broadcastUpdate === 'function') {
      global.broadcastUpdate('new-notification', newNotification);
    }
    
    res.status(201).json({ message: 'Notification sent successfully!', data: newNotification });
  } catch (error) {
    res.status(500).json({ message: 'Error creating notification', error: error.message });
  }
});

// Update notification (admin only)
app.put('/api/notifications/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { message } = req.body;
    
    const updatedNotification = await Notification.findByIdAndUpdate(
      id,
      { message },
      { new: true, runValidators: true }
    );
    
    if (!updatedNotification) {
      return res.status(404).json({ message: 'Notification not found' });
    }
    
    // Emit real-time update to all connected clients
    if (typeof global.broadcastUpdate === 'function') {
      global.broadcastUpdate('notification-updated', updatedNotification);
    }
    
    res.json({ message: 'Notification updated successfully!', data: updatedNotification });
  } catch (error) {
    res.status(500).json({ message: 'Error updating notification', error: error.message });
  }
});

// Delete notification (admin only - permanently deletes)
app.delete('/api/notifications/:id', async (req, res) => {
  try {
    const { id } = req.params;
    
    // Permanently delete the notification
    const deletedNotification = await Notification.findByIdAndDelete(id);
    
    if (!deletedNotification) {
      return res.status(404).json({ message: 'Notification not found' });
    }
    
    // Emit real-time update to all connected clients
    if (typeof global.broadcastUpdate === 'function') {
      global.broadcastUpdate('notification-deleted', { notificationId: id });
    }
    
    res.json({ message: 'Notification deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error deleting notification', error: error.message });
  }
});

// Notice Routes
// Upload notice image to Cloudinary
app.post('/api/notices/upload-image', upload.single('image'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: 'No image file provided' });
    }

    // Check if Cloudinary is configured
    const isCloudinaryConfigured = process.env.CLOUDINARY_CLOUD_NAME && 
                                 process.env.CLOUDINARY_API_KEY && 
                                 process.env.CLOUDINARY_API_SECRET;
    
    if (!isCloudinaryConfigured) {
      return res.status(500).json({ message: 'Cloudinary not configured' });
    }

    const uploadStream = cloudinary.uploader.upload_stream(
      {
        folder: 'notices/images',
        resource_type: 'image',
        transformation: [
          { width: 1200, height: 1200, crop: 'limit' },
          { quality: 'auto' }
        ]
      },
      (error, result) => {
        if (error) {
          console.error('Cloudinary upload error:', error);
          return res.status(500).json({ message: 'Image upload failed', error: error.message });
        }

        res.json({
          message: 'Image uploaded successfully',
          data: {
            url: result.secure_url,
            publicId: result.public_id
          }
        });
      }
    );

    // Convert buffer to stream and pipe to Cloudinary
    const bufferStream = require('stream').Readable.from(req.file.buffer);
    bufferStream.pipe(uploadStream);
  } catch (error) {
    console.error('Image upload error:', error);
    res.status(500).json({ message: 'Image upload failed', error: error.message });
  }
});

// Get all active notices (for users)
app.get('/api/notices', async (req, res) => {
  try {
    const notices = await Notice.find({ isActive: true }).sort({ createdAt: -1 });
    res.json(notices);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching notices', error: error.message });
  }
});

// Get all notices including inactive (for admin)
app.get('/api/admin/notices', async (req, res) => {
  try {
    const notices = await Notice.find().sort({ createdAt: -1 });
    res.json(notices);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching notices', error: error.message });
  }
});

// Create notice (admin only)
app.post('/api/notices', async (req, res) => {
  try {
    const { title, description, fileType, fileUrl, fileName } = req.body;
    
    if (!title || !fileType) {
      return res.status(400).json({ message: 'Title and file type are required' });
    }

    // For PDF and Image, fileUrl is required
    if ((fileType === 'pdf' || fileType === 'image') && !fileUrl) {
      return res.status(400).json({ message: 'File URL is required for PDF and Image notices' });
    }

    // For Text, description is required
    if (fileType === 'text' && !description) {
      return res.status(400).json({ message: 'Text content is required for Text notices' });
    }

    const newNotice = new Notice({
      title,
      description,
      fileType,
      fileUrl: fileUrl || 'text-notice', // Use placeholder for text notices
      fileName
    });
    
    await newNotice.save();
    
    // Emit real-time update to all connected clients
    if (typeof global.broadcastUpdate === 'function') {
      global.broadcastUpdate('new-notice', newNotice);
    }
    
    res.status(201).json({ message: 'Notice created successfully!', data: newNotice });
  } catch (error) {
    res.status(500).json({ message: 'Error creating notice', error: error.message });
  }
});

// Update notice (admin only)
app.put('/api/notices/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { title, description, fileType, fileUrl, fileName, isActive } = req.body;
    
    const updateData = {};
    if (title !== undefined) updateData.title = title;
    if (description !== undefined) updateData.description = description;
    if (fileType !== undefined) updateData.fileType = fileType;
    if (fileUrl !== undefined) updateData.fileUrl = fileUrl;
    if (fileName !== undefined) updateData.fileName = fileName;
    if (isActive !== undefined) updateData.isActive = isActive;
    
    const updatedNotice = await Notice.findByIdAndUpdate(
      id,
      updateData,
      { new: true, runValidators: true }
    );
    
    if (!updatedNotice) {
      return res.status(404).json({ message: 'Notice not found' });
    }
    
    // Emit real-time update to all connected clients
    if (typeof global.broadcastUpdate === 'function') {
      global.broadcastUpdate('notice-updated', updatedNotice);
    }
    
    res.json({ message: 'Notice updated successfully!', data: updatedNotice });
  } catch (error) {
    res.status(500).json({ message: 'Error updating notice', error: error.message });
  }
});

// Delete notice (admin only)
app.delete('/api/notices/:id', async (req, res) => {
  try {
    const { id } = req.params;
    
    const deletedNotice = await Notice.findByIdAndDelete(id);
    
    if (!deletedNotice) {
      return res.status(404).json({ message: 'Notice not found' });
    }
    
    // Emit real-time update to all connected clients
    if (typeof global.broadcastUpdate === 'function') {
      global.broadcastUpdate('notice-deleted', { noticeId: id });
    }
    
    res.json({ message: 'Notice deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error deleting notice', error: error.message });
  }
});

// Quiz Routes
// Get all quiz questions (only when exam is active)
app.get('/api/quiz/questions', async (req, res) => {
  try {
    // Check if there's an active exam session
    const activeSession = await ExamSession.findOne({ isActive: true });
    
    if (!activeSession) {
      return res.status(403).json({ message: 'No active exam session. Please wait for admin to start the exam.' });
    }

    // Check if session has expired
    const now = new Date();
    if (now > activeSession.endTime) {
      activeSession.isActive = false;
      await activeSession.save();
      return res.status(403).json({ message: 'Exam session has ended.' });
    }

    const questions = await QuizQuestion.find().select('-correctOption').sort({ createdAt: -1 });
    res.json(questions);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching questions', error: error.message });
  }
});

// Check exam eligibility (protected)
app.get('/api/quiz/check-eligibility', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Check if user is eligible (both teachers and students)
    if (!user.isExamEligible) {
      return res.json({ isEligible: false, reason: 'You are not eligible for the exam. Please contact admin.' });
    }

    res.json({ isEligible: true });
  } catch (error) {
    res.status(500).json({ message: 'Error checking eligibility', error: error.message });
  }
});

// Get all quiz questions (admin - includes correct answers)
app.get('/api/admin/quiz/questions', async (req, res) => {
  try {
    const questions = await QuizQuestion.find().sort({ createdAt: -1 });
    res.json(questions);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching questions', error: error.message });
  }
});

// Create quiz question (admin only)
app.post('/api/quiz/questions', async (req, res) => {
  try {
    const { question, option1, option2, option3, option4, correctOption } = req.body;
    const newQuestion = new QuizQuestion({
      question,
      option1,
      option2,
      option3,
      option4,
      correctOption
    });
    await newQuestion.save();
    res.status(201).json({ message: 'Question added successfully!', data: newQuestion });
  } catch (error) {
    res.status(500).json({ message: 'Error adding question', error: error.message });
  }
});

// Update quiz question (admin only)
app.put('/api/quiz/questions/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { question, option1, option2, option3, option4, correctOption } = req.body;
    const updatedQuestion = await QuizQuestion.findByIdAndUpdate(
      id,
      { question, option1, option2, option3, option4, correctOption },
      { new: true }
    );
    res.json({ message: 'Question updated successfully!', data: updatedQuestion });
  } catch (error) {
    res.status(500).json({ message: 'Error updating question', error: error.message });
  }
});

// Delete quiz question (admin only)
app.delete('/api/quiz/questions/:id', async (req, res) => {
  try {
    const { id } = req.params;
    await QuizQuestion.findByIdAndDelete(id);
    res.json({ message: 'Question deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error deleting question', error: error.message });
  }
});

// Submit quiz (protected)
app.post('/api/quiz/submit', authMiddleware, async (req, res) => {
  try {
    const { answers, sessionId } = req.body; // answers: [{ questionId, selectedOption }]
    const user = await User.findById(req.userId).select('-password');
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Verify session if provided
    if (sessionId) {
      const session = await ExamSession.findById(sessionId);
      if (!session) {
        return res.status(404).json({ message: 'Invalid exam session' });
      }
      
      // Check if session is still active
      const now = new Date();
      if (!session.isActive || now > session.endTime) {
        return res.status(400).json({ message: 'Exam session has ended' });
      }
    }

    // Get all questions with correct answers
    const questions = await QuizQuestion.find();
    const questionMap = new Map(questions.map(q => [q._id.toString(), q]));

    // Calculate score
    let correctCount = 0;
    const processedAnswers = answers.map(answer => {
      const question = questionMap.get(answer.questionId);
      const isCorrect = question && question.correctOption === answer.selectedOption;
      if (isCorrect) correctCount++;
      
      return {
        questionId: answer.questionId,
        selectedOption: answer.selectedOption,
        isCorrect
      };
    });

    const totalQuestions = answers.length;
    const percentage = Math.round((correctCount / totalQuestions) * 100);
    const passed = percentage >= 60; // Pass mark is 60%

    // Save result
    const result = new QuizResult({
      userId: user._id,
      userName: `${user.firstName} ${user.lastName}`,
      score: correctCount,
      totalQuestions,
      percentage,
      passed,
      answers: processedAnswers
    });

    await result.save();

    res.json({
      message: passed ? 'Congratulations! You passed!' : 'Better luck next time!',
      result: {
        score: correctCount,
        totalQuestions,
        percentage,
        passed,
        resultId: result._id
      }
    });
  } catch (error) {
    res.status(500).json({ message: 'Error submitting quiz', error: error.message });
  }
});

// Get quiz result by ID (allow both authenticated users and admins)
app.get('/api/quiz/result/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const result = await QuizResult.findById(id);
    
    if (!result) {
      return res.status(404).json({ message: 'Result not found' });
    }

    res.json(result);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching result', error: error.message });
  }
});

// Get user's quiz history
app.get('/api/quiz/my-results', authMiddleware, async (req, res) => {
  try {
    const results = await QuizResult.find({ userId: req.userId }).sort({ completedAt: -1 });
    res.json(results);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching results', error: error.message });
  }
});

// Get all quiz results (admin)
app.get('/api/admin/quiz/results', async (req, res) => {
  try {
    const results = await QuizResult.find().sort({ completedAt: -1 });
    res.json(results);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching results', error: error.message });
  }
});

// Exam Results Routes (Admin-managed)
// Start exam session (admin only)
app.post('/api/exam-session/start', async (req, res) => {
  try {
    // Check if there's an active session
    const activeSession = await ExamSession.findOne({ isActive: true });
    if (activeSession) {
      return res.status(400).json({ message: 'An exam session is already in progress' });
    }

    const { durationMinutes } = req.body; // Get duration from request, default to 60 minutes
    const duration = (durationMinutes || 60) * 60; // Convert to seconds
    const startTime = new Date();
    const endTime = new Date(startTime.getTime() + duration * 1000);

    const session = new ExamSession({
      startTime,
      endTime,
      duration,
      isActive: true
    });

    await session.save();

    // Broadcast to all eligible users via Socket.IO
    if (typeof global.broadcastUpdate === 'function') {
      global.broadcastUpdate('exam-started', {
        sessionId: session._id,
        startTime: session.startTime,
        endTime: session.endTime,
        duration: session.duration
      });
    }

    res.json({ 
      message: 'Exam session started successfully', 
      session 
    });
  } catch (error) {
    res.status(500).json({ message: 'Error starting exam session', error: error.message });
  }
});

// Get active exam session
app.get('/api/exam-session/active', async (req, res) => {
  try {
    const activeSession = await ExamSession.findOne({ isActive: true });
    
    if (!activeSession) {
      return res.json({ isActive: false });
    }

    // Check if session has expired
    const now = new Date();
    if (now > activeSession.endTime) {
      activeSession.isActive = false;
      await activeSession.save();
      return res.json({ isActive: false });
    }

    res.json({ 
      isActive: true,
      session: activeSession
    });
  } catch (error) {
    res.status(500).json({ message: 'Error fetching active session', error: error.message });
  }
});

// End exam session (admin only or automatic)
app.post('/api/exam-session/end/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { isSuspended } = req.body; // Check if admin manually stopped (suspended)
    const session = await ExamSession.findById(id);
    
    if (!session) {
      return res.status(404).json({ message: 'Session not found' });
    }

    session.isActive = false;
    await session.save();

    // If exam was suspended by admin, create suspended results for all participants who haven't submitted
    if (isSuspended) {
      // Get all eligible users who haven't submitted results for this session
      const eligibleUsers = await User.find({ isExamEligible: true, isActivated: true });
      const existingResults = await QuizResult.find({
        completedAt: { $gte: session.startTime }
      });
      const submittedUserIds = new Set(existingResults.map(r => r.userId.toString()));
      
      // Create suspended results for users who didn't submit
      const suspendedResults = [];
      for (const user of eligibleUsers) {
        if (!submittedUserIds.has(user._id.toString())) {
          const suspendedResult = new QuizResult({
            userId: user._id,
            userName: `${user.firstName} ${user.lastName}`,
            score: 0,
            totalQuestions: 0,
            percentage: 0,
            passed: false,
            isSuspended: true,
            suspendedReason: 'Exam was stopped by administrator',
            answers: []
          });
          suspendedResults.push(suspendedResult);
        }
      }
      
      if (suspendedResults.length > 0) {
        await QuizResult.insertMany(suspendedResults);
      }
    }

    // Broadcast session end
    if (typeof global.broadcastUpdate === 'function') {
      global.broadcastUpdate('exam-ended', {
        sessionId: session._id,
        isSuspended: isSuspended || false
      });
    }

    res.json({ 
      message: isSuspended ? 'Exam suspended' : 'Exam session ended', 
      session 
    });
  } catch (error) {
    res.status(500).json({ message: 'Error ending exam session', error: error.message });
  }
});

// Get all exam sessions (admin)
app.get('/api/exam-session/all', async (req, res) => {
  try {
    const sessions = await ExamSession.find().sort({ createdAt: -1 });
    res.json(sessions);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching sessions', error: error.message });
  }
});

// Exam Results Routes (Admin-managed)
// Get all exam results
app.get('/api/exam-results', async (req, res) => {
  try {
    const results = await ExamResult.find().sort({ createdAt: -1 });
    res.json(results);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching exam results', error: error.message });
  }
});

// Get exam results for a specific student
app.get('/api/exam-results/student/:studentId', authMiddleware, async (req, res) => {
  try {
    const { studentId } = req.params;
    const results = await ExamResult.find({ studentId }).sort({ createdAt: -1 });
    res.json(results);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching student results', error: error.message });
  }
});

// Add exam result (admin only)
app.post('/api/exam-results', async (req, res) => {
  try {
    const { studentId, studentName, rollNumber, class: studentClass, testType, subjects } = req.body;
    
    // If studentId is provided, get student details from database
    let finalStudentName = studentName;
    let finalRollNumber = rollNumber;
    let finalClass = studentClass;
    
    if (studentId) {
      const student = await User.findById(studentId);
      if (!student) {
        return res.status(404).json({ message: 'Student not found' });
      }

      if (student.userType !== 'student') {
        return res.status(400).json({ message: 'Results can only be added for students' });
      }
      
      finalStudentName = `${student.firstName} ${student.lastName}`;
      finalRollNumber = student.rollNumber;
      finalClass = student.class;
    } else {
      // Manual entry - validate required fields
      if (!studentName || !rollNumber || !studentClass) {
        return res.status(400).json({ message: 'Student Name, Roll Number, and Class are required' });
      }
    }

    // Calculate totals
    let totalMarks = 0;
    let obtainedMarks = 0;

    subjects.forEach(subject => {
      totalMarks += subject.maxMarks;
      obtainedMarks += subject.marks;
    });

    const percentage = ((obtainedMarks / totalMarks) * 100).toFixed(2);

    const examResult = new ExamResult({
      studentId: studentId || null,
      studentName: finalStudentName,
      rollNumber: finalRollNumber,
      class: finalClass,
      testType: testType || '',
      subjects,
      totalMarks,
      obtainedMarks,
      percentage: parseFloat(percentage),
      isPublished: false
    });

    await examResult.save();
    res.status(201).json({ message: 'Exam result added successfully', data: examResult });
  } catch (error) {
    res.status(500).json({ message: 'Error adding exam result', error: error.message });
  }
});

// Update exam result (admin only)
app.put('/api/exam-results/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { subjects, studentName, rollNumber, class: studentClass, testType, isPublished } = req.body;

    // Calculate totals if subjects are provided
    let updateData = {};
    
    if (subjects) {
      let totalMarks = 0;
      let obtainedMarks = 0;

      subjects.forEach(subject => {
        totalMarks += subject.maxMarks;
        obtainedMarks += subject.marks;
      });

      const percentage = ((obtainedMarks / totalMarks) * 100).toFixed(2);
      
      updateData = {
        subjects,
        totalMarks,
        obtainedMarks,
        percentage: parseFloat(percentage)
      };
    }
    
    // Add other fields if provided
    if (studentName) updateData.studentName = studentName;
    if (rollNumber) updateData.rollNumber = rollNumber;
    if (studentClass) updateData.class = studentClass;
    if (testType !== undefined) updateData.testType = testType;
    if (isPublished !== undefined) updateData.isPublished = isPublished;

    const updatedResult = await ExamResult.findByIdAndUpdate(
      id,
      updateData,
      { new: true }
    );

    if (!updatedResult) {
      return res.status(404).json({ message: 'Exam result not found' });
    }

    res.json({ message: 'Exam result updated successfully', data: updatedResult });
  } catch (error) {
    res.status(500).json({ message: 'Error updating exam result', error: error.message });
  }
});

// Delete exam result (admin only)
app.delete('/api/exam-results/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const deletedResult = await ExamResult.findByIdAndDelete(id);
    
    if (!deletedResult) {
      return res.status(404).json({ message: 'Exam result not found' });
    }

    res.json({ message: 'Exam result deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error deleting exam result', error: error.message });
  }
});

// Publish all exam results (admin only)
app.post('/api/exam-results/publish-all', async (req, res) => {
  try {
    const result = await ExamResult.updateMany(
      { isPublished: false },
      { $set: { isPublished: true } }
    );
    
    res.json({ 
      message: `Successfully published ${result.modifiedCount} exam result(s)`,
      count: result.modifiedCount
    });
  } catch (error) {
    res.status(500).json({ message: 'Error publishing exam results', error: error.message });
  }
});

// Unpublish all exam results (admin only)
app.post('/api/exam-results/unpublish-all', async (req, res) => {
  try {
    const result = await ExamResult.updateMany(
      { isPublished: true },
      { $set: { isPublished: false } }
    );
    
    res.json({ 
      message: `Successfully unpublished ${result.modifiedCount} exam result(s)`,
      count: result.modifiedCount
    });
  } catch (error) {
    res.status(500).json({ message: 'Error unpublishing exam results', error: error.message });
  }
});

// Reset user's quiz attempt (admin)
app.delete('/api/admin/quiz/reset/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    await QuizResult.deleteMany({ userId });
    res.json({ message: 'Quiz attempts reset successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error resetting quiz', error: error.message });
  }
});

// Video Routes
// Get all videos
app.get('/api/videos', async (req, res) => {
  try {
    const videos = await Video.find().sort({ createdAt: -1 });
    res.json(videos);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching videos', error: error.message });
  }
});

// Add video (admin only)
app.post('/api/videos', async (req, res) => {
  try {
    const { title, description, videoUrl, category } = req.body;
    
    let videoId = '';
    let videoType = 'youtube';
    
    // Check if it's a Google Drive URL
    if (videoUrl.includes('drive.google.com')) {
      videoType = 'drive';
      // Extract file ID from Google Drive URL
      const fileIdMatch = videoUrl.match(/\/d\/([a-zA-Z0-9_-]+)/) || 
                         videoUrl.match(/id=([a-zA-Z0-9_-]+)/);
      if (fileIdMatch && fileIdMatch[1]) {
        videoId = fileIdMatch[1];
      }
    } else {
      // YouTube URL - Extract video ID
      const urlPatterns = [
        /(?:youtube\.com\/watch\?v=|youtu\.be\/)([^&\n?#]+)/,
        /youtube\.com\/embed\/([^&\n?#]+)/
      ];
      
      for (const pattern of urlPatterns) {
        const match = videoUrl.match(pattern);
        if (match) {
          videoId = match[1];
          break;
        }
      }
      
      if (!videoId) {
        return res.status(400).json({ message: 'Invalid YouTube URL' });
      }
    }
    
    const video = new Video({
      title,
      description,
      videoUrl,
      videoId,
      videoType,
      category
    });
    
    await video.save();
    res.status(201).json({ message: 'Video added successfully', data: video });
  } catch (error) {
    res.status(500).json({ message: 'Error adding video', error: error.message });
  }
});

// Update video (admin only)
app.put('/api/videos/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { title, description, videoUrl, category } = req.body;
    
    let videoId = '';
    let videoType = 'youtube';
    
    // Check if it's a Google Drive URL
    if (videoUrl.includes('drive.google.com')) {
      videoType = 'drive';
      // Extract file ID from Google Drive URL
      const fileIdMatch = videoUrl.match(/\/d\/([a-zA-Z0-9_-]+)/) || 
                         videoUrl.match(/id=([a-zA-Z0-9_-]+)/);
      if (fileIdMatch && fileIdMatch[1]) {
        videoId = fileIdMatch[1];
      }
    } else {
      // YouTube URL - Extract video ID
      const urlPatterns = [
        /(?:youtube\.com\/watch\?v=|youtu\.be\/)([^&\n?#]+)/,
        /youtube\.com\/embed\/([^&\n?#]+)/
      ];
      
      for (const pattern of urlPatterns) {
        const match = videoUrl.match(pattern);
        if (match) {
          videoId = match[1];
          break;
        }
      }
      
      if (!videoId) {
        return res.status(400).json({ message: 'Invalid YouTube URL' });
      }
    }
    
    const updatedVideo = await Video.findByIdAndUpdate(
      id,
      { title, description, videoUrl, videoId, videoType, category },
      { new: true }
    );
    
    if (!updatedVideo) {
      return res.status(404).json({ message: 'Video not found' });
    }
    
    res.json({ message: 'Video updated successfully', data: updatedVideo });
  } catch (error) {
    res.status(500).json({ message: 'Error updating video', error: error.message });
  }
});

// Delete video (admin only)
app.delete('/api/videos/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const deletedVideo = await Video.findByIdAndDelete(id);
    
    if (!deletedVideo) {
      return res.status(404).json({ message: 'Video not found' });
    }
    
    res.json({ message: 'Video deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error deleting video', error: error.message });
  }
});

// Note Routes (PDF Study Materials)
// Get all notes
app.get('/api/notes', async (req, res) => {
  try {
    const notes = await Note.find().sort({ createdAt: -1 });
    res.json(notes);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching notes', error: error.message });
  }
});

// Add note (admin only)
app.post('/api/notes', async (req, res) => {
  try {
    const { title, description, pdfUrl, publicId, category, fileSize } = req.body;
    
    // Validate file size only if it's provided (for Cloudinary uploads)
    if (fileSize && fileSize > 10485760) {
      return res.status(400).json({ message: 'File size exceeds 10MB limit' });
    }
    
    const note = new Note({
      title,
      description,
      pdfUrl,
      publicId: publicId || '',
      category,
      fileSize: fileSize || 0
    });
    
    await note.save();
    res.status(201).json({ message: 'Note added successfully', data: note });
  } catch (error) {
    res.status(500).json({ message: 'Error adding note', error: error.message });
  }
});

// Upload PDF to Cloudinary (admin only)
app.post('/api/notes/upload-pdf', uploadPdf.single('pdf'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: 'No PDF file provided' });
    }

    // Validate file type
    if (req.file.mimetype !== 'application/pdf') {
      return res.status(400).json({ message: 'Please upload a PDF file only' });
    }

    // Validate file size (10MB = 10485760 bytes)
    if (req.file.size > 10485760) {
      return res.status(400).json({ message: 'File size exceeds 10MB limit' });
    }

    const uploadStream = cloudinary.uploader.upload_stream(
      {
        folder: 'school-notes',
        resource_type: 'raw',
        format: 'pdf'
      },
      (error, result) => {
        if (error) {
          console.error('Cloudinary upload error:', error);
          return res.status(500).json({ message: 'PDF upload failed', error: error.message });
        }

        res.json({
          message: 'PDF uploaded successfully',
          data: {
            pdfUrl: result.secure_url,
            publicId: result.public_id,
            fileSize: req.file.size
          }
        });
      }
    );

    // Convert buffer to stream and pipe to Cloudinary
    const bufferStream = require('stream').Readable.from(req.file.buffer);
    bufferStream.pipe(uploadStream);
  } catch (error) {
    console.error('PDF upload error:', error);
    res.status(500).json({ message: 'PDF upload failed', error: error.message });
  }
});

// Update note (admin only)
app.put('/api/notes/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { title, description, category, pdfUrl, publicId, fileSize } = req.body;
    
    const updateData = { title, description, category };
    
    // Update pdfUrl and related fields if provided
    if (pdfUrl !== undefined) updateData.pdfUrl = pdfUrl;
    if (publicId !== undefined) updateData.publicId = publicId;
    if (fileSize !== undefined) updateData.fileSize = fileSize;
    
    const updatedNote = await Note.findByIdAndUpdate(
      id,
      updateData,
      { new: true }
    );
    
    if (!updatedNote) {
      return res.status(404).json({ message: 'Note not found' });
    }
    
    res.json({ message: 'Note updated successfully', data: updatedNote });
  } catch (error) {
    res.status(500).json({ message: 'Error updating note', error: error.message });
  }
});

// Delete note (admin only)
app.delete('/api/notes/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const deletedNote = await Note.findByIdAndDelete(id);
    
    if (!deletedNote) {
      return res.status(404).json({ message: 'Note not found' });
    }
    
    res.json({ message: 'Note deleted successfully', publicId: deletedNote.publicId });
  } catch (error) {
    res.status(500).json({ message: 'Error deleting note', error: error.message });
  }
});

// Download PDF (proxy to avoid CORS issues)
app.get('/api/notes/download/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const note = await Note.findById(id);
    
    if (!note) {
      return res.status(404).json({ message: 'Note not found' });
    }
    
    // Redirect to Cloudinary URL with attachment flag
    const downloadUrl = note.pdfUrl.replace('/upload/', '/upload/fl_attachment/');
    res.redirect(downloadUrl);
  } catch (error) {
    res.status(500).json({ message: 'Error downloading PDF', error: error.message });
  }
});

// Check if user has passed the quiz
app.get('/api/quiz/check-status', authMiddleware, async (req, res) => {
  try {
    const latestResult = await QuizResult.findOne({ userId: req.userId })
      .sort({ completedAt: -1 })
      .limit(1);
    
    if (latestResult && latestResult.passed) {
      res.json({ 
        hasPassed: true, 
        resultId: latestResult._id,
        score: latestResult.score,
        totalQuestions: latestResult.totalQuestions,
        percentage: latestResult.percentage,
        completedAt: latestResult.completedAt
      });
    } else {
      res.json({ hasPassed: false });
    }
  } catch (error) {
    res.status(500).json({ message: 'Error checking quiz status', error: error.message });
  }
});

// Update user profile (protected)
app.put('/api/profile', authMiddleware, async (req, res) => {
  try {
    const { firstName, lastName, email, phone, rollNumber, class: studentClass } = req.body;
    
    const updateData = { firstName, lastName };
    if (email) updateData.email = email;
    if (phone) updateData.phone = phone;
    if (rollNumber) updateData.rollNumber = rollNumber;
    if (studentClass) updateData.class = studentClass;

    const user = await User.findByIdAndUpdate(
      req.userId,
      updateData,
      { new: true, runValidators: true }
    ).select('-password');

    res.json(user);
  } catch (error) {
    res.status(500).json({ message: 'Error updating profile', error: error.message });
  }
});

// Gallery Media Routes
// Get all gallery media
app.get('/api/gallery', async (req, res) => {
  try {
    const media = await GalleryMedia.find().sort({ createdAt: -1 });
    res.json(media);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching gallery media', error: error.message });
  }
});

// Add gallery media (admin only)
app.post('/api/gallery', async (req, res) => {
  try {
    const { type, title, description, url, thumbnail, publicId } = req.body;
    
    const media = new GalleryMedia({
      type,
      title,
      description,
      url,
      thumbnail,
      publicId
    });
    
    await media.save();
    res.status(201).json({ message: 'Media added to gallery successfully', data: media });
  } catch (error) {
    res.status(500).json({ message: 'Error adding gallery media', error: error.message });
  }
});

// Update gallery media (admin only)
app.put('/api/gallery/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { type, title, description, url, thumbnail, publicId } = req.body;
    
    const updatedMedia = await GalleryMedia.findByIdAndUpdate(
      id,
      { type, title, description, url, thumbnail, publicId },
      { new: true }
    );
    
    if (!updatedMedia) {
      return res.status(404).json({ message: 'Media not found' });
    }
    
    res.json({ message: 'Gallery media updated successfully', data: updatedMedia });
  } catch (error) {
    res.status(500).json({ message: 'Error updating gallery media', error: error.message });
  }
});

// Delete gallery media (admin only)
app.delete('/api/gallery/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const deletedMedia = await GalleryMedia.findByIdAndDelete(id);
    
    if (!deletedMedia) {
      return res.status(404).json({ message: 'Media not found' });
    }
    
    res.json({ message: 'Gallery media deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error deleting gallery media', error: error.message });
  }
});

// Upload image to Cloudinary (for gallery)
app.post('/api/gallery/upload-image', upload.single('image'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: 'No image file provided' });
    }

    const uploadStream = cloudinary.uploader.upload_stream(
      {
        folder: 'school-gallery',
        resource_type: 'image'
      },
      (error, result) => {
        if (error) {
          console.error('Cloudinary upload error:', error);
          return res.status(500).json({ message: 'Image upload failed', error: error.message });
        }

        res.json({
          message: 'Image uploaded successfully',
          data: {
            url: result.secure_url,
            publicId: result.public_id
          }
        });
      }
    );

    const bufferStream = require('stream').Readable.from(req.file.buffer);
    bufferStream.pipe(uploadStream);
  } catch (error) {
    console.error('Image upload error:', error);
    res.status(500).json({ message: 'Image upload failed', error: error.message });
  }
});

// ==================== ATTENDANCE & SUBJECT ROUTES ====================

// Subject Routes
// Get all subjects
app.get('/api/subjects', async (req, res) => {
  try {
    const subjects = await Subject.find().sort({ class: 1, name: 1 });
    res.json(subjects);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching subjects', error: error.message });
  }
});

// Get subjects by class
app.get('/api/subjects/class/:class', async (req, res) => {
  try {
    const { class: className } = req.params;
    const subjects = await Subject.find({ class: className }).sort({ name: 1 });
    res.json(subjects);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching subjects', error: error.message });
  }
});

// Add subject (admin only)
app.post('/api/subjects', async (req, res) => {
  try {
    const { name, class: className } = req.body;
    
    // Check if subject already exists for this class
    const existingSubject = await Subject.findOne({ name, class: className });
    if (existingSubject) {
      return res.status(400).json({ message: 'Subject already exists for this class' });
    }
    
    const subject = new Subject({
      name,
      class: className,
      createdBy: 'Admin'
    });
    
    await subject.save();
    res.status(201).json({ message: 'Subject added successfully', data: subject });
  } catch (error) {
    res.status(500).json({ message: 'Error adding subject', error: error.message });
  }
});

// Update subject (admin only)
app.put('/api/subjects/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { name, class: className } = req.body;
    
    const updatedSubject = await Subject.findByIdAndUpdate(
      id,
      { name, class: className },
      { new: true }
    );
    
    if (!updatedSubject) {
      return res.status(404).json({ message: 'Subject not found' });
    }
    
    res.json({ message: 'Subject updated successfully', data: updatedSubject });
  } catch (error) {
    res.status(500).json({ message: 'Error updating subject', error: error.message });
  }
});

// Delete subject (admin only)
app.delete('/api/subjects/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const deletedSubject = await Subject.findByIdAndDelete(id);
    
    if (!deletedSubject) {
      return res.status(404).json({ message: 'Subject not found' });
    }
    
    // Also delete all attendance records for this subject
    await Attendance.deleteMany({ subjectId: id });
    
    res.json({ message: 'Subject deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error deleting subject', error: error.message });
  }
});

// Attendance Routes
// Get all attendance records (admin)
app.get('/api/attendance', async (req, res) => {
  try {
    const attendance = await Attendance.find()
      .populate('studentId', 'firstName lastName class rollNumber')
      .sort({ date: -1 });
    res.json(attendance);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching attendance', error: error.message });
  }
});

// Get attendance by student ID
app.get('/api/attendance/student/:studentId', async (req, res) => {
  try {
    const { studentId } = req.params;
    const attendance = await Attendance.find({ studentId })
      .sort({ date: -1 });
    res.json(attendance);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching student attendance', error: error.message });
  }
});

// Get attendance by class
app.get('/api/attendance/class/:class', async (req, res) => {
  try {
    const { class: className } = req.params;
    const attendance = await Attendance.find({ class: className })
      .populate('studentId', 'firstName lastName rollNumber')
      .sort({ date: -1 });
    res.json(attendance);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching class attendance', error: error.message });
  }
});

// Get attendance by date range
app.get('/api/attendance/date-range', async (req, res) => {
  try {
    const { startDate, endDate, class: className } = req.query;
    
    const query = {};
    if (startDate && endDate) {
      query.date = {
        $gte: new Date(startDate),
        $lte: new Date(endDate)
      };
    }
    if (className) {
      query.class = className;
    }
    
    const attendance = await Attendance.find(query)
      .populate('studentId', 'firstName lastName class rollNumber')
      .sort({ date: -1 });
    res.json(attendance);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching attendance', error: error.message });
  }
});

// Mark attendance (teacher or admin)
app.post('/api/attendance/mark', authMiddleware, async (req, res) => {
  try {
    const { attendanceRecords } = req.body; // Array of { studentId, date, status }
    const user = await User.findById(req.userId);
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    const markedBy = `${user.firstName} ${user.lastName}`;
    const results = [];
    const errors = [];
    
    for (const record of attendanceRecords) {
      try {
        const { studentId, date, status } = record;
        
        // Get student details
        const student = await User.findById(studentId);
        
        if (!student) {
          errors.push({ studentId, error: 'Student not found' });
          continue;
        }
        
        // Use findOneAndUpdate with upsert to handle duplicates (only one attendance per day)
        const attendance = await Attendance.findOneAndUpdate(
          {
            studentId,
            date: new Date(date)
          },
          {
            studentName: `${student.firstName} ${student.lastName}`,
            rollNumber: student.rollNumber,
            class: student.class,
            status,
            markedBy,
            markedByUserId: req.userId
          },
          {
            upsert: true,
            new: true,
            setDefaultsOnInsert: true
          }
        );
        
        results.push(attendance);
      } catch (error) {
        errors.push({ record, error: error.message });
      }
    }
    
    res.status(201).json({
      message: `Attendance marked successfully for ${results.length} student(s)`,
      data: results,
      errors: errors.length > 0 ? errors : undefined
    });
  } catch (error) {
    res.status(500).json({ message: 'Error marking attendance', error: error.message });
  }
});

// Update attendance record
app.put('/api/attendance/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;
    
    // Check if user is admin
    const user = await User.findById(req.userId);
    if (user.userType !== 'admin') {
      return res.status(403).json({ message: 'Only admins can edit attendance records' });
    }
    
    const attendance = await Attendance.findByIdAndUpdate(
      id,
      { status },
      { new: true }
    );
    
    if (!attendance) {
      return res.status(404).json({ message: 'Attendance record not found' });
    }
    
    res.json({ message: 'Attendance updated successfully', data: attendance });
  } catch (error) {
    res.status(500).json({ message: 'Error updating attendance', error: error.message });
  }
});

// Delete attendance record (admin only)
app.delete('/api/attendance/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    
    // Check if user is admin
    const user = await User.findById(req.userId);
    if (user.userType !== 'admin') {
      return res.status(403).json({ message: 'Only admins can delete attendance records' });
    }
    
    const deletedAttendance = await Attendance.findByIdAndDelete(id);
    
    if (!deletedAttendance) {
      return res.status(404).json({ message: 'Attendance record not found' });
    }
    
    res.json({ message: 'Attendance record permanently deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error deleting attendance', error: error.message });
  }
});

// Get attendance summary for a student
app.get('/api/attendance/summary/student/:studentId', async (req, res) => {
  try {
    const { studentId } = req.params;
    const { year } = req.query;
    
    const startDate = year ? new Date(`${year}-01-01`) : new Date(new Date().getFullYear(), 0, 1);
    const endDate = year ? new Date(`${year}-12-31`) : new Date(new Date().getFullYear(), 11, 31);
    
    const attendance = await Attendance.find({
      studentId,
      date: { $gte: startDate, $lte: endDate }
    });
    
    // Calculate overall summary
    const summary = { present: 0, absent: 0, total: 0 };
    attendance.forEach(record => {
      summary[record.status]++;
      summary.total++;
    });
    
    res.json({ summary, records: attendance });
  } catch (error) {
    res.status(500).json({ message: 'Error fetching attendance summary', error: error.message });
  }
});

// Teacher Attendance Routes
// Get all teacher attendance records (admin)
app.get('/api/teacher-attendance', async (req, res) => {
  try {
    const attendance = await TeacherAttendance.find()
      .populate('teacherId', 'firstName lastName email')
      .sort({ date: -1 });
    res.json(attendance);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching teacher attendance', error: error.message });
  }
});

// Get attendance for a specific teacher
app.get('/api/teacher-attendance/teacher/:teacherId', authMiddleware, async (req, res) => {
  try {
    const { teacherId } = req.params;
    const attendance = await TeacherAttendance.find({ teacherId })
      .sort({ date: -1 });
    res.json(attendance);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching teacher attendance', error: error.message });
  }
});

// Get teacher attendance summary (teacher dashboard)
app.get('/api/teacher-attendance/summary/:teacherId', authMiddleware, async (req, res) => {
  try {
    const { teacherId } = req.params;
    const { year } = req.query;
    
    const startDate = year ? new Date(`${year}-01-01`) : new Date(new Date().getFullYear(), 0, 1);
    const endDate = year ? new Date(`${year}-12-31`) : new Date(new Date().getFullYear(), 11, 31);
    
    const attendance = await TeacherAttendance.find({
      teacherId,
      date: { $gte: startDate, $lte: endDate }
    });
    
    // Calculate overall summary
    const summary = { present: 0, absent: 0, total: 0 };
    attendance.forEach(record => {
      summary[record.status]++;
      summary.total++;
    });
    
    res.json({ summary, records: attendance });
  } catch (error) {
    res.status(500).json({ message: 'Error fetching teacher attendance summary', error: error.message });
  }
});

// Mark teacher attendance (admin only)
app.post('/api/teacher-attendance/mark', async (req, res) => {
  try {
    const { attendanceRecords } = req.body; // Array of { teacherId, date, status }
    const results = [];
    const errors = [];
    
    for (const record of attendanceRecords) {
      try {
        const { teacherId, date, status } = record;
        
        // Get teacher details
        const teacher = await User.findById(teacherId);
        
        if (!teacher) {
          errors.push({ teacherId, error: 'Teacher not found' });
          continue;
        }
        
        // Use findOneAndUpdate with upsert to handle duplicates
        const attendance = await TeacherAttendance.findOneAndUpdate(
          {
            teacherId,
            date: new Date(date)
          },
          {
            teacherName: `${teacher.firstName} ${teacher.lastName}`,
            status,
            markedBy: 'Admin'
          },
          {
            upsert: true,
            new: true,
            setDefaultsOnInsert: true
          }
        );
        
        results.push(attendance);
      } catch (error) {
        errors.push({ record, error: error.message });
      }
    }
    
    res.status(201).json({
      message: `Attendance marked successfully for ${results.length} teacher(s)`,
      data: results,
      errors: errors.length > 0 ? errors : undefined
    });
  } catch (error) {
    res.status(500).json({ message: 'Error marking teacher attendance', error: error.message });
  }
});

// Delete teacher attendance record (admin only)
app.delete('/api/teacher-attendance/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const deletedAttendance = await TeacherAttendance.findByIdAndDelete(id);
    
    if (!deletedAttendance) {
      return res.status(404).json({ message: 'Teacher attendance record not found' });
    }
    
    res.json({ message: 'Teacher attendance record deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error deleting teacher attendance record', error: error.message });
  }
});

// Fees Management Routes
// Get all fees records (admin)
app.get('/api/fees', async (req, res) => {
  try {
    const fees = await Fees.find().sort({ class: 1, rollNumber: 1 });
    res.json(fees);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching fees records', error: error.message });
  }
});

// Get fees for a specific student
app.get('/api/fees/student/:studentId', authMiddleware, async (req, res) => {
  try {
    const { studentId } = req.params;
    let fees = await Fees.findOne({ studentId });
    
    // If no fees record exists, create one
    if (!fees) {
      const student = await User.findById(studentId);
      if (!student || student.userType !== 'student') {
        return res.status(404).json({ message: 'Student not found' });
      }
      
      fees = new Fees({
        studentId,
        studentName: `${student.firstName} ${student.lastName}`,
        rollNumber: student.rollNumber,
        class: student.class,
        totalFees: 0,
        deposit: 0,
        dues: 0,
        transactions: []
      });
      await fees.save();
    }
    
    res.json(fees);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching student fees', error: error.message });
  }
});

// Update fees for a student (admin only)
app.put('/api/fees/:studentId', async (req, res) => {
  try {
    const { studentId } = req.params;
    const { totalFees, deposit, description } = req.body;
    
    const student = await User.findById(studentId);
    if (!student || student.userType !== 'student') {
      return res.status(404).json({ message: 'Student not found' });
    }
    
    let fees = await Fees.findOne({ studentId });
    
    // If no fees record exists, create one
    if (!fees) {
      fees = new Fees({
        studentId,
        studentName: `${student.firstName} ${student.lastName}`,
        rollNumber: student.rollNumber,
        class: student.class,
        totalFees: 0,
        deposit: 0,
        dues: 0,
        transactions: []
      });
    }
    
    // Check if this is a reset operation (totalFees = 0 and deposit = 0)
    const isReset = totalFees === 0 && deposit === 0;
    
    if (isReset) {
      // Reset all fees to 0
      fees.transactions.push({
        amount: 0,
        type: 'fee_set',
        description: description || 'Fees reset by admin',
        date: new Date()
      });
      fees.totalFees = 0;
      fees.deposit = 0;
      fees.dues = 0;
    } else {
      // Update fees based on what's provided
      if (totalFees !== undefined && totalFees !== fees.totalFees) {
        fees.transactions.push({
          amount: totalFees,
          type: 'fee_set',
          description: description || `Total fees set to ₹${totalFees}`,
          date: new Date()
        });
        fees.totalFees = totalFees;
      }
      
      if (deposit !== undefined && deposit !== 0) {
        fees.transactions.push({
          amount: deposit,
          type: 'deposit',
          description: description && description.trim() !== '' ? description : '',
          date: new Date()
        });
        fees.deposit += deposit;
      }
      
      // Calculate dues (ensure it's never negative)
      fees.dues = Math.max(0, fees.totalFees - fees.deposit);
    }
    
    fees.updatedAt = new Date();
    
    await fees.save();
    
    res.json({ message: 'Fees updated successfully', data: fees });
  } catch (error) {
    res.status(500).json({ message: 'Error updating fees', error: error.message });
  }
});

// Get fees by class (admin)
app.get('/api/fees/class/:className', async (req, res) => {
  try {
    const { className } = req.params;
    const fees = await Fees.find({ class: className }).sort({ rollNumber: 1 });
    res.json(fees);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching class fees', error: error.message });
  }
});

// Initialize fees for all students who don't have a record (admin)
app.post('/api/fees/initialize-all', async (req, res) => {
  try {
    const students = await User.find({ userType: 'student' });
    let initialized = 0;
    
    for (const student of students) {
      const existingFees = await Fees.findOne({ studentId: student._id });
      if (!existingFees) {
        const fees = new Fees({
          studentId: student._id,
          studentName: `${student.firstName} ${student.lastName}`,
          rollNumber: student.rollNumber,
          class: student.class,
          totalFees: 0,
          deposit: 0,
          dues: 0,
          transactions: []
        });
        await fees.save();
        initialized++;
      }
    }
    
    res.json({ message: `Initialized fees for ${initialized} students`, count: initialized });
  } catch (error) {
    res.status(500).json({ message: 'Error initializing fees', error: error.message });
  }
});

// Public Teacher Schema
const publicTeacherSchema = new mongoose.Schema({
  name: { type: String, required: true },
  subject: { type: String },
  qualification: { type: String },
  experience: { type: String },
  gmail: { type: String },
  mobile: { type: String },
  image: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const PublicTeacher = mongoose.model('PublicTeacher', publicTeacherSchema);

// Public Member Schema
const publicMemberSchema = new mongoose.Schema({
  name: { type: String, required: true },
  designation: { type: String },
  gmail: { type: String },
  phone: { type: String },
  image: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const PublicMember = mongoose.model('PublicMember', publicMemberSchema);

// Public Teachers Routes

// Upload Public Teacher Image
app.post('/api/public-teachers/upload-image', upload.single('image'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: 'No image file uploaded' });
    }

    // Validate file size (1MB limit)
    if (req.file.size > 1 * 1024 * 1024) {
      return res.status(400).json({ message: 'Image size must be under 1MB' });
    }

    // Upload to Cloudinary
    const result = await new Promise((resolve, reject) => {
      const uploadStream = cloudinary.uploader.upload_stream(
        {
          folder: 'public-teachers',
          transformation: [
            { width: 500, height: 500, crop: 'fill' },
            { quality: 'auto' },
            { fetch_format: 'auto' }
          ]
        },
        (error, result) => {
          if (error) reject(error);
          else resolve(result);
        }
      );
      uploadStream.end(req.file.buffer);
    });

    res.json({
      success: true,
      data: {
        url: result.secure_url,
        publicId: result.public_id
      }
    });
  } catch (error) {
    console.error('Error uploading public teacher image:', error);
    res.status(500).json({ message: 'Failed to upload image', error: error.message });
  }
});

// Get all public teachers
app.get('/api/public-teachers', async (req, res) => {
  try {
    const teachers = await PublicTeacher.find().sort({ createdAt: -1 });
    res.json({ success: true, data: teachers });
  } catch (error) {
    res.status(500).json({ message: 'Error fetching public teachers', error: error.message });
  }
});

// Create public teacher
app.post('/api/public-teachers', async (req, res) => {
  try {
    const { name, subject, qualification, experience, gmail, mobile, image } = req.body;

    if (!name || !image) {
      return res.status(400).json({ message: 'Name and Image are required' });
    }

    const teacher = new PublicTeacher({
      name,
      subject,
      qualification,
      experience,
      gmail,
      mobile,
      image
    });

    await teacher.save();
    res.status(201).json({ success: true, data: teacher });
  } catch (error) {
    res.status(500).json({ message: 'Error creating public teacher', error: error.message });
  }
});

// Update public teacher
app.put('/api/public-teachers/:id', async (req, res) => {
  try {
    const { name, subject, qualification, experience, gmail, mobile, image } = req.body;

    const teacher = await PublicTeacher.findByIdAndUpdate(
      req.params.id,
      { name, subject, qualification, experience, gmail, mobile, image },
      { new: true }
    );

    if (!teacher) {
      return res.status(404).json({ message: 'Public teacher not found' });
    }

    res.json({ success: true, data: teacher });
  } catch (error) {
    res.status(500).json({ message: 'Error updating public teacher', error: error.message });
  }
});

// Delete public teacher
app.delete('/api/public-teachers/:id', async (req, res) => {
  try {
    const teacher = await PublicTeacher.findByIdAndDelete(req.params.id);
    
    if (!teacher) {
      return res.status(404).json({ message: 'Public teacher not found' });
    }

    res.json({ success: true, message: 'Public teacher deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error deleting public teacher', error: error.message });
  }
});

// Public Members Routes

// Upload Public Member Image
app.post('/api/public-members/upload-image', upload.single('image'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: 'No image file uploaded' });
    }

    // Validate file size (1MB limit)
    if (req.file.size > 1 * 1024 * 1024) {
      return res.status(400).json({ message: 'Image size must be under 1MB' });
    }

    // Upload to Cloudinary
    const result = await new Promise((resolve, reject) => {
      const uploadStream = cloudinary.uploader.upload_stream(
        {
          folder: 'public-members',
          transformation: [
            { width: 500, height: 500, crop: 'fill' },
            { quality: 'auto' },
            { fetch_format: 'auto' }
          ]
        },
        (error, result) => {
          if (error) reject(error);
          else resolve(result);
        }
      );
      uploadStream.end(req.file.buffer);
    });

    res.json({
      success: true,
      data: {
        url: result.secure_url,
        publicId: result.public_id
      }
    });
  } catch (error) {
    console.error('Error uploading public member image:', error);
    res.status(500).json({ message: 'Failed to upload image', error: error.message });
  }
});

// Get all public members
app.get('/api/public-members', async (req, res) => {
  try {
    const members = await PublicMember.find().sort({ createdAt: -1 });
    res.json({ success: true, data: members });
  } catch (error) {
    res.status(500).json({ message: 'Error fetching public members', error: error.message });
  }
});

// Create public member
app.post('/api/public-members', async (req, res) => {
  try {
    const { name, designation, gmail, phone, image } = req.body;

    if (!name || !image) {
      return res.status(400).json({ message: 'Name and Image are required' });
    }

    const member = new PublicMember({
      name,
      designation,
      gmail,
      phone,
      image
    });

    await member.save();
    res.status(201).json({ success: true, data: member });
  } catch (error) {
    res.status(500).json({ message: 'Error creating public member', error: error.message });
  }
});

// Update public member
app.put('/api/public-members/:id', async (req, res) => {
  try {
    const { name, designation, gmail, phone, image } = req.body;

    const member = await PublicMember.findByIdAndUpdate(
      req.params.id,
      { name, designation, gmail, phone, image },
      { new: true }
    );

    if (!member) {
      return res.status(404).json({ message: 'Public member not found' });
    }

    res.json({ success: true, data: member });
  } catch (error) {
    res.status(500).json({ message: 'Error updating public member', error: error.message });
  }
});

// Delete public member
app.delete('/api/public-members/:id', async (req, res) => {
  try {
    const member = await PublicMember.findByIdAndDelete(req.params.id);
    
    if (!member) {
      return res.status(404).json({ message: 'Public member not found' });
    }

    res.json({ success: true, message: 'Public member deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error deleting public member', error: error.message });
  }
});

// ============= PROGRESS CARD ROUTES =============

// Get all progress cards
app.get('/api/progress-cards', async (req, res) => {
  try {
    const progressCards = await ProgressCard.find().sort({ createdAt: -1 });
    res.json({ success: true, data: progressCards });
  } catch (error) {
    res.status(500).json({ message: 'Error fetching progress cards', error: error.message });
  }
});

// Get progress card by ID
app.get('/api/progress-cards/:id', async (req, res) => {
  try {
    const progressCard = await ProgressCard.findById(req.params.id);
    if (!progressCard) {
      return res.status(404).json({ message: 'Progress card not found' });
    }
    res.json({ success: true, data: progressCard });
  } catch (error) {
    res.status(500).json({ message: 'Error fetching progress card', error: error.message });
  }
});

// Create progress card
app.post('/api/progress-cards', async (req, res) => {
  try {
    const progressCardData = req.body;

    // Validate required fields
    if (!progressCardData.studentId || !progressCardData.studentName || !progressCardData.class || !progressCardData.aadhaarNumber) {
      return res.status(400).json({ message: 'Missing required fields' });
    }

    if (!progressCardData.subjects || progressCardData.subjects.length === 0) {
      return res.status(400).json({ message: 'At least one subject is required' });
    }

    const progressCard = new ProgressCard(progressCardData);
    await progressCard.save();

    res.status(201).json({ success: true, data: progressCard, message: 'Progress card created successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error creating progress card', error: error.message });
  }
});

// Update progress card
app.put('/api/progress-cards/:id', async (req, res) => {
  try {
    const progressCardData = req.body;

    const progressCard = await ProgressCard.findByIdAndUpdate(
      req.params.id,
      progressCardData,
      { new: true, runValidators: true }
    );

    if (!progressCard) {
      return res.status(404).json({ message: 'Progress card not found' });
    }

    res.json({ success: true, data: progressCard, message: 'Progress card updated successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error updating progress card', error: error.message });
  }
});

// Delete progress card
app.delete('/api/progress-cards/:id', async (req, res) => {
  try {
    const progressCard = await ProgressCard.findByIdAndDelete(req.params.id);

    if (!progressCard) {
      return res.status(404).json({ message: 'Progress card not found' });
    }

    res.json({ success: true, message: 'Progress card deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error deleting progress card', error: error.message });
  }
});

// Publish single progress card
app.put('/api/progress-cards/:id/publish', async (req, res) => {
  try {
    const progressCard = await ProgressCard.findByIdAndUpdate(
      req.params.id,
      { isPublished: true },
      { new: true }
    );

    if (!progressCard) {
      return res.status(404).json({ message: 'Progress card not found' });
    }

    res.json({ success: true, message: 'Progress card published successfully', data: progressCard });
  } catch (error) {
    res.status(500).json({ message: 'Error publishing progress card', error: error.message });
  }
});

// Unpublish single progress card
app.put('/api/progress-cards/:id/unpublish', async (req, res) => {
  try {
    const progressCard = await ProgressCard.findByIdAndUpdate(
      req.params.id,
      { isPublished: false },
      { new: true }
    );

    if (!progressCard) {
      return res.status(404).json({ message: 'Progress card not found' });
    }

    res.json({ success: true, message: 'Progress card unpublished successfully', data: progressCard });
  } catch (error) {
    res.status(500).json({ message: 'Error unpublishing progress card', error: error.message });
  }
});

// Publish all progress cards
app.put('/api/progress-cards/publish-all', async (req, res) => {
  try {
    const result = await ProgressCard.updateMany({}, { isPublished: true });

    res.json({ success: true, message: `${result.modifiedCount} progress card(s) published successfully` });
  } catch (error) {
    res.status(500).json({ message: 'Error publishing all progress cards', error: error.message });
  }
});

// Unpublish all progress cards
app.put('/api/progress-cards/unpublish-all', async (req, res) => {
  try {
    const result = await ProgressCard.updateMany({}, { isPublished: false });

    res.json({ success: true, message: `${result.modifiedCount} progress card(s) unpublished successfully` });
  } catch (error) {
    res.status(500).json({ message: 'Error unpublishing all progress cards', error: error.message });
  }
});

// Get student's own progress card
app.get('/api/my-progress-card', authMiddleware, async (req, res) => {
  try {
    const progressCard = await ProgressCard.findOne({ 
      studentId: req.userId,
      isPublished: true 
    });

    if (!progressCard) {
      return res.status(404).json({ message: 'No published progress card found' });
    }

    res.json({ success: true, data: progressCard });
  } catch (error) {
    res.status(500).json({ message: 'Error fetching progress card', error: error.message });
  }
});

app.get('/', (req, res) => {
  res.send('School Website API is running...');
});

const PORT = process.env.PORT || 5000;

// Initialize Socket.IO
const io = new Server(server, {
  cors: {
    origin: "http://localhost:5173", // Vite's default port
    methods: ["GET", "POST"]
  }
});

// Store connected clients
const connectedClients = new Map();

// Socket.IO connection handling
io.on('connection', (socket) => {
  
  // Store client info
  connectedClients.set(socket.id, { id: socket.id });
  
  // Handle client disconnect
  socket.on('disconnect', () => {
    connectedClients.delete(socket.id);
  });
  
  // Handle admin connection
  socket.on('admin-connected', () => {
    socket.join('admins');
  });
  
  // Handle user connection
  socket.on('user-connected', (userId) => {
    socket.join(`user-${userId}`);
  });
});

// Function to emit real-time updates
const emitRealTimeUpdate = (event, data) => {
  io.emit(event, data);
};

// Function to emit admin update
const emitAdminUpdate = (event, data) => {
  io.to('admins').emit(event, data);
};

// Function to emit user update
const emitUserUpdate = (userId, event, data) => {
  io.to(`user-${userId}`).emit(event, data);
};

// Make emit functions globally available
global.emitRealTimeUpdate = emitRealTimeUpdate;
global.emitAdminUpdate = emitAdminUpdate;
global.emitUserUpdate = emitUserUpdate;

global.io = io;

global.broadcastUpdate = (eventType, data) => {
  io.emit(eventType, data);
};

server.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
