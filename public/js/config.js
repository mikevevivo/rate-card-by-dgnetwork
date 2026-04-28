// ============================================================
// DEVELOPER SETUP — fill in your Firebase project credentials
// Found in: Firebase Console → Project Settings → Your Apps
// ============================================================
const firebaseConfig = {
  apiKey:            "AIzaSyAxSGf24Uf23tmXrBh_zX3aezL5GmUMFsE",
  authDomain:        "rate-card-by-dgnetwork.firebaseapp.com",
  projectId:         "rate-card-by-dgnetwork",
  storageBucket:     "rate-card-by-dgnetwork.firebasestorage.app",
  messagingSenderId: "769051347043",
  appId:             "1:769051347043:web:b84bbd472d256bc54f9056"
};

// ============================================================
// USER MANAGEMENT
// Add/remove authorised users here.
// Passwords are set via Firebase Console → Authentication →
// Users, or use the Admin SDK to invite users by email.
// This array controls which email addresses are ALLOWED
// to access the tool even after Firebase authentication.
// ============================================================
const ALLOWED_EMAILS = [
  // "user@example.com",
  // "associate@agency.com",
];
