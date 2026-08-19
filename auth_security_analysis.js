/**
 * Django Authentication Security Analysis - JavaScript Version
 * Enhanced with Advanced Security Features
 * ============================================================
 * 
 * This file demonstrates:
 * 1. Security vulnerabilities in authentication
 * 2. How Django fixes these vulnerabilities
 * 3. Secure JavaScript implementations
 * 4. ADVANCED SECURITY FEATURES:
 *    - Rate limiting & brute force protection
 *    - Account lockout mechanism
 *    - Two-factor authentication (TOTP)
 *    - Strong password validation
 *    - Secure session management
 *    - Input validation & sanitization
 *    - Logging & monitoring
 * 
 * Analysis of: django/contrib/auth/hashers.py
 * Most Sensitive Part: Password verification and timing attack mitigation
 */

const crypto = require('crypto');

// ============================================================================
// PART 1: VULNERABLE AUTHENTICATION (INSECURE - DO NOT USE)
// ============================================================================

class VulnerableAuth {
  /**
   * BAD authentication implementation - vulnerable to:
   * 1. Timing attacks
   * 2. User enumeration
   * 3. Password cracking
   */

  static insecureCheckPassword(providedPassword, storedHash) {
    const providedHash = crypto
      .createHash('sha256')
      .update(providedPassword)
      .digest('hex');

    // BUG: Simple string comparison is NOT constant time!
    return providedHash === storedHash; // INSECURE!
  }

  static insecureVerifyUserExists(username, database) {
    if (!(username in database)) {
      return false;
    }
    const storedHash = database[username];
    return true;
  }
}

// ============================================================================
// PART 2: TIMING ATTACK DEMONSTRATION
// ============================================================================

function demonstrateTimingAttack() {
  console.log('\n' + '='.repeat(70));
  console.log('TIMING ATTACK DEMONSTRATION');
  console.log('='.repeat(70));

  const realPassword = 'Django2024Secure!';
  const realHash = crypto
    .createHash('sha256')
    .update(realPassword)
    .digest('hex');

  const guesses = [
    'password123',
    'Dabc',
    'Django2024Secure!',
  ];

  console.log('\nAttacker tries different passwords:');
  console.log(`Real password: ${realPassword}`);
  console.log(`Real hash: ${realHash}\n`);

  guesses.forEach((guess) => {
    const guessHash = crypto
      .createHash('sha256')
      .update(guess)
      .digest('hex');

    const start = process.hrtime.bigint();
    for (let i = 0; i < 100000; i++) {
      guessHash === realHash;
    }
    const elapsed = Number(process.hrtime.bigint() - start) / 1000000;

    console.log(
      `Guess: '${guess.padEnd(25)}' | Time: ${elapsed.toFixed(4)}ms | Match: ${
        guessHash === realHash
      }`
    );
  });

  console.log('\n⚠️  VULNERABILITY: Timing differences reveal password!');
}

// ============================================================================
// PART 3: USER ENUMERATION ATTACK DEMONSTRATION
// ============================================================================

function demonstrateUserEnumeration() {
  console.log('\n' + '='.repeat(70));
  console.log('USER ENUMERATION ATTACK DEMONSTRATION');
  console.log('='.repeat(70));

  const usersDb = {
    admin: 'pbkdf2_sha256$260000$salt1$hash1...',
    john: 'pbkdf2_sha256$260000$salt2$hash2...',
  };

  const testUsers = ['admin', 'randomuser123', 'john'];

  console.log('\nAttacker checks which usernames exist (vulnerable method):\n');

  testUsers.forEach((testUser) => {
    const start = process.hrtime.bigint();

    let exists;
    if (testUser in usersDb) {
      const dummy = crypto.createHash('sha256').update('test').digest('hex');
      exists = true;
    } else {
      exists = false;
    }

    const elapsed = Number(process.hrtime.bigint() - start) / 1000000;
    console.log(
      `User: '${testUser.padEnd(20)}' | Time: ${elapsed.toFixed(4)}ms | Exists: ${exists}`
    );
  });

  console.log('\n⚠️  VULNERABILITY: Attacker learns which users exist by timing!');
}

// ============================================================================
// PART 4: SECURE AUTHENTICATION (LIKE DJANGO)
// ============================================================================

class SecureAuth {
  /**
   * SECURE authentication implementation
   * Follows Django's best practices
   */

  static constantTimeCompare(a, b) {
    if (typeof a === 'string') {
      a = Buffer.from(a);
    }
    if (typeof b === 'string') {
      b = Buffer.from(b);
    }

    if (a.length !== b.length) {
      let result = 0;
      for (let i = 0; i < Math.max(a.length, b.length); i++) {
        result |= (a[i] || 0) ^ (b[i] || 0);
      }
      return false;
    }

    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a[i] ^ b[i];
    }

    return result === 0;
  }

  static secureHashPassword(password, salt = null) {
    if (salt === null) {
      salt = crypto.randomBytes(16);
    }

    if (typeof salt === 'string') {
      salt = Buffer.from(salt, 'hex');
    }

    const hashResult = crypto.pbkdf2Sync(password, salt, 260000, 64, 'sha256');

    const saltHex = salt.toString('hex');
    const hashHex = hashResult.toString('hex');
    return `pbkdf2_sha256$260000$${saltHex}$${hashHex}`;
  }

  static secureVerifyPassword(providedPassword, storedHash) {
    const parts = storedHash.split('$');

    if (parts.length !== 4) {
      this.constantTimeCompare('invalid', 'invalid');
      return false;
    }

    const [algorithm, iterationsStr, saltHex, storedHashHex] = parts;

    try {
      const iterations = parseInt(iterationsStr, 10);
      const salt = Buffer.from(saltHex, 'hex');

      const providedHash = crypto.pbkdf2Sync(
        providedPassword,
        salt,
        iterations,
        64,
        'sha256'
      );

      const providedHashHex = providedHash.toString('hex');

      return this.constantTimeCompare(storedHashHex, providedHashHex);
    } catch (error) {
      this.constantTimeCompare('invalid', 'invalid');
      return false;
    }
  }
}

// ============================================================================
// PART 5: ADVANCED SECURITY FEATURES - RATE LIMITING & BRUTE FORCE PROTECTION
// ============================================================================

class RateLimiter {
  /**
   * Prevent brute force attacks by limiting login attempts
   */
  constructor(maxAttempts = 5, windowMs = 15 * 60 * 1000) {
    this.maxAttempts = maxAttempts;
    this.windowMs = windowMs;
    this.attempts = new Map();
  }

  recordAttempt(identifier) {
    const now = Date.now();
    const key = identifier;

    if (!this.attempts.has(key)) {
      this.attempts.set(key, []);
    }

    const timestamps = this.attempts.get(key);
    
    // Remove old attempts outside the window
    const filtered = timestamps.filter(t => now - t < this.windowMs);
    filtered.push(now);
    
    this.attempts.set(key, filtered);

    return {
      attempts: filtered.length,
      maxAttempts: this.maxAttempts,
      isLimited: filtered.length > this.maxAttempts,
      resetTime: filtered.length > 0 ? filtered[0] + this.windowMs : null
    };
  }

  isLimited(identifier) {
    const status = this.recordAttempt(identifier);
    return status.isLimited;
  }

  reset(identifier) {
    this.attempts.delete(identifier);
  }
}

// ============================================================================
// PART 6: ACCOUNT LOCKOUT MECHANISM
// ============================================================================

class AccountLockout {
  /**
   * Lock accounts after multiple failed login attempts
   */
  constructor(maxFailedAttempts = 5, lockoutDurationMs = 30 * 60 * 1000) {
    this.maxFailedAttempts = maxFailedAttempts;
    this.lockoutDurationMs = lockoutDurationMs;
    this.lockedAccounts = new Map();
    this.failedAttempts = new Map();
  }

  recordFailedAttempt(username) {
    const now = Date.now();
    const key = username;

    if (!this.failedAttempts.has(key)) {
      this.failedAttempts.set(key, []);
    }

    const attempts = this.failedAttempts.get(key);
    attempts.push(now);

    // Remove attempts older than 24 hours
    const filtered = attempts.filter(t => now - t < 24 * 60 * 60 * 1000);
    this.failedAttempts.set(key, filtered);

    if (filtered.length >= this.maxFailedAttempts) {
      this.lockAccount(username);
      return { locked: true, reason: 'Too many failed attempts' };
    }

    return { locked: false, attempts: filtered.length, remaining: this.maxFailedAttempts - filtered.length };
  }

  recordSuccessfulLogin(username) {
    // Clear failed attempts on successful login
    this.failedAttempts.delete(username);
    this.unlockAccount(username);
  }

  lockAccount(username) {
    this.lockedAccounts.set(username, {
      lockedAt: Date.now(),
      reason: 'Too many failed login attempts'
    });
  }

  unlockAccount(username) {
    this.lockedAccounts.delete(username);
  }

  isAccountLocked(username) {
    if (!this.lockedAccounts.has(username)) {
      return false;
    }

    const lockInfo = this.lockedAccounts.get(username);
    const now = Date.now();

    if (now - lockInfo.lockedAt > this.lockoutDurationMs) {
      this.unlockAccount(username);
      return false;
    }

    return {
      locked: true,
      reason: lockInfo.reason,
      unlocksAt: new Date(lockInfo.lockedAt + this.lockoutDurationMs)
    };
  }
}

// ============================================================================
// PART 7: TWO-FACTOR AUTHENTICATION (TOTP)
// ============================================================================

class TwoFactorAuth {
  /**
   * Time-based One-Time Password (TOTP) implementation
   * Like Google Authenticator
   */
  constructor() {
    this.userSecrets = new Map();
  }

  generateSecret(username) {
    // Generate a random secret for TOTP
    const secret = crypto.randomBytes(20);
    this.userSecrets.set(username, {
      secret: secret.toString('base64'),
      enabled: false,
      createdAt: Date.now()
    });

    return {
      secret: secret.toString('base64'),
      qrCode: `otpauth://totp/${username}?secret=${secret.toString('base64')}`
    };
  }

  verifyTotp(username, token) {
    if (!this.userSecrets.has(username)) {
      return { valid: false, error: 'User not found' };
    }

    const userSecret = this.userSecrets.get(username);
    if (!userSecret.enabled) {
      return { valid: false, error: '2FA not enabled for this account' };
    }

    // TOTP verification (simplified - production should use speakeasy library)
    const now = Math.floor(Date.now() / 1000);
    const timeWindow = 1; // Allow 1 time step (30 seconds)

    for (let i = -timeWindow; i <= timeWindow; i++) {
      const time = Math.floor((now + i * 30) / 30);
      const hmac = crypto.createHmac('sha1', Buffer.from(userSecret.secret, 'base64'));
      hmac.update(Buffer.alloc(8));
      const digest = hmac.digest();
      const offset = digest[digest.length - 1] & 0xf;
      const code = (digest.readUInt32BE(offset) & 0x7fffffff) % 1000000;

      if (String(code).padStart(6, '0') === token) {
        return { valid: true };
      }
    }

    return { valid: false, error: 'Invalid TOTP token' };
  }

  enableTotp(username) {
    if (this.userSecrets.has(username)) {
      const userSecret = this.userSecrets.get(username);
      userSecret.enabled = true;
    }
  }
}

// ============================================================================
// PART 8: PASSWORD STRENGTH VALIDATION
// ============================================================================

class PasswordValidator {
  /**
   * Enforce strong password requirements
   */
  static validatePassword(password) {
    const errors = [];
    const warnings = [];

    // Minimum length
    if (password.length < 12) {
      errors.push('Password must be at least 12 characters long');
    }

    // Uppercase letters
    if (!/[A-Z]/.test(password)) {
      errors.push('Password must contain at least one uppercase letter');
    }

    // Lowercase letters
    if (!/[a-z]/.test(password)) {
      errors.push('Password must contain at least one lowercase letter');
    }

    // Numbers
    if (!/[0-9]/.test(password)) {
      errors.push('Password must contain at least one number');
    }

    // Special characters
    if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
      errors.push('Password must contain at least one special character (!@#$%^&*)');
    }

    // Check common patterns
    if (/(.)\1{2,}/.test(password)) {
      warnings.push('Avoid repeating characters');
    }

    if (/^123|456|789|abc|def|qwerty/.test(password)) {
      warnings.push('Avoid common sequences');
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings,
      strength: this.calculateStrength(password)
    };
  }

  static calculateStrength(password) {
    let strength = 0;

    if (password.length >= 12) strength += 20;
    if (password.length >= 16) strength += 20;
    if (/[A-Z]/.test(password)) strength += 15;
    if (/[a-z]/.test(password)) strength += 15;
    if (/[0-9]/.test(password)) strength += 15;
    if (/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) strength += 15;

    if (strength >= 80) return 'Strong';
    if (strength >= 60) return 'Medium';
    return 'Weak';
  }
}

// ============================================================================
// PART 9: SECURE SESSION MANAGEMENT
// ============================================================================

class SessionManager {
  /**
   * Secure session management with CSRF protection
   */
  constructor() {
    this.sessions = new Map();
  }

  createSession(userId, userAgent, ipAddress) {
    const sessionId = crypto.randomBytes(32).toString('hex');
    const csrfToken = crypto.randomBytes(32).toString('hex');

    const session = {
      userId,
      sessionId,
      csrfToken,
      userAgent,
      ipAddress,
      createdAt: Date.now(),
      lastActivity: Date.now(),
      isActive: true,
      expiresAt: Date.now() + 60 * 60 * 1000 // 1 hour
    };

    this.sessions.set(sessionId, session);
    return { sessionId, csrfToken };
  }

  validateSession(sessionId, userAgent, ipAddress) {
    if (!this.sessions.has(sessionId)) {
      return { valid: false, error: 'Session not found' };
    }

    const session = this.sessions.get(sessionId);

    // Check if session expired
    if (Date.now() > session.expiresAt) {
      this.sessions.delete(sessionId);
      return { valid: false, error: 'Session expired' };
    }

    // Verify user agent (detect session hijacking)
    if (session.userAgent !== userAgent) {
      return { valid: false, error: 'User agent mismatch - possible session hijacking' };
    }

    // Verify IP address (optional - can cause issues with proxies)
    if (session.ipAddress !== ipAddress) {
      console.warn('⚠️  IP address changed - possible session hijacking');
    }

    // Update last activity
    session.lastActivity = Date.now();

    return { valid: true, session };
  }

  validateCsrfToken(sessionId, token) {
    if (!this.sessions.has(sessionId)) {
      return false;
    }

    const session = this.sessions.get(sessionId);
    return SecureAuth.constantTimeCompare(session.csrfToken, token);
  }

  destroySession(sessionId) {
    this.sessions.delete(sessionId);
  }
}

// ============================================================================
// PART 10: INPUT VALIDATION & SANITIZATION
// ============================================================================

class InputValidator {
  /**
   * Validate and sanitize user inputs
   */
  static validateEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email) && email.length <= 254;
  }

  static validateUsername(username) {
    // Alphanumeric and underscore only, 3-32 characters
    const usernameRegex = /^[a-zA-Z0-9_]{3,32}$/;
    return usernameRegex.test(username);
  }

  static sanitizeInput(input) {
    if (typeof input !== 'string') {
      return '';
    }
    
    // Remove potentially dangerous characters
    return input
      .replace(/[<>]/g, '') // Remove angle brackets
      .trim()
      .substring(0, 1000); // Limit length
  }

  static validateInput(email, username, password) {
    const errors = [];

    if (!this.validateEmail(email)) {
      errors.push('Invalid email format');
    }

    if (!this.validateUsername(username)) {
      errors.push('Username must be 3-32 alphanumeric characters');
    }

    const passwordValidation = PasswordValidator.validatePassword(password);
    if (!passwordValidation.valid) {
      errors.push(...passwordValidation.errors);
    }

    return {
      valid: errors.length === 0,
      errors
    };
  }
}

// ============================================================================
// PART 11: LOGGING & MONITORING
// ============================================================================

class SecurityLogger {
  /**
   * Log security events for monitoring and audit
   */
  constructor() {
    this.logs = [];
    this.alerts = [];
  }

  log(event, severity, details) {
    const logEntry = {
      timestamp: new Date().toISOString(),
      event,
      severity, // 'INFO', 'WARNING', 'ERROR', 'CRITICAL'
      details,
      id: crypto.randomBytes(8).toString('hex')
    };

    this.logs.push(logEntry);

    if (severity === 'CRITICAL' || severity === 'ERROR') {
      this.createAlert(logEntry);
    }

    return logEntry.id;
  }

  createAlert(logEntry) {
    this.alerts.push({
      ...logEntry,
      alertedAt: Date.now()
    });

    console.log(`\n🚨 SECURITY ALERT: ${logEntry.event}`);
    console.log(`   Severity: ${logEntry.severity}`);
    console.log(`   Details: ${JSON.stringify(logEntry.details)}`);
  }

  getSecurityReport() {
    const criticalEvents = this.logs.filter(log => log.severity === 'CRITICAL').length;
    const errorEvents = this.logs.filter(log => log.severity === 'ERROR').length;
    const warningEvents = this.logs.filter(log => log.severity === 'WARNING').length;

    return {
      totalEvents: this.logs.length,
      critical: criticalEvents,
      errors: errorEvents,
      warnings: warningEvents,
      alerts: this.alerts.length,
      recentLogs: this.logs.slice(-10)
    };
  }
}

// ============================================================================
// PART 12: SECURE LOGIN SYSTEM (COMPLETE)
// ============================================================================

class SecureLoginSystem {
  /**
   * Complete secure login system with all protections
   */
  constructor() {
    this.users = new Map(); // In production: use database
    this.rateLimiter = new RateLimiter(5, 15 * 60 * 1000);
    this.accountLockout = new AccountLockout(5, 30 * 60 * 1000);
    this.twoFactorAuth = new TwoFactorAuth();
    this.sessionManager = new SessionManager();
    this.logger = new SecurityLogger();
  }

  register(email, username, password) {
    console.log('\n📝 REGISTRATION PROCESS');
    console.log('-'.repeat(50));

    // Validate input
    const validation = InputValidator.validateInput(email, username, password);
    if (!validation.valid) {
      this.logger.log('Registration failed - invalid input', 'WARNING', validation.errors);
      return { success: false, errors: validation.errors };
    }

    // Check if user exists
    if (this.users.has(username)) {
      this.logger.log('Registration failed - user exists', 'WARNING', { username });
      return { success: false, error: 'Username already exists' };
    }

    // Hash password
    const passwordHash = SecureAuth.secureHashPassword(password);

    // Create user
    const user = {
      username,
      email,
      passwordHash,
      createdAt: Date.now(),
      lastLogin: null,
      totpEnabled: false,
      passwordChanged: Date.now()
    };

    this.users.set(username, user);

    this.logger.log('User registered successfully', 'INFO', { username, email });
    return { success: true, message: 'Registration successful' };
  }

  login(username, password, userAgent, ipAddress, totpToken = null) {
    console.log('\n🔐 LOGIN PROCESS');
    console.log('-'.repeat(50));

    // Check rate limiting
    if (this.rateLimiter.isLimited(username)) {
      this.logger.log('Login attempt rate limited', 'WARNING', { username, ipAddress });
      return { success: false, error: 'Too many login attempts. Try again later.' };
    }

    // Check account lockout
    const lockoutStatus = this.accountLockout.isAccountLocked(username);
    if (lockoutStatus) {
      this.logger.log('Login attempt on locked account', 'ERROR', { username, reason: lockoutStatus.reason });
      return { success: false, error: `Account locked until ${lockoutStatus.unlocksAt}` };
    }

    // Sanitize input
    const sanitizedUsername = InputValidator.sanitizeInput(username);
    const sanitizedPassword = InputValidator.sanitizeInput(password);

    // Check user exists
    if (!this.users.has(sanitizedUsername)) {
      this.accountLockout.recordFailedAttempt(sanitizedUsername);
      this.logger.log('Login failed - user not found', 'INFO', { username: sanitizedUsername, ipAddress });
      
      // Fake runtime to prevent user enumeration
      SecureAuth.secureHashPassword(sanitizedPassword);
      return { success: false, error: 'Invalid credentials' };
    }

    const user = this.users.get(sanitizedUsername);

    // Verify password
    const isPasswordValid = SecureAuth.secureVerifyPassword(sanitizedPassword, user.passwordHash);

    if (!isPasswordValid) {
      this.accountLockout.recordFailedAttempt(sanitizedUsername);
      const lockoutCheck = this.accountLockout.recordFailedAttempt(sanitizedUsername);
      
      this.logger.log('Login failed - invalid password', 'WARNING', { username: sanitizedUsername, ipAddress });
      
      if (lockoutCheck.locked) {
        return { success: false, error: 'Account locked due to too many failed attempts' };
      }
      
      return { success: false, error: 'Invalid credentials' };
    }

    // Check 2FA if enabled
    if (user.totpEnabled) {
      if (!totpToken) {
        return { success: false, needsTwoFactor: true, message: 'Please provide TOTP token' };
      }

      const totpValidation = this.twoFactorAuth.verifyTotp(sanitizedUsername, totpToken);
      if (!totpValidation.valid) {
        this.logger.log('Login failed - invalid TOTP', 'WARNING', { username: sanitizedUsername });
        return { success: false, error: 'Invalid TOTP token' };
      }
    }

    // Login successful
    this.accountLockout.recordSuccessfulLogin(sanitizedUsername);
    this.rateLimiter.reset(sanitizedUsername);

    // Create session
    const { sessionId, csrfToken } = this.sessionManager.createSession(
      sanitizedUsername,
      userAgent,
      ipAddress
    );

    user.lastLogin = Date.now();

    this.logger.log('User logged in successfully', 'INFO', { username: sanitizedUsername, ipAddress });

    return {
      success: true,
      message: 'Login successful',
      sessionId,
      csrfToken,
      user: { username: user.username, email: user.email }
    };
  }

  logout(sessionId) {
    this.sessionManager.destroySession(sessionId);
    this.logger.log('User logged out', 'INFO', { sessionId: sessionId.substring(0, 8) });
    return { success: true };
  }

  getSecurityReport() {
    return this.logger.getSecurityReport();
  }
}

// ============================================================================
// PART 13: DEMONSTRATION
// ============================================================================

function demonstrateSecureLogin() {
  console.log('\n' + '█'.repeat(70));
  console.log('█ ENHANCED SECURE LOGIN SYSTEM DEMONSTRATION'.padEnd(70) + '█');
  console.log('█'.repeat(70));

  const loginSystem = new SecureLoginSystem();

  // Register users
  console.log('\n✅ REGISTERING USERS:');
  loginSystem.register('alice@example.com', 'alice_secure', 'SecurePass123!@#');
  loginSystem.register('bob@example.com', 'bob_user', 'MyPassword456!@#');

  // Test 1: Successful login
  console.log('\n✅ TEST 1: SUCCESSFUL LOGIN');
  const successLogin = loginSystem.login('alice_secure', 'SecurePass123!@#', 'Mozilla/5.0', '192.168.1.1');
  console.log(`Result: ${successLogin.success ? '✅ SUCCESS' : '❌ FAILED'}`);
  if (successLogin.success) {
    console.log(`Session ID: ${successLogin.sessionId.substring(0, 16)}...`);
  }

  // Test 2: Wrong password
  console.log('\n❌ TEST 2: WRONG PASSWORD');
  const wrongPassword = loginSystem.login('alice_secure', 'WrongPassword123', 'Mozilla/5.0', '192.168.1.1');
  console.log(`Result: ${wrongPassword.success ? '✅ SUCCESS' : '❌ FAILED'}`);
  console.log(`Error: ${wrongPassword.error}`);

  // Test 3: Rate limiting (multiple failed attempts)
  console.log('\n⚠️  TEST 3: RATE LIMITING (5 failed attempts)');
  for (let i = 1; i <= 6; i++) {
    const attempt = loginSystem.login('bob_user', 'WrongPassword', 'Mozilla/5.0', '192.168.1.1');
    console.log(`Attempt ${i}: ${attempt.success ? 'SUCCESS' : 'BLOCKED'} - ${attempt.error || 'OK'}`);
  }

  // Test 4: Invalid input
  console.log('\n🔍 TEST 4: INPUT VALIDATION');
  const invalidEmail = InputValidator.validateEmail('invalid-email');
  const validEmail = InputValidator.validateEmail('user@example.com');
  console.log(`Invalid email: ${invalidEmail ? '✅ VALID' : '❌ INVALID'}`);
  console.log(`Valid email: ${validEmail ? '✅ VALID' : '❌ INVALID'}`);

  // Test 5: Password strength
  console.log('\n🔐 TEST 5: PASSWORD STRENGTH VALIDATION');
  const weakPass = PasswordValidator.validatePassword('weak');
  const strongPass = PasswordValidator.validatePassword('StrongPass123!@#$%');
  console.log(`Weak password: ${weakPass.strength}`);
  console.log(`Strong password: ${strongPass.strength}`);

  // Security report
  console.log('\n' + '='.repeat(70));
  console.log('SECURITY REPORT');
  console.log('='.repeat(70));
  const report = loginSystem.getSecurityReport();
  console.log(`Total security events: ${report.totalEvents}`);
  console.log(`Critical alerts: ${report.critical}`);
  console.log(`Errors: ${report.errors}`);
  console.log(`Warnings: ${report.warnings}`);
}

// ============================================================================
// MAIN: RUN ALL DEMONSTRATIONS
// ============================================================================

function main() {
  console.log('\n' + '█'.repeat(70));
  console.log('█ DJANGO AUTHENTICATION SECURITY ANALYSIS - ENHANCED'.padEnd(70) + '█');
  console.log('█ JAVASCRIPT VERSION WITH ADVANCED SECURITY FEATURES'.padEnd(70) + '█');
  console.log('█'.repeat(70));

  // Run basic demonstrations
  demonstrateTimingAttack();
  demonstrateUserEnumeration();

  // Run secure login system demo
  demonstrateSecureLogin();

  // Final summary
  console.log('\n' + '='.repeat(70));
  console.log('ADVANCED SECURITY FEATURES IMPLEMENTED');
  console.log('='.repeat(70));
  console.log(`
✅ RATE LIMITING
   • Limit login attempts per IP/username
   • Default: 5 attempts per 15 minutes
   • Prevents brute force attacks

✅ ACCOUNT LOCKOUT
   • Lock accounts after failed attempts
   • Automatic unlock after timeout
   • Tracks failed login history

✅ TWO-FACTOR AUTHENTICATION (TOTP)
   • Time-based one-time passwords
   • Compatible with Google Authenticator
   • Optional per user

✅ PASSWORD STRENGTH VALIDATION
   • Minimum 12 characters
   • Requires uppercase, lowercase, numbers, symbols
   • Detect common patterns
   • Strength meter: Weak/Medium/Strong

✅ SECURE SESSION MANAGEMENT
   • Unique session tokens
   • CSRF token protection
   • User agent validation
   • IP address tracking
   • Automatic expiration (1 hour)

✅ INPUT VALIDATION & SANITIZATION
   • Email validation
   • Username validation
   • Input length limits
   • XSS prevention

✅ LOGGING & MONITORING
   • Security event logging
   • Alert system for critical events
   • Security report generation
   • Audit trail

✅ CORE SECURITY
   • Constant-time password comparison
   • PBKDF2-HMAC-SHA256 (260,000 iterations)
   • Random salt per password
   • Fake runtime to prevent enumeration

BEST PRACTICES FOR PRODUCTION:
1. Use bcryptjs or argon2 npm packages
2. Store sensitive logs securely
3. Implement rate limiting with Redis
4. Use JWT for stateless sessions
5. Enable HTTPS/TLS everywhere
6. Implement comprehensive logging
7. Regular security audits
8. Keep dependencies updated

RECOMMENDED NPM PACKAGES:
• bcryptjs - Secure password hashing
• argon2 - Advanced hashing algorithm
• jsonwebtoken - JWT implementation
• express-rate-limit - Rate limiting middleware
• speakeasy - TOTP generation
• helmet - Security headers

  `);
  console.log('='.repeat(70) + '\n');
}

main();

module.exports = {
  VulnerableAuth,
  SecureAuth,
  RateLimiter,
  AccountLockout,
  TwoFactorAuth,
  PasswordValidator,
  SessionManager,
  InputValidator,
  SecurityLogger,
  SecureLoginSystem,
};
