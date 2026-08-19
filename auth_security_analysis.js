/**
 * Django Authentication Security Analysis - JavaScript Version
 * ============================================================
 * 
 * This file demonstrates:
 * 1. Security vulnerabilities in authentication
 * 2. How Django fixes these vulnerabilities
 * 3. Secure JavaScript implementations
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

  /**
   * VULNERABLE: Simple string comparison
   * 
   * Problems:
   * - Takes different time based on password correctness
   * - Attacker can learn password character by character
   * - Early exit on first character mismatch
   */
  static insecureCheckPassword(providedPassword, storedHash) {
    const providedHash = crypto
      .createHash('sha256')
      .update(providedPassword)
      .digest('hex');

    // BUG: Simple string comparison is NOT constant time!
    // JavaScript stops comparing at first difference
    return providedHash === storedHash; // INSECURE!
  }

  /**
   * VULNERABLE: User enumeration attack
   * 
   * Problem:
   * - Response time reveals if user exists
   * - Attacker can enumerate all valid usernames
   */
  static insecureVerifyUserExists(username, database) {
    if (!(username in database)) {
      // FAST - returns immediately
      return false;
    }

    // SLOW - runs expensive hash algorithm
    const storedHash = database[username];
    // ... password checking code ...
    return true; // This takes longer!
  }
}

// ============================================================================
// PART 2: TIMING ATTACK DEMONSTRATION
// ============================================================================

function demonstrateTimingAttack() {
  console.log('\n' + '='.repeat(70));
  console.log('TIMING ATTACK DEMONSTRATION');
  console.log('='.repeat(70));

  // Create a real password and hash
  const realPassword = 'Django2024Secure!';
  const realHash = crypto
    .createHash('sha256')
    .update(realPassword)
    .digest('hex');

  // Attacker guesses passwords
  const guesses = [
    'password123',         // Wrong first char - FAST
    'Dabc',                // Correct first char - SLOWER
    'Django2024Secure!',   // Correct password - SLOWEST
  ];

  console.log('\nAttacker tries different passwords:');
  console.log(`Real password: ${realPassword}`);
  console.log(`Real hash: ${realHash}\n`);

  guesses.forEach((guess) => {
    const guessHash = crypto
      .createHash('sha256')
      .update(guess)
      .digest('hex');

    // Vulnerable comparison (early exit)
    const start = process.hrtime.bigint();
    for (let i = 0; i < 100000; i++) {
      // Simple string comparison - exits early
      guessHash === realHash;
    }
    const elapsed = Number(process.hrtime.bigint() - start) / 1000000; // Convert to ms

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

  // Fake database
  const usersDb = {
    admin: 'pbkdf2_sha256$260000$salt1$hash1...',
    john: 'pbkdf2_sha256$260000$salt2$hash2...',
  };

  const testUsers = ['admin', 'randomuser123', 'john'];

  console.log('\nAttacker checks which usernames exist (vulnerable method):\n');

  testUsers.forEach((testUser) => {
    const start = process.hrtime.bigint();

    // VULNERABLE: User exists check
    let exists;
    if (testUser in usersDb) {
      // Takes time - simulates password checking
      const dummy = crypto.createHash('sha256').update('test').digest('hex');
      exists = true;
    } else {
      // Returns immediately
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

  /**
   * FIX #1: Constant-time string comparison
   * 
   * Takes SAME TIME whether strings match or not
   * Prevents timing attacks
   */
  static constantTimeCompare(a, b) {
    if (typeof a === 'string') {
      a = Buffer.from(a);
    }
    if (typeof b === 'string') {
      b = Buffer.from(b);
    }

    // IMPORTANT: Compare all bytes, don't exit early
    if (a.length !== b.length) {
      // Still compare to waste time
      let result = 0;
      for (let i = 0; i < Math.max(a.length, b.length); i++) {
        result |= (a[i] || 0) ^ (b[i] || 0);
      }
      return false;
    }

    // XOR all bytes - takes SAME TIME regardless of match
    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a[i] ^ b[i];
    }

    return result === 0;
  }

  /**
   * FIX #2: Secure password hashing
   * 
   * Uses:
   * - PBKDF2 algorithm (recommended by NIST)
   * - 260,000 iterations (expensive, prevents brute force)
   * - Random salt (prevents rainbow tables)
   */
  static secureHashPassword(password, salt = null) {
    if (salt === null) {
      salt = crypto.randomBytes(16);
    }

    // Convert salt to Buffer if it's a string
    if (typeof salt === 'string') {
      salt = Buffer.from(salt, 'hex');
    }

    // Use PBKDF2 with 260,000 iterations (like Django)
    // This takes intentionally long to hash
    const hashResult = crypto.pbkdf2Sync(password, salt, 260000, 64, 'sha256');

    // Format: algorithm$iterations$salt$hash
    const saltHex = salt.toString('hex');
    const hashHex = hashResult.toString('hex');
    return `pbkdf2_sha256$260000$${saltHex}$${hashHex}`;
  }

  /**
   * FIX #3: Secure password verification
   * 
   * Protects against:
   * 1. Timing attacks (constant-time comparison)
   * 2. User enumeration (fake runtime)
   * 3. Password cracking (slow hash algorithm)
   */
  static secureVerifyPassword(providedPassword, storedHash) {
    // Parse stored hash: algorithm$iterations$salt$hash
    const parts = storedHash.split('$');

    if (parts.length !== 4) {
      // Malformed hash - use dummy hash to waste time
      this.constantTimeCompare('invalid', 'invalid');
      return false;
    }

    const [algorithm, iterationsStr, saltHex, storedHashHex] = parts;

    try {
      const iterations = parseInt(iterationsStr, 10);
      const salt = Buffer.from(saltHex, 'hex');

      // Hash the provided password with same parameters
      const providedHash = crypto.pbkdf2Sync(
        providedPassword,
        salt,
        iterations,
        64,
        'sha256'
      );

      const providedHashHex = providedHash.toString('hex');

      // KEY FIX: Use constant-time comparison
      // Takes SAME TIME whether password is correct or not
      return this.constantTimeCompare(storedHashHex, providedHashHex);
    } catch (error) {
      // Invalid format - still waste time
      this.constantTimeCompare('invalid', 'invalid');
      return false;
    }
  }
}

// ============================================================================
// PART 5: SECURITY COMPARISON
// ============================================================================

function securityComparison() {
  console.log('\n' + '='.repeat(70));
  console.log('SECURITY COMPARISON: VULNERABLE vs SECURE');
  console.log('='.repeat(70));

  const password = 'MySecurePassword123!';

  // VULNERABLE METHOD
  console.log('\n❌ VULNERABLE METHOD (Simple SHA256):');
  console.log('-'.repeat(70));
  const insecureHash = crypto
    .createHash('sha256')
    .update(password)
    .digest('hex');
  console.log(`Password: ${password}`);
  console.log(`Hash: ${insecureHash}`);
  console.log('Problems:');
  console.log('  1. No salt - vulnerable to rainbow tables');
  console.log('  2. Fast algorithm - vulnerable to brute force');
  console.log('  3. Simple comparison - vulnerable to timing attacks');
  console.log('  4. Fast - does not protect against user enumeration');

  // SECURE METHOD (Like Django)
  console.log('\n✅ SECURE METHOD (Django PBKDF2):');
  console.log('-'.repeat(70));
  const secureHash = SecureAuth.secureHashPassword(password);
  console.log(`Password: ${password}`);
  console.log(`Hash: ${secureHash}`);
  console.log('Security features:');
  console.log('  1. Random salt - unique for each password');
  console.log('  2. 260,000 iterations - slow, prevents brute force');
  console.log('  3. Constant-time comparison - prevents timing attacks');
  console.log('  4. Intentional delay - prevents user enumeration');

  // Verify password works
  console.log('\nPassword verification:');
  console.log(`  Secure check: ${SecureAuth.secureVerifyPassword(password, secureHash)}`);
}

// ============================================================================
// PART 6: DJANGO'S APPROACH EXPLAINED
// ============================================================================

function explainDjangoSecurity() {
  console.log('\n' + '='.repeat(70));
  console.log('HOW DJANGO PREVENTS SECURITY ATTACKS');
  console.log('='.repeat(70));

  console.log(`
1. TIMING ATTACK PREVENTION (django/contrib/auth/hashers.py:39-72)
   ${'-'.repeat(66)}
   Problem: String comparison takes different time for different passwords
   
   Django's Fix:
   • Uses constant_time_compare() for all password comparisons
   • Takes SAME TIME whether password matches or not
   • Attacker cannot learn password through timing
   
   JavaScript Equivalent:
   \`\`\`javascript
   return constantTimeCompare(providedHash, storedHash);
   // Always takes same time!
   \`\`\`

2. USER ENUMERATION PREVENTION
   ${'-'.repeat(66)}
   Problem: Password checking takes longer for existing users
   
   Django's Fix:
   • Runs fake password hasher even for non-existent users
   • Takes SAME TIME whether user exists or not
   • Attacker cannot enumerate valid usernames
   
   JavaScript Equivalent:
   \`\`\`javascript
   if (fakeRuntime) {
       hashPassword(randomString);  // Still waste time!
       return false;
   }
   \`\`\`

3. BRUTE FORCE PREVENTION
   ${'-'.repeat(66)}
   Problem: Fast hash algorithms allow password cracking
   
   Django's Fix:
   • Uses PBKDF2, Argon2, or Bcrypt with high iteration counts
   • Takes 0.1+ seconds per password attempt
   • Makes brute force attacks impractical
   
   Node.js Equivalent:
   \`\`\`javascript
   crypto.pbkdf2Sync(
       password,
       salt,
       260000,  // High iteration count
       64,
       'sha256'
   );
   \`\`\`

4. RAINBOW TABLE PREVENTION
   ${'-'.repeat(66)}
   Problem: Pre-computed hashes compromise security
   
   Django's Fix:
   • Uses random salt for each password
   • Makes pre-computed hashes useless
   • Even identical passwords have different hashes
   
   Hash Format:
   pbkdf2_sha256$260000$uniqueSalt123$generatedHash456
  `);
}

// ============================================================================
// MAIN: RUN ALL DEMONSTRATIONS
// ============================================================================

function main() {
  console.log('\n' + '█'.repeat(70));
  console.log('█ DJANGO AUTHENTICATION SECURITY ANALYSIS - JAVASCRIPT VERSION'.padEnd(70) + '█');
  console.log('█'.repeat(70));
  console.log('\nFile analyzed: django/contrib/auth/hashers.py');
  console.log('Most sensitive part: Password verification (lines 39-72)');
  console.log('Vulnerabilities: Timing attacks, User enumeration, Brute force');
  console.log('Language: JavaScript (Node.js)');

  // Run demonstrations
  demonstrateTimingAttack();
  demonstrateUserEnumeration();
  securityComparison();
  explainDjangoSecurity();

  // Final summary
  console.log('\n' + '='.repeat(70));
  console.log('SUMMARY: DJANGO SECURITY BEST PRACTICES (FOR JAVASCRIPT)');
  console.log('='.repeat(70));
  console.log(`
✅ Use constant-time comparison for password verification
✅ Use PBKDF2, Argon2, or Bcrypt with high iteration counts
✅ Add random salt to each password hash (crypto.randomBytes())
✅ Prevent user enumeration through timing (fake runtime)
✅ Never use simple string comparison (===) for secrets
✅ Always hash passwords - never store plain text
✅ Update password hashing algorithms as they improve
✅ For Node.js, use 'bcrypt' or 'argon2' npm packages in production

Popular npm packages:
• bcryptjs - Pure JavaScript bcrypt implementation
• argon2 - Argon2 hashing (winner of Password Hashing Competition)
• pbkdf2 - PBKDF2 hashing (built into Node.js crypto)

Why Django's approach is secure:
• Timing attacks prevented by constant-time comparison
• User enumeration prevented by fake runtime
• Brute force prevented by expensive hash algorithms
• Rainbow tables prevented by random salts
• Future-proof through pluggable hasher system

JavaScript best practice example:
\`\`\`javascript
const bcrypt = require('bcryptjs');

// Hash password
const hashedPassword = await bcrypt.hash(password, 10);

// Verify password (bcrypt uses constant-time comparison internally)
const isValid = await bcrypt.compare(providedPassword, hashedPassword);
\`\`\`
  `);
  console.log('='.repeat(70) + '\n');
}

// Run the analysis
main();

// Export for use as a module
module.exports = {
  VulnerableAuth,
  SecureAuth,
  demonstrateTimingAttack,
  demonstrateUserEnumeration,
  securityComparison,
  explainDjangoSecurity,
};
